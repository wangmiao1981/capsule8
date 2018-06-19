// Copyright 2017 Capsule8, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sensor

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

// Number of random bytes to generate for Sensor Id
const sensorIDLengthBytes = 32

// Sensor represents the state of a sensor instance.
type Sensor struct {
	// Unique Id for this sensor. Sensor Ids are ephemeral.
	ID string

	// Sensor-unique event sequence number. Each event sent from this
	// sensor to any subscription has a unique sequence number for the
	// indicated sensor Id.
	sequenceNumber uint64

	// Record the value of CLOCK_MONOTONIC_RAW when the sensor starts.
	// All event monotimes are relative to this value.
	bootMonotimeNanos int64

	// Metrics counters for this sensor
	Metrics MetricsCounters

	// If temporary fs mounts are made at startup, they're stored here.
	perfEventMountPoint string
	traceFSMountPoint   string

	// A sensor-global event monitor that is used for events to aid in
	// caching process information
	Monitor *perf.EventMonitor

	// A lookup table of available kernel symbols. The key is the symbol
	// name as would be used with RegisterKprobe. The value is the actual
	// symbol that should be used, which is normally the same, but can
	// sometimes differ due to compiler name mangling.
	kallsyms map[string]string

	// Per-sensor caches and monitors
	ProcessCache   *ProcessInfoCache
	ContainerCache *ContainerCache
	dockerMonitor  *dockerMonitor
	ociMonitor     *ociMonitor

	// Mapping of event ids to subscriptions
	eventMap *safeSubscriptionMap

	dispatchMutex     sync.Mutex
	dispatchCond      sync.Cond
	dispatchQueueHead *queuedSamples
	dispatchQueueTail *queuedSamples
	dispatchFreelist  *queuedSamples
	dispatchRunning   bool
	dispatchWaitGroup sync.WaitGroup

	// Used by syscall events to handle syscall enter events with
	// argument filters
	dummySyscallEventID    uint64
	dummySyscallEventCount int64
}

type queuedSamples struct {
	next    *queuedSamples
	samples []perf.EventMonitorSample
}

// NewSensor creates a new Sensor instance.
func NewSensor() (*Sensor, error) {
	randomBytes := make([]byte, sensorIDLengthBytes)
	rand.Read(randomBytes)
	sensorID := hex.EncodeToString(randomBytes)

	s := &Sensor{
		ID:                sensorID,
		bootMonotimeNanos: sys.CurrentMonotonicRaw(),
		eventMap:          newSafeSubscriptionMap(),
	}
	s.dispatchCond = sync.Cond{L: &s.dispatchMutex}

	return s, nil
}

// Start starts a sensor instance running.
func (s *Sensor) Start() error {
	var buf unix.Utsname
	if err := unix.Uname(&buf); err == nil {
		machine := string(buf.Machine[:])
		nodename := string(buf.Nodename[:])
		sysname := string(buf.Sysname[:])
		release := string(buf.Release[:])
		version := string(buf.Version[:])
		glog.Infof("%s %s %s %s %s",
			machine, nodename, sysname, release, version)
	}

	// We require that our run dir (usually /var/run/capsule8) exists.
	// Ensure that now before proceeding any further.
	if err := os.MkdirAll(config.Global.RunDir, 0700); err != nil {
		glog.Warningf("Couldn't mkdir %s: %s",
			config.Global.RunDir, err)
		return err
	}

	// If there is no mounted tracefs, the Sensor really can't do anything.
	// Try mounting our own private mount of it.
	if !config.Sensor.DontMountTracing && len(sys.TracingDir()) == 0 {
		// If we couldn't find one, try mounting our own private one
		glog.V(2).Info("Can't find mounted tracefs, mounting one")
		if err := s.mountTraceFS(); err != nil {
			glog.V(1).Info(err)
			return err
		}
	}

	// If there is no mounted cgroupfs for the perf_event cgroup, we can't
	// efficiently separate processes in monitored containers from host
	// processes. We can run without it, but it's better performance when
	// available.
	if !config.Sensor.DontMountPerfEvent && len(sys.PerfEventDir()) == 0 {
		glog.V(2).Info("Can't find mounted perf_event cgroupfs, mounting one")
		if err := s.mountPerfEventCgroupFS(); err != nil {
			glog.V(1).Info(err)
			// This is not a fatal error condition, proceed on
		}
	}

	// Create the sensor-global event monitor. This EventMonitor instance
	// will be used for all perf_event events
	if err := s.createEventMonitor(); err != nil {
		s.Stop()
		return err
	}
	s.loadKernelSymbols()

	s.ContainerCache = NewContainerCache(s)
	s.ProcessCache = NewProcessInfoCache(s)
	s.ProcessCache.Start()

	if len(config.Sensor.DockerContainerDir) > 0 {
		s.dockerMonitor = newDockerMonitor(s,
			config.Sensor.DockerContainerDir)
		if s.dockerMonitor != nil {
			s.dockerMonitor.start()
		}
	}
	/* Temporarily disable the OCI monitor until a better means of
	   supporting it is found.
	if len(config.Sensor.OciContainerDir) > 0 {
		s.ociMonitor = newOciMonitor(s, config.Sensor.OciContainerDir)
		s.ociMonitor.start()
	}
	*/

	// Make sure that all events registered with the sensor's event monitor
	// are active
	s.Monitor.EnableGroup(0)

	// Start dispatch goroutine(s). We'll just spin one up for now, but we
	// can run multiples if we want. The sensor needs to keep samples in
	// order coming from the EventMonitor in order to maintain internal
	// consistency, but it makes no guarantees about the order in which
	// telemetry events are emitted to external clients.
	// NOTE: if more than one dispatch goroutine is spun up, then there
	// needs to be synchronization in containerFilter
	s.dispatchRunning = true
	s.dispatchWaitGroup.Add(1)
	go s.sampleDispatchLoop()

	return nil
}

// Stop stops a running sensor instance.
func (s *Sensor) Stop() {
	if s.dispatchRunning {
		s.dispatchMutex.Lock()
		if s.dispatchRunning {
			s.dispatchRunning = false
			s.dispatchCond.Broadcast()
			s.dispatchMutex.Unlock()
			s.dispatchWaitGroup.Wait()
		} else {
			s.dispatchMutex.Unlock()
		}
	}
	if s.Monitor != nil {
		glog.V(2).Info("Stopping sensor-global EventMonitor")
		s.Monitor.Close()
		s.Monitor = nil
		glog.V(2).Info("Sensor-global EventMonitor stopped successfully")
	}

	if len(s.traceFSMountPoint) > 0 {
		s.unmountTraceFS()
	}

	if len(s.perfEventMountPoint) > 0 {
		s.unmountPerfEventCgroupFS()
	}
}

func (s *Sensor) mountTraceFS() error {
	dir := filepath.Join(config.Global.RunDir, "tracing")
	err := sys.MountTempFS("tracefs", dir, "tracefs", 0, "")
	if err == nil {
		s.traceFSMountPoint = dir
	}
	return err
}

func (s *Sensor) unmountTraceFS() {
	err := sys.UnmountTempFS(s.traceFSMountPoint, "tracefs")
	if err == nil {
		s.traceFSMountPoint = ""
	} else {
		glog.V(2).Infof("Could not unmount %s: %s",
			s.traceFSMountPoint, err)
	}
}

func (s *Sensor) mountPerfEventCgroupFS() error {
	dir := filepath.Join(config.Global.RunDir, "perf_event")
	err := sys.MountTempFS("cgroup", dir, "cgroup", 0, "perf_event")
	if err == nil {
		s.perfEventMountPoint = dir
	}
	return err
}

func (s *Sensor) unmountPerfEventCgroupFS() {
	err := sys.UnmountTempFS(s.perfEventMountPoint, "cgroup")
	if err == nil {
		s.perfEventMountPoint = ""
	} else {
		glog.V(2).Infof("Could not unmount %s: %s",
			s.perfEventMountPoint, err)
	}
}

func (s *Sensor) buildMonitorGroups() ([]string, []int, error) {
	var (
		cgroupList []string
		pidList    []int
		system     bool
	)

	cgroups := make(map[string]bool)
	for _, cgroup := range config.Sensor.CgroupName {
		if len(cgroup) == 0 || cgroup == "/" {
			system = true
			continue
		}
		if cgroups[cgroup] {
			continue
		}
		cgroups[cgroup] = true
		cgroupList = append(cgroupList, cgroup)
	}

	// Try a system-wide perf event monitor if requested or as
	// a fallback if no cgroups were requested
	if system || len(sys.PerfEventDir()) == 0 || len(cgroupList) == 0 {
		glog.V(1).Info("Creating new system-wide event monitor")
		pidList = append(pidList, -1)
	}

	return cgroupList, pidList, nil
}

func (s *Sensor) loadKernelSymbols() {
	filename := filepath.Join(sys.ProcFS().MountPoint, "kallsyms")
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	s.kallsyms = make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// Only record symbols in text segments
		if fields[1] != "t" && fields[1] != "T" {
			continue
		}
		parts := strings.Split(fields[2], ".")
		if len(parts) < 1 {
			continue
		}
		s.kallsyms[parts[0]] = fields[2]
	}
}

func (s *Sensor) createEventMonitor() error {
	eventMonitorOptions := []perf.EventMonitorOption{}

	if len(s.traceFSMountPoint) > 0 {
		eventMonitorOptions = append(eventMonitorOptions,
			perf.WithTracingDir(s.traceFSMountPoint))
	}

	cgroups, pids, err := s.buildMonitorGroups()
	if err != nil {
		return err
	}

	if len(cgroups) == 0 && len(pids) == 0 {
		glog.Fatal("Can't create event monitor with no cgroups or pids")
	}

	if len(cgroups) > 0 {
		var perfEventDir string
		if len(s.perfEventMountPoint) > 0 {
			perfEventDir = s.perfEventMountPoint
		} else {
			perfEventDir = sys.PerfEventDir()
		}
		if len(perfEventDir) > 0 {
			glog.V(1).Infof("Creating new perf event monitor on cgroups %s",
				strings.Join(cgroups, ","))

			eventMonitorOptions = append(eventMonitorOptions,
				perf.WithPerfEventDir(perfEventDir),
				perf.WithCgroups(cgroups))
		}
	}

	if len(pids) > 0 {
		glog.V(1).Info("Creating new system-wide event monitor")
		eventMonitorOptions = append(eventMonitorOptions,
			perf.WithPids(pids))
	}

	s.Monitor, err = perf.NewEventMonitor(eventMonitorOptions...)
	if err != nil {
		// If a cgroup-specific event monitor could not be created,
		// fall back to a system-wide event monitor.
		if len(cgroups) > 0 &&
			(len(pids) == 0 || (len(pids) == 1 && pids[0] == -1)) {

			glog.Warningf("Couldn't create perf event monitor on cgroups %s: %s",
				strings.Join(cgroups, ","), err)

			glog.V(1).Info("Creating new system-wide event monitor")
			s.Monitor, err = perf.NewEventMonitor()
		}
		if err != nil {
			glog.V(1).Infof("Couldn't create event monitor: %s", err)
			return err
		}
	}

	go func() {
		err := s.Monitor.Run(s.dispatchSamples)
		if err != nil {
			glog.Fatal(err)
		}
		glog.V(2).Info("EventMonitor.Run() returned; exiting goroutine")
	}()

	return nil
}

// IsKernelSymbolAvailable checks to see if the specified kprobe symbol is
// available for use in the running kernel.
func (s *Sensor) IsKernelSymbolAvailable(symbol string) bool {
	// If the kallsyms mapping is nil, the table could not be
	// loaded for some reason; assume anything is available
	if s.kallsyms == nil {
		return true
	}

	_, ok := s.kallsyms[symbol]
	return ok
}

// RegisterKprobe registers a kprobe with the sensor's EventMonitor instance,
// but before doing so, ensures that the kernel symbol is available.
func (s *Sensor) RegisterKprobe(
	address string,
	onReturn bool,
	output string,
	fn perf.TraceEventDecoderFn,
	options ...perf.RegisterEventOption,
) (uint64, error) {
	if s.kallsyms != nil {
		if actual, ok := s.kallsyms[address]; ok {
			if actual != address {
				glog.V(2).Infof("Using %q for kprobe symbol %q", actual, address)
				address = actual
			}
		} else {
			return 0, fmt.Errorf("Kernel symbol not found: %s", address)
		}
	}
	return s.Monitor.RegisterKprobe(address, onReturn, output, fn, options...)
}

// NewSubscription creates a new telemetry subscription
func (s *Sensor) NewSubscription() *Subscription {
	subscriptionID := atomic.AddUint64(&s.Metrics.Subscriptions, 1)

	// Use an empty dispatch function until Subscription.Run is called with
	// the real dispatch function to use. This is to avoid an extra branch
	// during dispatch to check for a nil dispatchFn. Since under normal
	// operation this case is impossible, it's a waste to add the check
	// when it's so easy to handle otherwise during the subscription
	// window.
	return &Subscription{
		sensor:         s,
		subscriptionID: subscriptionID,
		dispatchFn:     func(e TelemetryEvent) {},
	}
}

func (s *Sensor) dispatchSamples(samples []perf.EventMonitorSample) {
	s.dispatchMutex.Lock()

	var qs *queuedSamples
	if s.dispatchFreelist == nil {
		qs = &queuedSamples{samples: samples}
	} else {
		qs = s.dispatchFreelist
		s.dispatchFreelist = qs.next
		qs.next = nil
		qs.samples = samples
	}

	if s.dispatchQueueTail == nil {
		s.dispatchQueueHead = qs
		s.dispatchCond.Signal()
	} else {
		s.dispatchQueueTail.next = qs
	}
	s.dispatchQueueTail = qs

	s.dispatchMutex.Unlock()
}

func (s *Sensor) popSamples() []perf.EventMonitorSample {
	qs := s.dispatchQueueHead
	samples := qs.samples

	s.dispatchQueueHead = qs.next
	if s.dispatchQueueHead == nil {
		s.dispatchQueueTail = nil
	}

	qs.next = s.dispatchFreelist
	qs.samples = nil
	s.dispatchFreelist = qs

	return samples
}

func (s *Sensor) dispatchQueuedSamples(samples []perf.EventMonitorSample) {
	eventMap := s.eventMap.getMap()
	for _, esm := range samples {
		if esm.Err != nil {
			glog.Warning(esm.Err)
			continue
		}

		event, ok := esm.DecodedSample.(TelemetryEvent)
		if !ok || event == nil {
			continue
		}

		eventSinks, ok := eventMap[esm.EventID]
		if !ok {
			continue
		}

		for _, es := range eventSinks {
			if es.filter != nil {
				v, err := es.filter.Evaluate(
					es.filterTypes,
					expression.FieldValueMap(esm.DecodedData))
				if err != nil {
					glog.V(1).Infof("Expression evaluation error: %s", err)
					continue
				}
				if !expression.IsValueTrue(v) {
					continue
				}
			}
			s := es.subscription
			containerInfo := event.CommonTelemetryEventData().Container
			if !s.containerFilter.Match(containerInfo) {
				continue
			}
			s.dispatchFn(event)
		}
	}
}

func (s *Sensor) sampleDispatchLoop() {
	glog.V(2).Info("Sample dispatch loop started")

	s.dispatchMutex.Lock()
	for s.dispatchRunning {
		if s.dispatchQueueHead == nil {
			s.dispatchCond.Wait()
			continue
		}
		samples := s.popSamples()

		s.dispatchMutex.Unlock()
		s.dispatchQueuedSamples(samples)
		s.dispatchMutex.Lock()
	}
	s.dispatchMutex.Unlock()

	glog.V(2).Info("Sample dispatch loop stopped")
	s.dispatchWaitGroup.Done()
}
