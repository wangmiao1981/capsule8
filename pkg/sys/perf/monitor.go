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

package perf

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

var (
	eventMonitorOnce sync.Once
	haveClockID      bool
	notedClockID     bool
	timeOffsets      []int64
)

type eventMonitorOptions struct {
	flags              uintptr
	defaultEventAttr   *EventAttr
	perfEventDir       string
	tracingDir         string
	ringBufferNumPages int
	cgroups            []string
	pids               []int
}

// EventMonitorOption is used to implement optional arguments for
// NewEventMonitor. It must be exported, but it is not typically
// used directly.
type EventMonitorOption func(*eventMonitorOptions)

// WithFlags is used to set optional flags when creating a new EventMonitor.
// The flags are passed to the low-level perf_event_open() system call.
func WithFlags(flags uintptr) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.flags = flags
	}
}

// WithDefaultEventAttr is used to set an optional EventAttr struct to be used
// by default when registering events and no EventAttr is specified as part of
// the registration.
func WithDefaultEventAttr(defaultEventAttr *EventAttr) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.defaultEventAttr = defaultEventAttr
	}
}

// WithPerfEventDir is used to set an optional directory to use for monitoring
// cgroups. This should only be necessary if the perf_event cgroup fs is not
// mounted in the usual location.
func WithPerfEventDir(dir string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.perfEventDir = dir
	}
}

// WithTracingDir is used to set an alternate mountpoint to use for managing
// tracepoints, kprobes, and uprobes.
func WithTracingDir(dir string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.tracingDir = dir
	}
}

// WithRingBufferNumPages is used to set the size of the ringbuffers used to
// retrieve samples from the kernel.
func WithRingBufferNumPages(numPages int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.ringBufferNumPages = numPages
	}
}

// WithCgroup is used to add a cgroup to the set of sources to monitor.
func WithCgroup(cgroup string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.cgroups = append(o.cgroups, cgroup)
	}
}

// WithCgroups is used to add a list of cgroups to the set of sources to
// monitor.
func WithCgroups(cgroups []string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.cgroups = append(o.cgroups, cgroups...)
	}
}

// WithPid is used to add a pid to the set of sources to monitor.
func WithPid(pid int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.pids = append(o.pids, pid)
	}
}

// WithPids is used to add a list of pids to the set of sources to monitor.
func WithPids(pids []int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.pids = append(o.pids, pids...)
	}
}

type registerEventOptions struct {
	disabled  bool
	eventAttr *EventAttr
	filter    string
}

// RegisterEventOption is used to implement optional arguments for event
// registration methods. It must be exported, but it is not typically used
// directly.
type RegisterEventOption func(*registerEventOptions)

// WithEventDisabled is used to register the event in a disabled state.
func WithEventDisabled() RegisterEventOption {
	return func(o *registerEventOptions) {
		o.disabled = true
	}
}

// WithEventEnabled is used to register the event in an enabled state.
func WithEventEnabled() RegisterEventOption {
	return func(o *registerEventOptions) {
		o.disabled = false
	}
}

// WithEventAttr is used to register the event with an EventAttr struct
// instead of using the EventMonitor's default.
func WithEventAttr(eventAttr *EventAttr) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.eventAttr = eventAttr
	}
}

// WithFilter is used to set a filter for the event.
func WithFilter(filter string) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.filter = filter
	}
}

// EventType represents the type of an event (tracepoint, external, etc.)
type EventType int

const (
	// EventTypeInvalid is not a valid event type
	EventTypeInvalid EventType = iota

	// EventTypeTracepoint is a trace event (PERF_TYPE_TRACEPOINT)
	EventTypeTracepoint

	// EventTypeKprobe is a kernel probe
	EventTypeKprobe
	// EventTypeUprobe is a user probe
	EventTypeUprobe

	// EventTypeHardware is a hardware event (PERF_TYPE_HARDWARE)
	EventTypeHardware

	// EventTypeSoftware is a software event (PERF_TYPE_SOFTWARE)
	EventTypeSoftware

	// EventTypeHardwareCache is a hardware cache event (PERF_TYPE_HW_CACHE)
	EventTypeHardwareCache

	// EventTypeRaw is a raw event (PERF_TYPE_RAW)
	EventTypeRaw

	// EventTypeBreakpoint is a breakpoint event (PERF_TYPE_BREAKPOINT)
	EventTypeBreakpoint // PERF_TYPE_BREAKPOINT

	// EventTypeDynamicPMU is a dynamic PMU event
	EventTypeDynamicPMU

	// EventTypeExternal is an external event
	EventTypeExternal
)

type registeredEvent struct {
	name      string
	fds       []int
	fields    map[string]int32
	decoderFn TraceEventDecoderFn // used for EventTypeExternal
	eventType EventType
}

type perfEventGroup struct {
	rb    *ringBuffer
	pid   int // passed as 'pid' argument to perf_event_open()
	cpu   int // passed as 'cpu' argument to perf_event_open()
	fd    int // fd returned from perf_event_open()
	flags uintptr

	// Mutable only by the monitor goroutine while running. No
	// synchronization is required.
	pendingSamples []EventMonitorSample
	processed      bool
}

func (group *perfEventGroup) cleanup() {
	if group.rb != nil {
		group.rb.unmap()
	}
	unix.Close(group.fd)
	if group.flags&PERF_FLAG_PID_CGROUP == PERF_FLAG_PID_CGROUP {
		unix.Close(group.pid)
	}
}

// SampleDispatchFn is the signature of a function called to dispatch a
// sample. The first argument is the event ID, the second is the sample.
type SampleDispatchFn func(uint64, EventMonitorSample)

// EventMonitor is a high-level interface to the Linux kernel's perf_event
// infrastructure.
type EventMonitor struct {
	// Ordering of fields is intentional to keep the most frequently used
	// fields together at the head of the struct in an effort to increase
	// cache locality

	// Immutable items. No protection required. These fields are all set
	// when the EventMonitor is created and never changed after that.
	groups       map[int]*perfEventGroup // fd : group data
	dispatchChan chan [][]EventMonitorSample
	epollFD      int

	// Mutable by various goroutines, and also needed by the monitor
	// goroutine. All of these are thread-safe mutable without a lock.
	// The monitor goroutine only ever reads from them, so there's no lock
	// taken. The thread-safe mutation of .decoders is handled elsewhere.
	// The other safe maps will lock if the monitor goroutine is running;
	// otherwise, .lock protects in-place writes.
	eventAttrMap *safeEventAttrMap // stream id : event attr
	eventIDMap   *safeUInt64Map    // stream id : event id
	decoders     *traceEventDecoderMap
	events       *safeRegisteredEventMap // event id : event

	// Mutable only by the monitor goroutine while running. No protection
	// required.
	hasPendingSamples bool

	// Immutable once set. Only used by the dispatchSampleLoop goroutine.
	// Load once there and cache locally to avoid cache misses on this
	// struct.
	dispatchFn SampleDispatchFn

	// Mutable only by the dispatchSampleLoop goroutine. As external
	// samples are pulled from externalSamples, they're entered into this
	// list so that the mutex need not be locked for every single event
	// while pending externalSamples remain undispatched.
	pendingExternalSamples   externalSampleList
	lastSampleTimeDispatched uint64

	// This lock protects everything mutable below this point.
	lock *sync.Mutex

	// Mutable only by the monitor goroutine, but readable by others
	isRunning bool
	pipe      [2]int

	// Mutable by various goroutines, but not required by the monitor goroutine
	nextEventID            uint64
	nextProbeID            uint64
	eventfds               map[int]int    // fd : cpu index
	eventids               map[int]uint64 // fd : stream id
	externalSamples        externalSampleList
	nextExternalSampleTime uint64

	// Immutable, used only when adding new tracepoints/probes
	defaultAttr EventAttr
	tracingDir  string

	// Used only once during shutdown
	cond *sync.Cond
	wg   sync.WaitGroup
}

func fixupEventAttr(eventAttr *EventAttr) {
	// Adjust certain fields in eventAttr that must be set a certain way
	eventAttr.SampleType |= PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_TIME
	eventAttr.ReadFormat = 0
	eventAttr.SampleIDAll = true

	if haveClockID {
		eventAttr.UseClockID = true
		eventAttr.ClockID = unix.CLOCK_MONOTONIC_RAW
	} else {
		eventAttr.UseClockID = false
		eventAttr.ClockID = 0
	}

	// Either WakeupWatermark or WakeupEvents may be used, but at least
	// one must be non-zero, because EventMonitor does not poll.
	if eventAttr.Watermark && eventAttr.WakeupWatermark == 0 {
		eventAttr.WakeupWatermark = 1
	} else if !eventAttr.Watermark && eventAttr.WakeupEvents == 0 {
		eventAttr.WakeupEvents = 1
	}
}

func now() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts)
	return unix.TimespecToNsec(ts)
}

func (monitor *EventMonitor) writeTraceCommand(name string, cmd string) error {
	filename := filepath.Join(monitor.tracingDir, name)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		glog.Fatalf("Couldn't open %s WO+A: %s", filename, err)
	}
	defer file.Close()

	_, err = file.Write([]byte(cmd))
	return err
}

func normalizeFetchargs(args string) string {
	// Normalize the output string so we can match it later
	args = strings.TrimSpace(args)
	if strings.Index(args, "  ") != -1 {
		parts := strings.Split(args, " ")
		result := make([]string, 0, len(parts))
		for _, s := range parts {
			if len(s) > 0 {
				result = append(result, s)
			}
		}
		args = strings.Join(result, " ")
	}

	return args
}

func (monitor *EventMonitor) addKprobe(
	name string,
	address string,
	onReturn bool,
	output string,
) error {
	output = normalizeFetchargs(output)

	var definition string
	if onReturn {
		definition = fmt.Sprintf("r:%s %s %s", name, address, output)
	} else {
		definition = fmt.Sprintf("p:%s %s %s", name, address, output)
	}

	glog.V(1).Infof("Adding kprobe: '%s'", definition)
	return monitor.writeTraceCommand("kprobe_events", definition)
}

func (monitor *EventMonitor) removeKprobe(name string) error {
	return monitor.writeTraceCommand("kprobe_events",
		fmt.Sprintf("-:%s", name))
}

func (monitor *EventMonitor) addUprobe(
	name string,
	bin string,
	address string,
	onReturn bool,
	output string,
) error {
	output = normalizeFetchargs(output)

	var definition string
	if onReturn {
		definition = fmt.Sprintf("r:%s %s:%s %s", name, bin, address, output)
	} else {
		definition = fmt.Sprintf("p:%s %s:%s %s", name, bin, address, output)
	}

	glog.V(1).Infof("Adding uprobe: '%s'", definition)
	return monitor.writeTraceCommand("uprobe_events", definition)
}

func (monitor *EventMonitor) removeUprobe(name string) error {
	return monitor.writeTraceCommand("uprobe_events",
		fmt.Sprintf("-:%s", name))
}

func (monitor *EventMonitor) newProbeName() string {
	monitor.nextProbeID++
	return fmt.Sprintf("capsule8/sensor_%d_%d", unix.Getpid(),
		monitor.nextProbeID)
}

func (monitor *EventMonitor) perfEventOpen(
	eventAttr *EventAttr,
	filter string,
) ([]int, error) {
	glog.V(2).Infof("Opening perf event: %d %s", eventAttr.Config, filter)

	var err error
	newfds := make([]int, 0, len(monitor.groups))
	for groupfd, group := range monitor.groups {
		var fd int
		flags := group.flags | PERF_FLAG_FD_OUTPUT | PERF_FLAG_FD_NO_GROUP
		fd, err = open(eventAttr, group.pid, group.cpu, groupfd, flags)
		if err != nil {
			break
		}
		newfds = append(newfds, fd)

		if len(filter) > 0 {
			err = setFilter(fd, filter)
			if err != nil {
				break
			}
		}
	}

	if err != nil {
		for j := len(newfds) - 1; j >= 0; j-- {
			unix.Close(newfds[j])
		}
		return nil, err
	}
	return newfds, nil
}

func (monitor *EventMonitor) newRegisteredPerfEvent(
	name string,
	config uint64,
	fields map[string]int32,
	opts registerEventOptions,
	eventType EventType,
) (uint64, error) {
	// This should be called with monitor.lock held.

	var attr EventAttr
	if opts.eventAttr == nil {
		attr = monitor.defaultAttr
	} else {
		attr = *opts.eventAttr
		fixupEventAttr(&attr)
	}
	attr.Config = config
	attr.Disabled = opts.disabled

	switch eventType {
	case EventTypeHardware:
		attr.Type = PERF_TYPE_HARDWARE
	case EventTypeSoftware:
		attr.Type = PERF_TYPE_SOFTWARE
	case EventTypeTracepoint, EventTypeKprobe, EventTypeUprobe:
		attr.Type = PERF_TYPE_TRACEPOINT
	case EventTypeHardwareCache:
		attr.Type = PERF_TYPE_HW_CACHE
	case EventTypeRaw:
		attr.Type = PERF_TYPE_RAW
	case EventTypeBreakpoint:
		attr.Type = PERF_TYPE_BREAKPOINT
	}

	newfds, err := monitor.perfEventOpen(&attr, opts.filter)
	if err != nil {
		return 0, err
	}

	// Choose the eventid for this event now, but don't commit to it until
	// later when no error has occurred in registering the event.
	eventid := monitor.nextEventID

	eventAttrMap := newEventAttrMap()
	eventIDMap := newUInt64Map()
	for _, fd := range newfds {
		streamid, err := unix.IoctlGetInt(fd, PERF_EVENT_IOC_ID)
		if err != nil {
			for _, fd := range newfds {
				unix.Close(fd)
				delete(monitor.eventids, fd)
			}
			return 0, err
		}
		eventAttrMap[uint64(streamid)] = &attr
		eventIDMap[uint64(streamid)] = eventid
		monitor.eventids[fd] = uint64(streamid)
	}

	// Now is the time to commit to the eventid
	monitor.nextEventID++
	if monitor.isRunning {
		monitor.eventAttrMap.update(eventAttrMap)
		monitor.eventIDMap.update(eventIDMap)
	} else {
		monitor.eventAttrMap.updateInPlace(eventAttrMap)
		monitor.eventIDMap.updateInPlace(eventIDMap)
	}
	for i, fd := range newfds {
		monitor.eventfds[fd] = i
	}

	event := registeredEvent{
		name:      name,
		fds:       newfds,
		fields:    fields,
		eventType: eventType,
	}

	if monitor.isRunning {
		monitor.events.insert(eventid, event)
	} else {
		monitor.events.insertInPlace(eventid, event)
	}
	return eventid, nil
}

func (monitor *EventMonitor) newRegisteredTraceEvent(
	name string,
	fn TraceEventDecoderFn,
	opts registerEventOptions,
	eventType EventType,
) (uint64, error) {
	// This should be called with monitor.lock held.

	id, err := monitor.decoders.AddDecoder(name, fn)
	if err != nil {
		return 0, err
	}

	decoder := monitor.decoders.getDecoder(id)
	fields := make(map[string]int32, len(decoder.fields))
	for k, v := range decoder.fields {
		fields[k] = v.dataType
	}

	eventid, err := monitor.newRegisteredPerfEvent(name, uint64(id), fields, opts, eventType)
	if err != nil {
		monitor.decoders.RemoveDecoder(name)
		return 0, err
	}

	return eventid, nil
}

// RegisterExternalEvent is used to register an event that can be injected into
// the EventMonitor event stream from an external source. An event ID is
// returned that is unique to the EventMonitor and is to be used to unregister
// the event. The event ID will also be passed to the EventMonitor's dispatch
// function.
func (monitor *EventMonitor) RegisterExternalEvent(
	name string,
	decoderFn TraceEventDecoderFn,
	fields map[string]int32,
) (uint64, error) {
	event := registeredEvent{
		name:      name,
		fields:    fields,
		decoderFn: decoderFn,
		eventType: EventTypeExternal,
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	eventID := monitor.nextEventID
	monitor.nextEventID++

	if monitor.isRunning {
		monitor.events.insert(eventID, event)
	} else {
		monitor.events.insertInPlace(eventID, event)
	}

	return eventID, nil
}

// RegisterTracepoint is used to register a tracepoint with an EventMonitor.
// The tracepoint is selected by name and it must exist in the running Linux
// kernel. An event ID is returned that is unique to the EventMonitor and is
// to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterTracepoint(
	name string,
	fn TraceEventDecoderFn,
	options ...RegisterEventOption,
) (uint64, error) {

	opts := registerEventOptions{}
	for _, option := range options {
		option(&opts)
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	return monitor.newRegisteredTraceEvent(name, fn, opts, EventTypeTracepoint)
}

// RegisterKprobe is used to register a kprobe with an EventMonitor. The kprobe
// will first be registered with the kernel, and then registered with the
// EventMonitor. An event ID is returned that is unqiue to the EventMonitor and
// is to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterKprobe(
	address string,
	onReturn bool,
	output string,
	fn TraceEventDecoderFn,
	options ...RegisterEventOption,
) (uint64, error) {
	opts := registerEventOptions{}
	for _, option := range options {
		option(&opts)
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	name := monitor.newProbeName()
	err := monitor.addKprobe(name, address, onReturn, output)
	if err != nil {
		return 0, err
	}

	eventid, err := monitor.newRegisteredTraceEvent(name, fn, opts, EventTypeKprobe)
	if err != nil {
		monitor.removeKprobe(name)
		return 0, err
	}

	return eventid, nil
}

// RegisterUprobe is used to register a uprobe with an EventMonitor. The uprobe
// will first be registered with the kernel, and then registered with the
// EventMonitor. An event ID is returned that is unique to the EventMonitor and
// is to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterUprobe(
	bin string,
	address string,
	onReturn bool,
	output string,
	fn TraceEventDecoderFn,
	options ...RegisterEventOption,
) (uint64, error) {
	opts := registerEventOptions{}
	for _, option := range options {
		option(&opts)
	}

	// If the address looks like a symbol that needs to be resolved, it
	// must be resolved here and now. The kernel does not do symbol
	// resolution for uprobes.
	if address[0] == '_' || unicode.IsLetter(rune(address[0])) {
		var err error
		address, err = monitor.resolveSymbol(bin, address)
		if err != nil {
			return 0, err
		}
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	name := monitor.newProbeName()
	err := monitor.addUprobe(name, bin, address, onReturn, output)
	if err != nil {
		return 0, err
	}

	eventid, err := monitor.newRegisteredTraceEvent(name, fn, opts, EventTypeUprobe)
	if err != nil {
		monitor.removeUprobe(name)
		return 0, err
	}

	return eventid, nil
}

func baseAddress(file *elf.File, vaddr uint64) uint64 {
	if file.FileHeader.Type != elf.ET_EXEC {
		return 0
	}

	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}

		if vaddr < prog.Vaddr || vaddr >= prog.Vaddr+prog.Memsz {
			continue
		}

		return prog.Vaddr
	}

	return 0
}

func symbolOffset(file *elf.File, name string, symbols []elf.Symbol) uint64 {
	for _, sym := range symbols {
		if sym.Name == name {
			return sym.Value - baseAddress(file, sym.Value)
		}
	}

	return 0
}

func (monitor *EventMonitor) resolveSymbol(bin, symbol string) (string, error) {
	file, err := elf.Open(bin)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// We don't know how to deal with anything other than ET_DYN or
	// ET_EXEC types.
	if file.FileHeader.Type != elf.ET_DYN && file.FileHeader.Type != elf.ET_EXEC {
		return "", fmt.Errorf("Executable is of unsupported ELF type %d",
			file.FileHeader.Type)
	}

	// Check symbols followed by dynamic symbols. Ignore errors from either
	// one, because they'll just be about the sections not existing, which
	// is fine. In the end, we'll generate our own error to return to the
	// caller if the symbol isn't found.

	var offset uint64
	symbols, _ := file.Symbols()
	offset = symbolOffset(file, symbol, symbols)
	if offset == 0 {
		symbols, _ = file.DynamicSymbols()
		offset = symbolOffset(file, symbol, symbols)
		if offset == 0 {
			return "", fmt.Errorf("Symbol %q not found in %q",
				symbol, bin)
		}
	}

	return fmt.Sprintf("%#x", offset), nil
}

func (monitor *EventMonitor) removeRegisteredEvent(event registeredEvent) {
	// This should be called with monitor.lock held

	// event.fds may legitimately be nil for non-perf_event-based events
	if event.fds != nil {
		ids := make([]uint64, 0, len(event.fds))
		for _, fd := range event.fds {
			delete(monitor.eventfds, fd)
			id, ok := monitor.eventids[fd]
			if ok {
				ids = append(ids, id)
				delete(monitor.eventids, fd)
			}
			unix.Close(fd)
		}

		if monitor.isRunning {
			monitor.eventAttrMap.remove(ids)
			monitor.eventIDMap.remove(ids)
		} else {
			monitor.eventAttrMap.removeInPlace(ids)
			monitor.eventIDMap.removeInPlace(ids)
		}
	}

	switch event.eventType {
	case EventTypeTracepoint:
		monitor.decoders.RemoveDecoder(event.name)
	case EventTypeKprobe:
		monitor.removeKprobe(event.name)
		monitor.decoders.RemoveDecoder(event.name)
	case EventTypeUprobe:
		monitor.removeUprobe(event.name)
		monitor.decoders.RemoveDecoder(event.name)
	}
}

// UnregisterEvent is used to remove a previously registered event from an
// EventMonitor. The event can be of any type and is specified by the event
// ID that was returned when the event was initially registered with the
// EventMonitor.
func (monitor *EventMonitor) UnregisterEvent(eventid uint64) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if !ok {
		return errors.New("event is not registered")
	}
	if monitor.isRunning {
		monitor.events.remove(eventid)
	} else {
		monitor.events.removeInPlace(eventid)
	}
	monitor.removeRegisteredEvent(event)

	return nil
}

// RegisteredEventType returns the type of an event
func (monitor *EventMonitor) RegisteredEventType(
	eventID uint64,
) (EventType, bool) {
	event, ok := monitor.events.lookup(eventID)
	if !ok {
		return EventTypeInvalid, false
	}
	return event.eventType, true
}

// Close gracefully cleans up an EventMonitor instance. If the EventMonitor
// is still running when Close is called, it will first be stopped. After
// Close completes, the EventMonitor instance cannot be reused.
func (monitor *EventMonitor) Close(wait bool) error {
	// if the monitor is running, stop it and wait for it to stop
	monitor.Stop(wait)

	// This lock isn't strictly necessary -- by the time .Close() is
	// called, it would be a programming error for multiple go routines
	// to be trying to close the monitor or update events. It doesn't
	// hurt to lock, so do it anyway just to be on the safe side.
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	for _, event := range monitor.events.getMap() {
		monitor.removeRegisteredEvent(event)
	}
	monitor.events = nil

	if len(monitor.eventfds) != 0 {
		panic("internal error: stray event fds left after monitor Close")
	}
	monitor.eventfds = nil

	if len(monitor.eventids) != 0 {
		panic("internal error: stray event ids left after monitor Close")
	}
	monitor.eventids = nil

	if len(monitor.eventAttrMap.getMap()) != 0 {
		panic("internal error: stray event attrs left after monitor Close")
	}
	monitor.eventAttrMap = nil

	if len(monitor.eventIDMap.getMap()) != 0 {
		panic("internal error: stray event IDs left after monitor Close")
	}
	monitor.eventIDMap = nil

	for _, group := range monitor.groups {
		group.cleanup()
	}
	monitor.groups = nil

	if monitor.epollFD != -1 {
		unix.Close(monitor.epollFD)
		monitor.epollFD = -1
	}

	return nil
}

// Disable is used to disable a registered event. The event to disable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Disable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if ok {
		for _, fd := range event.fds {
			disable(fd)
		}
	}
}

// DisableAll disables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) DisableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	// Group FDs are always disabled
	for fd := range monitor.eventfds {
		disable(fd)
	}
}

// Enable is used to enable a registered event. The event to enable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Enable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if ok {
		for _, fd := range event.fds {
			enable(fd)
		}
	}
}

// EnableAll enables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) EnableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	// Group FDs are always disabled
	for fd := range monitor.eventfds {
		enable(fd)
	}
}

// SetFilter is used to set or remove a filter from a registered event.
func (monitor *EventMonitor) SetFilter(eventid uint64, filter string) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events.lookup(eventid)
	if ok {
		for _, fd := range event.fds {
			err := setFilter(fd, filter)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (monitor *EventMonitor) stopWithSignal() {
	monitor.lock.Lock()
	monitor.isRunning = false
	monitor.cond.Broadcast()
	monitor.lock.Unlock()
}

// EventMonitorSample is an encapsulation of a sample from the EventMonitor
// interface. It contains the raw sample, decoded data, translated sample,
// and any error that may have occurred while processing the sample.
type EventMonitorSample struct {
	// RawSample is the raw sample from the perf_event interface.
	RawSample Sample

	// Fields is name and type information about the fields defined for
	// the event. Data in DecodedData will correspond to this field
	// information.
	Fields map[string]int32

	// DecodedData is the sample data decoded from RawSample.Record.RawData
	// if RawSample is of type *SampleRecord; otherwise, it will be nil.
	DecodedData TraceEventSampleData

	// DecodedSample is the value returned from calling the registered
	// decoder for RawSample and DecodedData together.
	DecodedSample interface{}

	// Err will be non-nil if any occurred during processing of RawSample.
	Err error
}

type externalSample struct {
	eventID uint64
	sample  EventMonitorSample
}

// externalSampleList implements sort.Interface and is used for sorting a list
// of externalSample instances by time in descending order.
type externalSampleList []externalSample

func (l externalSampleList) Len() int {
	return len(l)
}

func (l externalSampleList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func (l externalSampleList) Less(i, j int) bool {
	return l[i].sample.RawSample.Time > l[j].sample.RawSample.Time
}

// EnqueueExternalSample enqueues an external sample to a registered external
// eventID. Events may not be enqueued for eventIDs that are not registered or
// not registered as external. Events with timestamps that fall outside the
// eventstream will be dropped.
func (monitor *EventMonitor) EnqueueExternalSample(
	eventID uint64,
	sampleID SampleID,
	decodedData TraceEventSampleData,
) error {
	event, ok := monitor.events.lookup(eventID)
	if !ok {
		return fmt.Errorf("Invalid eventID %d", eventID)
	}
	if event.eventType != EventTypeExternal {
		return fmt.Errorf("EventID %d is not an external type", eventID)
	}
	if sampleID.Time == 0 {
		return fmt.Errorf("Invalid sample time (%d)", sampleID.Time)
	}
	if sampleID.Time < monitor.lastSampleTimeDispatched {
		// Silently drop the event; it will only be dropped later, so
		// save some time now
		return nil
	}

	esm := EventMonitorSample{
		Fields:      event.fields,
		DecodedData: decodedData,
	}
	esm.RawSample.Type = PERF_RECORD_SAMPLE
	esm.RawSample.Record = &SampleRecord{
		Pid:  sampleID.PID,
		Tid:  sampleID.TID,
		Time: sampleID.Time,
		CPU:  sampleID.CPU,
	}
	esm.RawSample.PID = sampleID.PID
	esm.RawSample.TID = sampleID.TID
	esm.RawSample.Time = sampleID.Time
	esm.RawSample.CPU = sampleID.CPU
	e := externalSample{
		eventID: eventID,
		sample:  esm,
	}

	var updateMonitorGoRoutine = false

	monitor.lock.Lock()
	monitor.externalSamples = append(monitor.externalSamples, e)
	if monitor.nextExternalSampleTime == 0 ||
		sampleID.Time < monitor.nextExternalSampleTime {
		monitor.nextExternalSampleTime = sampleID.Time
		updateMonitorGoRoutine = true
	}
	monitor.lock.Unlock()

	if updateMonitorGoRoutine {
		var buffer = make([]byte, 8)
		binary.LittleEndian.PutUint64(buffer, sampleID.Time)
		syscall.Write(monitor.pipe[1], buffer)
	}

	return nil
}

func (monitor *EventMonitor) processExternalSamples(timeLimit uint64) {
	if monitor.externalSamples != nil {
		monitor.lock.Lock()
		externalSamples := monitor.externalSamples
		monitor.externalSamples = nil
		monitor.nextExternalSampleTime = 0
		monitor.lock.Unlock()

		monitor.pendingExternalSamples = append(
			monitor.pendingExternalSamples, externalSamples...)
		sort.Sort(monitor.pendingExternalSamples)
	}

	if len(monitor.pendingExternalSamples) == 0 {
		return
	}

	dispatchFn := monitor.dispatchFn
	eventMap := monitor.events.getMap()
	for len(monitor.pendingExternalSamples) > 0 {
		l := len(monitor.pendingExternalSamples)
		e := monitor.pendingExternalSamples[l-1]
		if e.sample.RawSample.Time > timeLimit {
			break
		}
		monitor.pendingExternalSamples =
			monitor.pendingExternalSamples[:l-1]
		if e.sample.RawSample.Time < monitor.lastSampleTimeDispatched {
			continue
		}
		event, ok := eventMap[e.eventID]
		if !ok {
			continue
		}
		if event.decoderFn != nil {
			e.sample.DecodedSample, e.sample.Err = event.decoderFn(
				e.sample.RawSample.Record.(*SampleRecord),
				e.sample.DecodedData)
		}
		dispatchFn(e.eventID, e.sample)
	}

	l := len(monitor.pendingExternalSamples)
	if l > 0 {
		monitor.lock.Lock()
		nextTimeout := monitor.pendingExternalSamples[l-1].sample.RawSample.Time
		monitor.nextExternalSampleTime = nextTimeout
		monitor.lock.Unlock()

		if nextTimeout > 0 {
			var buffer = make([]byte, 8)
			binary.LittleEndian.PutUint64(buffer, nextTimeout)
			syscall.Write(monitor.pipe[1], buffer)
		}
	}
}

type sampleMerger struct {
	samples [][]EventMonitorSample
	indices []int
}

func (m *sampleMerger) next() (EventMonitorSample, bool) {
	nSources := len(m.indices)
	if nSources == 0 {
		return EventMonitorSample{}, true
	}

	// Samples from each ringbuffer will be in timestamp order; therefore,
	// we can simpy look at the first element in each source to find the
	// next one to return.

	if nSources == 1 {
		sample := m.samples[0][m.indices[0]]
		m.indices[0]++
		if m.indices[0] == len(m.samples[0]) {
			m.samples = nil
			m.indices = nil
		}
		return sample, false
	}

	index := 0
	value := m.samples[0][m.indices[0]].RawSample.Time
	for i := 1; i < nSources; i++ {
		if v := m.samples[i][m.indices[i]].RawSample.Time; v < value {
			index = i
			value = v
		}
	}
	sample := m.samples[index][m.indices[index]]

	m.indices[index]++
	if m.indices[index] == len(m.samples[index]) {
		nSources--
		m.indices[index] = m.indices[nSources]
		m.indices = m.indices[:nSources]
		m.samples[index] = m.samples[nSources]
		m.samples = m.samples[:nSources]
	}

	return sample, false
}

func newSampleMerger(samples [][]EventMonitorSample) sampleMerger {
	return sampleMerger{
		samples: samples,
		indices: make([]int, len(samples)),
	}
}

func (monitor *EventMonitor) dispatchSamples(samples [][]EventMonitorSample) {
	dispatchFn := monitor.dispatchFn
	eventIDMap := monitor.eventIDMap.getMap()
	eventMap := monitor.events.getMap()

	m := newSampleMerger(samples)
	for {
		esm, done := m.next()
		if done {
			break
		}

		monitor.processExternalSamples(esm.RawSample.Time)

		streamID := esm.RawSample.SampleID.StreamID
		eventID, ok := eventIDMap[streamID]
		if !ok {
			// Refresh the map in case we're dealing with a newly
			// added event, but more likely we're here because the
			// event has been removed while we're still processing
			// samples from the ringbuffer.
			eventIDMap = monitor.eventIDMap.getMap()
			eventMap = monitor.events.getMap()
			eventID, ok = eventIDMap[streamID]
			if !ok {
				continue
			}
		}

		event, ok := eventMap[eventID]
		if !ok {
			// If not ok, the eventID has been removed while we're
			// still processing samples. Drop it
			continue
		}
		esm.Fields = event.fields

		switch record := esm.RawSample.Record.(type) {
		case *SampleRecord:
			// Adjust the sample time so that it
			// matches the normalized timestamp.
			record.Time = esm.RawSample.Time
			if esm.Err == nil &&
				(event.eventType == EventTypeTracepoint ||
					event.eventType == EventTypeKprobe ||
					event.eventType == EventTypeUprobe) {
				esm.DecodedData, esm.DecodedSample, esm.Err =
					monitor.decoders.DecodeSample(record)
			}
		}
		dispatchFn(eventID, esm)
		if esm.RawSample.Time > monitor.lastSampleTimeDispatched {
			monitor.lastSampleTimeDispatched = esm.RawSample.Time
		}
	}

	monitor.processExternalSamples(monitor.lastSampleTimeDispatched)
}

func (monitor *EventMonitor) dispatchSampleLoop() {
	defer monitor.wg.Done()

	for monitor.isRunning {
		select {
		case samples, ok := <-monitor.dispatchChan:
			if !ok {
				// Channel is closed; stop dispatch
				monitor.dispatchChan = nil
				return
			}

			if len(samples) > 0 {
				monitor.dispatchSamples(samples)
			} else {
				monitor.processExternalSamples(uint64(time.Now().UnixNano()))
			}
		}
	}
}

func (monitor *EventMonitor) readRingBuffers(readyfds []int) {
	// Clear the monitor's hasPendingSamples flag immediately. All samples
	// pending at this time will be included for processing. New pending
	// samples may be added and so this flag will be updated later.
	monitor.hasPendingSamples = false

	var lastTimestamp uint64
	samples := make([][]EventMonitorSample, 0, len(readyfds))
	for _, fd := range readyfds {
		// It is not necessary to read from the ready fd, because the
		// kernel fabricates that information on demand. We're not
		// interested in it, so don't bother. Emptying the ringbuffer
		// is what clears the fd's ready state.

		var groupSamples, newPendingSamples []EventMonitorSample
		group := monitor.groups[fd]
		group.processed = true

		group.rb.read(func(data []byte) {
			attrMap := monitor.eventAttrMap.getMap()
			r := bytes.NewReader(data)
			for r.Len() > 0 {
				ems := EventMonitorSample{}
				ems.Err = ems.RawSample.read(r, nil, attrMap)
				ems.RawSample.Time =
					uint64(int64(ems.RawSample.Time) -
						timeOffsets[group.cpu])
				groupSamples = append(groupSamples, ems)
			}
		})

		if len(groupSamples) == 0 {
			if len(group.pendingSamples) > 0 {
				samples = append(samples, group.pendingSamples)
			}
			group.pendingSamples = nil
			continue
		}

		if lastTimestamp == 0 {
			lastTimestamp = groupSamples[len(groupSamples)-1].RawSample.Time
		} else {
			l := len(groupSamples)
			for i := l - 1; i >= 0; i-- {
				if groupSamples[i].RawSample.Time <= lastTimestamp {
					break
				}
				l--
			}
			if l != len(groupSamples) {
				monitor.hasPendingSamples = true
				newPendingSamples = groupSamples[l:]
				groupSamples = groupSamples[:l]
				if len(groupSamples) == 0 {
					group.pendingSamples = newPendingSamples
					continue
				}
			}
		}

		groupSamples = append(group.pendingSamples, groupSamples...)
		group.pendingSamples = newPendingSamples
		samples = append(samples, groupSamples)
	}

	for _, group := range monitor.groups {
		if !group.processed && len(group.pendingSamples) > 0 {
			samples = append(samples, group.pendingSamples)
			group.pendingSamples = nil
		}
		group.processed = false
	}

	if len(samples) > 0 {
		monitor.dispatchChan <- samples
	}
}

func (monitor *EventMonitor) flushPendingSamples() {
	var samples [][]EventMonitorSample
	for _, group := range monitor.groups {
		if len(group.pendingSamples) > 0 {
			samples = append(samples, group.pendingSamples)
			group.pendingSamples = nil
		}
	}

	monitor.hasPendingSamples = false
	if len(samples) > 0 {
		monitor.dispatchChan <- samples
	}
}

// Go does not provide fcntl(). We need to provide it for ourselves
func fcntl(fd, cmd int, flag uintptr) (uintptr, error) {
	r1, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), flag)
	return r1, errno
}

// Run puts an EventMonitor into the running state. While an EventMonitor is
// running, samples will be pulled from event sources, decoded, and dispatched
// to a function that is specified here.
func (monitor *EventMonitor) Run(fn SampleDispatchFn) error {
	monitor.lock.Lock()
	if monitor.isRunning {
		monitor.lock.Unlock()
		return errors.New("monitor is already running")
	}
	monitor.isRunning = true

	err := unix.Pipe(monitor.pipe[:])
	monitor.lock.Unlock()
	if err != nil {
		monitor.stopWithSignal()
		return err
	}
	f, _ := fcntl(monitor.pipe[0], syscall.F_GETFL, 0)
	fcntl(monitor.pipe[0], syscall.F_SETFL, f|syscall.O_NONBLOCK)

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     -1,
	}
	err = unix.EpollCtl(monitor.epollFD, unix.EPOLL_CTL_ADD,
		monitor.pipe[0], &event)

	monitor.dispatchChan = make(chan [][]EventMonitorSample,
		config.Sensor.ChannelBufferLength)
	monitor.dispatchFn = fn

	monitor.wg.Add(1)
	go monitor.dispatchSampleLoop()

	var nextTimeout int64
	events := make([]unix.EpollEvent, len(monitor.groups))

runloop:
	for {
		var n int

		// If there are pending samples, check for waiting events and
		// return immediately. If there aren't any, flush everything
		// pending and go back to waiting for events normally. If there
		// are events, the pending events will get handled during
		// normal processing
		if monitor.hasPendingSamples {
			n, err = unix.EpollWait(monitor.epollFD, events, 0)
			if err != nil && err != unix.EINTR {
				break
			}
			if n == 0 {
				monitor.flushPendingSamples()
				continue
			}
		} else {
			var timeout int
			if nextTimeout == 0 {
				timeout = -1
			} else {
				now := time.Now().UnixNano()
				if now > nextTimeout {
					nextTimeout = 0
					timeout = 0
				} else {
					timeout = int((nextTimeout - now) / 1e6)
				}
			}
			n, err = unix.EpollWait(monitor.epollFD, events, timeout)
			if err != nil && err != unix.EINTR {
				break
			}
		}

		if n == 0 {
			if monitor.nextExternalSampleTime != 0 {
				monitor.dispatchChan <- nil
			}
		} else if n > 0 {
			readyfds := make([]int, 0, n)
			for i := 0; i < n; i++ {
				e := events[i]
				if e.Fd == -1 {
					if e.Events & ^uint32(unix.EPOLLIN) != 0 {
						// EPOLLERR, EPOLLHUP, etc.
						break runloop
					}
					if e.Events&unix.EPOLLIN != unix.EPOLLIN {
						continue
					}
					fd := monitor.pipe[0]
					for {
						var buffer = make([]byte, 8)

						_, err = syscall.Read(fd, buffer)
						if err != nil {
							if err == syscall.EINTR {
								continue
							}
							break
						}
						v := int64(binary.LittleEndian.Uint64(buffer))
						if nextTimeout == 0 || v < nextTimeout {
							nextTimeout = v
						}
					}
				} else if (e.Events & unix.EPOLLIN) != 0 {
					readyfds = append(readyfds, int(e.Fd))
				}
			}
			if len(readyfds) > 0 {
				monitor.readRingBuffers(readyfds)
			} else if monitor.hasPendingSamples {
				monitor.flushPendingSamples()
			}
		}
	}

	if monitor.dispatchChan != nil {
		close(monitor.dispatchChan)
	}

	monitor.lock.Lock()
	if monitor.pipe[1] != -1 {
		unix.Close(monitor.pipe[1])
		monitor.pipe[1] = -1
	}
	if monitor.pipe[0] != -1 {
		unix.Close(monitor.pipe[0])
		monitor.pipe[0] = -1
	}
	monitor.lock.Unlock()

	if monitor.dispatchChan != nil {
		// Wait for dispatchSampleLoop goroutine to exit
		monitor.wg.Wait()
	}

	monitor.stopWithSignal()
	return err
}

// Stop stops a running EventMonitor. If the EventMonitor is not running, this
// function does nothing. Once an EventMonitor has been stopped, it may be
// restarted again. Whether Stop waits for the EventMonitor to fully stop is
// optional, but if the caller does not wait there is no other mechanism by
// which the caller may learn whether the EventMonitor is stopped.
func (monitor *EventMonitor) Stop(wait bool) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if !monitor.isRunning {
		return
	}

	if monitor.pipe[1] != -1 {
		fd := monitor.pipe[1]
		monitor.pipe[1] = -1
		unix.Close(fd)
	}

	if wait {
		for monitor.isRunning {
			// Wait for condition to signal that Run() is done
			monitor.cond.Wait()
		}
	}
}

func collectReferenceSamples(ncpu int) ([]*Sample, error) {
	referenceEventAttr := &EventAttr{
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_CPU_CLOCK,
		SampleFreq:   1,
		SampleType:   PERF_SAMPLE_TIME,
		Disabled:     true,
		Freq:         true,
		WakeupEvents: 1,
	}

	rbs := make([]*ringBuffer, ncpu)
	pollfds := make([]unix.PollFd, ncpu)
	for cpu := 0; cpu < ncpu; cpu++ {
		fd, err := open(referenceEventAttr, -1, cpu, -1, 0)
		if err != nil {
			err = fmt.Errorf("Couldn't open reference event: %s", err)
			return nil, err
		}
		defer unix.Close(fd)
		pollfds[cpu] = unix.PollFd{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		}

		rbs[cpu], err = newRingBuffer(fd, 1)
		if err != nil {
			err = fmt.Errorf("Couldn't allocate ringbuffer: %s", err)
			return nil, err
		}
		defer rbs[cpu].unmap()
	}

	// Enable all of the events we just registered
	for _, p := range pollfds {
		enable(int(p.Fd))
	}

	// Read all samples from each group, but keep only the first for each
	// Don't wait forever. Return a timeout error if samples don't arrive
	// within 2 seconds.
	const timeout = 2 * time.Second
	glog.V(2).Infof("Calculating CPU time offsets (max wait %d nsec)", timeout)

	nsamples := 0
	samples := make([]*Sample, ncpu)
	timeoutAt := now() + int64(timeout)
	for nsamples < ncpu {
		t := now()
		if t >= timeoutAt {
			return nil, errors.New("Timeout while reading samples")
		}
		n, err := unix.Poll(pollfds, int((timeoutAt-t)/int64(time.Millisecond)))
		if err != nil && err != unix.EINTR {
			return nil, err
		}
		if n == 0 {
			continue
		}

		for cpu, p := range pollfds {
			if p.Revents&unix.POLLIN != unix.POLLIN {
				continue
			}

			rbs[cpu].read(func(data []byte) {
				r := bytes.NewReader(data)
				s := Sample{}
				err := s.read(r, referenceEventAttr, nil)
				if err == nil {
					samples[cpu] = &s
					nsamples++
				}
			})

			if samples[cpu] != nil {
				pollfds[cpu].Events &= ^unix.POLLIN
			}
		}
	}

	return samples, nil
}

func calculateTimeOffsets() error {
	// If there's only one CPU, there's nothing to do since offsets are
	// relative to CPU 0.
	ncpu := runtime.NumCPU()
	timeOffsets = make([]int64, ncpu)
	if haveClockID || ncpu < 2 {
		return nil
	}

	// Obtain references samples, one for each group.
	samples, err := collectReferenceSamples(ncpu)
	if err != nil {
		return err
	}

	// Calculate offsets relative to CPU 0.
	timeBase := int64(samples[0].Time)
	for cpu := 1; cpu < ncpu; cpu++ {
		timeOffsets[cpu] = int64(samples[cpu].Time) - timeBase
		glog.V(2).Infof("EventMonitor CPU %d time offset is %d\n",
			cpu, timeOffsets[cpu])
	}

	return nil
}

func (monitor *EventMonitor) initializeGroupLeaders(
	pid int,
	flags uintptr,
	ringBufferNumPages int,
) error {
	groupEventAttr := &EventAttr{
		Type:     PERF_TYPE_SOFTWARE,
		Config:   PERF_COUNT_SW_DUMMY, // Added in Linux 3.12
		Disabled: true,
	}
	if haveClockID {
		groupEventAttr.UseClockID = true
		groupEventAttr.ClockID = unix.CLOCK_MONOTONIC_RAW
	}

	ncpu := runtime.NumCPU()
	groups := make([]*perfEventGroup, ncpu)
	for cpu := 0; cpu < ncpu; cpu++ {
		groupfd, err := open(groupEventAttr, pid, cpu, -1, flags)
		if err != nil {
			for fd := range groups {
				unix.Close(fd)
			}
			return err
		}

		groups[cpu] = &perfEventGroup{
			pid:   pid,
			cpu:   cpu,
			fd:    groupfd,
			flags: flags,
		}

		groups[cpu].rb, err = newRingBuffer(groupfd, ringBufferNumPages)
		if err != nil {
			for i := cpu; i >= 0; i-- {
				groups[i].cleanup()
			}
			return err
		}

		event := unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(groupfd),
		}
		err = unix.EpollCtl(monitor.epollFD, unix.EPOLL_CTL_ADD,
			groupfd, &event)
		if err != nil {
			for i := cpu; i >= 0; i-- {
				groups[i].cleanup()
			}
			return err
		}
	}

	for _, v := range groups {
		monitor.groups[v.fd] = v
	}

	return nil
}

func doProbeCleanup(
	tracingDir, eventsFile string,
	activePids, deadPids map[int]bool,
) {
	eventsFilename := filepath.Join(tracingDir, eventsFile)
	data, err := ioutil.ReadFile(eventsFilename)
	if err != nil {
		return
	}

	var file *os.File

	// Read one line at a time and check for capsule8/sensor_ probes. The
	// pid that created the probe is encoded within. If the pid is dead,
	// remove the probe.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		name := line[2:strings.Index(line, " ")]
		if !strings.HasPrefix(name, "capsule8/sensor_") {
			continue
		}

		// Capsule8 sensor names are of the form sensor_<pid>_<count>
		var pid int
		fmt.Sscanf(name, "capsule8/sensor_%d_", &pid)
		if activePids[pid] {
			continue
		} else if !deadPids[pid] {
			if syscall.Kill(pid, 0) != syscall.ESRCH {
				activePids[pid] = true
				continue
			}
			deadPids[pid] = true
		}

		cmd := fmt.Sprintf("-:%s\n", name)
		if file == nil {
			file, err = os.OpenFile(eventsFilename, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				glog.Errorf("Couldn't open %s WO+A: %s", eventsFilename, err)
				return
			}
			defer file.Close()
		}
		file.Write([]byte(cmd))
		glog.V(1).Infof("Removed stale probe from %s: %s", eventsFile, name)
	}
}

func cleanupStaleProbes(tracingDir string) {
	activePids := make(map[int]bool)
	deadPids := make(map[int]bool)

	activePids[os.Getpid()] = true

	doProbeCleanup(tracingDir, "kprobe_events", activePids, deadPids)
	doProbeCleanup(tracingDir, "uprobe_events", activePids, deadPids)
}

// NewEventMonitor creates a new EventMonitor instance in the stopped state.
// Once an EventMonitor instance is returned from this function, its Close
// method must be called to clean it up gracefully, even if no events are
// registered or it is never put into the running state.
func NewEventMonitor(options ...EventMonitorOption) (*EventMonitor, error) {
	eventMonitorOnce.Do(func() {
		attr := EventAttr{
			SamplePeriod:    1,
			Disabled:        true,
			UseClockID:      true,
			ClockID:         unix.CLOCK_MONOTONIC_RAW,
			Watermark:       true,
			WakeupWatermark: 1,
		}
		fd, err := open(&attr, 0, -1, -1, 0)
		if err == nil {
			unix.Close(fd)
			haveClockID = true
		}
		calculateTimeOffsets()
	})
	if haveClockID && !notedClockID {
		glog.V(1).Infof("EventMonitor is using ClockID CLOCK_MONOTONIC_RAW")
		notedClockID = true
	}

	opts := eventMonitorOptions{}
	for _, option := range options {
		option(&opts)
	}

	var eventAttr EventAttr

	if opts.defaultEventAttr == nil {
		eventAttr = EventAttr{
			SamplePeriod: 1,
			SampleType:   PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
			Disabled:     true,
			Inherit:      true,
		}
	} else {
		eventAttr = *opts.defaultEventAttr
	}
	fixupEventAttr(&eventAttr)

	// Only allow certain flags to be passed
	opts.flags &= PERF_FLAG_FD_CLOEXEC

	// If no tracing dir was specified, scan mounts for one
	if len(opts.tracingDir) == 0 {
		opts.tracingDir = sys.TracingDir()
	}
	cleanupStaleProbes(opts.tracingDir)

	// If no perf_event cgroup mountpoint was specified, scan mounts for one
	if len(opts.perfEventDir) == 0 && len(opts.cgroups) > 0 {
		opts.perfEventDir = sys.PerfEventDir()

		// If we didn't find one, we can't monitor specific cgroups
		if len(opts.perfEventDir) == 0 {
			return nil, errors.New("Can't monitor specific cgroups without perf_event cgroupfs")
		}
	}

	// If no pids or cgroups were specified, default to monitoring the
	// whole system (pid -1)
	if len(opts.pids) == 0 && len(opts.cgroups) == 0 {
		opts.pids = append(opts.pids, -1)
	}

	epollFD, err := unix.EpollCreate1(0)
	if err != nil {
		return nil, err
	}

	monitor := &EventMonitor{
		groups:       make(map[int]*perfEventGroup),
		epollFD:      epollFD,
		eventAttrMap: newSafeEventAttrMap(),
		eventIDMap:   newSafeUInt64Map(),
		decoders:     newTraceEventDecoderMap(opts.tracingDir),
		events:       newSafeRegisteredEventMap(),
		nextEventID:  1,
		eventfds:     make(map[int]int),
		eventids:     make(map[int]uint64),
		defaultAttr:  eventAttr,
		tracingDir:   opts.tracingDir,
	}
	monitor.lock = &sync.Mutex{}
	monitor.cond = sync.NewCond(monitor.lock)

	cgroups := make(map[string]bool, len(opts.cgroups))
	for _, cgroup := range opts.cgroups {
		if cgroups[cgroup] {
			glog.V(1).Infof("Ignoring duplicate cgroup %s", cgroup)
			continue
		}
		cgroups[cgroup] = true

		path := filepath.Join(opts.perfEventDir, cgroup)
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err == nil {
			err = monitor.initializeGroupLeaders(fd,
				opts.flags|PERF_FLAG_PID_CGROUP,
				opts.ringBufferNumPages)
			if err == nil {
				continue
			}
		}

		for _, group := range monitor.groups {
			group.cleanup()
		}
		return nil, err
	}

	pids := make(map[int]bool, len(opts.pids))
	for _, pid := range opts.pids {
		if pids[pid] {
			glog.V(1).Infof("Ignoring duplicate pid %d", pid)
			continue
		}
		pids[pid] = true

		err := monitor.initializeGroupLeaders(pid, opts.flags,
			opts.ringBufferNumPages)
		if err == nil {
			continue
		}

		for _, group := range monitor.groups {
			group.cleanup()
		}
		return nil, err
	}

	return monitor, nil
}
