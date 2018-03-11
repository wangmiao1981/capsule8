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
	"errors"
	"reflect"
	"sync"
	"unicode"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/gobwas/glob"
	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

var containerEventTypes = expression.FieldTypeMap{
	"name":             int32(api.ValueType_STRING),
	"image_id":         int32(api.ValueType_STRING),
	"image_name":       int32(api.ValueType_STRING),
	"host_pid":         int32(api.ValueType_SINT32),
	"exit_code":        int32(api.ValueType_SINT32),
	"exit_status":      int32(api.ValueType_UINT32),
	"exit_signal":      int32(api.ValueType_UINT32),
	"exit_core_dumped": int32(api.ValueType_BOOL),
}

// ContainerCache is a cache of container information
type ContainerCache struct {
	sync.Mutex
	cache map[string]*ContainerInfo

	sensor *Sensor

	// These are external event IDs registered with the sensor's event
	// monitor instance. The cache will enqueue these events as appropriate
	// as the cache is updated.
	ContainerCreatedEventID   uint64 // api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED
	ContainerRunningEventID   uint64 // api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING
	ContainerExitedEventID    uint64 // api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED
	ContainerDestroyedEventID uint64 // api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED
	ContainerUpdatedEventID   uint64 // api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED
}

// ContainerState represents the state of a container (created, running, etc.)
type ContainerState uint

const (
	// ContainerStateUnknown indicates that the container is in an unknown
	// state.
	ContainerStateUnknown ContainerState = iota

	// ContainerStateCreated indicates the container exists, but is not
	// running.
	ContainerStateCreated

	// ContainerStatePaused indicates the container is paused.
	ContainerStatePaused

	// ContainerStateRunning indicates the container is running.
	ContainerStateRunning

	// ContainerStateRestarting indicates the container is in the process
	// of restarting.
	ContainerStateRestarting

	// ContainerStateExited indicates the container has exited.
	ContainerStateExited

	// ContainerStateRemoving indicates the container is being removed.
	ContainerStateRemoving
)

// ContainerStateNames is a mapping of container states to printable names.
var ContainerStateNames = map[ContainerState]string{
	ContainerStateCreated:    "created",
	ContainerStateRestarting: "restarting",
	ContainerStateRunning:    "running",
	ContainerStateRemoving:   "removing",
	ContainerStatePaused:     "paused",
	ContainerStateExited:     "exited",
}

// ContainerRuntime represents the runtime used to manager a container
type ContainerRuntime uint

const (
	// ContainerRuntimeUnknown means the container runtime managing the
	// container is unknown. Information about the container comes from
	// runc, the kernel, or other generic sources.
	ContainerRuntimeUnknown ContainerRuntime = iota

	// ContainerRuntimeDocker means the container is managed by Docker.
	ContainerRuntimeDocker
)

// ContainerInfo records interesting information known about a container.
type ContainerInfo struct {
	cache *ContainerCache // the cache to which this info belongs

	ID        string
	Name      string
	ImageID   string
	ImageName string

	Pid      int
	ExitCode int

	Runtime ContainerRuntime
	State   ContainerState

	JSONConfig string
	OCIConfig  string
}

// NewContainerCache creates a new container cache.
func NewContainerCache(sensor *Sensor) *ContainerCache {
	cache := &ContainerCache{
		cache:  make(map[string]*ContainerInfo),
		sensor: sensor,
	}

	var err error
	cache.ContainerCreatedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_CREATED",
		cache.decodeContainerCreatedEvent,
		containerEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerRunningEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_RUNNING",
		cache.decodeContainerRunningEvent,
		containerEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerExitedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_EXITED",
		cache.decodeContainerExitedEvent,
		containerEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerDestroyedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_DESTROYED",
		cache.decodeContainerDestroyedEvent,
		containerEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ContainerUpdatedEventID, err = sensor.Monitor.RegisterExternalEvent(
		"CONTAINER_UPDATED",
		cache.decodeContainerUpdatedEvent,
		containerEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register extern event: %s", err)
	}

	return cache
}

// DeleteContainer removes a container from the cache.
func (cc *ContainerCache) DeleteContainer(
	containerID string,
	runtime ContainerRuntime,
	sampleID perf.SampleID,
) {
	cc.Lock()
	info, ok := cc.cache[containerID]
	if ok {
		if runtime == info.Runtime {
			delete(cc.cache, containerID)
		} else {
			ok = false
		}
	}
	cc.Unlock()

	if ok {
		glog.V(2).Infof("Sending CONTAINER_DESTROYED for %s", info.ID)
		cc.enqueueContainerEvent(cc.ContainerDestroyedEventID,
			sampleID, info)
	}
}

func (cc *ContainerCache) newContainerInfo(containerID string) *ContainerInfo {
	return &ContainerInfo{
		cache:   cc,
		ID:      containerID,
		Runtime: ContainerRuntimeUnknown,
	}
}

// LookupContainer searches the cache for a container by ID and returns any
// information found, optionally creating a cache entry if there is one does
// not already exist.
func (cc *ContainerCache) LookupContainer(containerID string, create bool) *ContainerInfo {
	cc.Lock()
	defer cc.Unlock()

	info := cc.cache[containerID]
	if info == nil && create {
		info = cc.newContainerInfo(containerID)
		cc.cache[containerID] = info
	}

	return info
}

func (cc *ContainerCache) enqueueContainerEvent(
	eventID uint64,
	sampleID perf.SampleID,
	info *ContainerInfo,
) error {
	ws := unix.WaitStatus(info.ExitCode)
	data := map[string]interface{}{
		"container_id":     info.ID,
		"name":             info.Name,
		"image_id":         info.ImageID,
		"image_name":       info.ImageName,
		"host_pid":         int32(info.Pid),
		"exit_code":        int32(info.ExitCode),
		"exit_status":      uint32(0),
		"exit_signal":      uint32(0),
		"exit_core_dumped": ws.CoreDump(),
	}

	if ws.Exited() {
		data["exit_status"] = uint32(ws.ExitStatus())
	}
	if ws.Signaled() {
		data["exit_signal"] = uint32(ws.Signal())
	}

	return cc.sensor.Monitor.EnqueueExternalSample(eventID, sampleID, data)
}

func (cc *ContainerCache) newContainerEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
	eventType api.ContainerEventType,
) (*api.TelemetryEvent, error) {
	event := cc.sensor.NewEventFromSample(sample, data)
	if event == nil {
		return nil, nil
	}

	cev := &api.ContainerEvent{
		Type:           eventType,
		ImageId:        data["image_id"].(string),
		ImageName:      data["image_name"].(string),
		HostPid:        data["host_pid"].(int32),
		ExitCode:       data["exit_code"].(int32),
		ExitStatus:     data["exit_status"].(uint32),
		ExitSignal:     data["exit_signal"].(uint32),
		ExitCoreDumped: data["exit_core_dumped"].(bool),
	}

	if s, ok := data["docker_config"].(string); ok && len(s) > 0 {
		cev.DockerConfigJson = s
	}
	if s, ok := data["oci_config"].(string); ok && len(s) > 0 {
		cev.OciConfigJson = s
	}

	event.ContainerId = data["container_id"].(string)
	event.Event = &api.TelemetryEvent_Container{
		Container: cev,
	}
	return event, nil
}

func (cc *ContainerCache) decodeContainerCreatedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED)
}

func (cc *ContainerCache) decodeContainerRunningEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING)
}

func (cc *ContainerCache) decodeContainerExitedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED)
}

func (cc *ContainerCache) decodeContainerDestroyedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED)
}

func (cc *ContainerCache) decodeContainerUpdatedEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return cc.newContainerEvent(sample, data,
		api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED)
}

// Update updates the data cached for a container with new information. Some
// new information may trigger telemetry events to fire.
func (info *ContainerInfo) Update(
	runtime ContainerRuntime,
	sampleID perf.SampleID,
	data map[string]interface{},
) {
	if info.Runtime == ContainerRuntimeUnknown {
		info.Runtime = runtime
	}

	oldState := info.State
	dataChanged := false

	s := reflect.ValueOf(info).Elem()
	t := s.Type()
	for i := t.NumField() - 1; i >= 0; i-- {
		f := t.Field(i)
		if !unicode.IsUpper(rune(f.Name[0])) {
			continue
		}
		v, ok := data[f.Name]
		if !ok {
			continue
		}
		if !reflect.TypeOf(v).AssignableTo(f.Type) {
			glog.Fatalf("Cannot assign %v to %s %s",
				v, f.Name, f.Type)
		}

		if s.Field(i).Interface() != v {
			if f.Name != "State" {
				dataChanged = true
			} else if info.Runtime != runtime {
				// Only allow state changes from the runtime
				// known to be managing the container.
				continue
			}
			s.Field(i).Set(reflect.ValueOf(v))
		}
	}

	if info.State != oldState {
		if oldState < ContainerStateCreated {
			glog.V(2).Infof("Sending CONTAINER_CREATED for %s", info.ID)
			info.cache.enqueueContainerEvent(
				info.cache.ContainerCreatedEventID, sampleID,
				info)
		}
		if oldState < ContainerStateRunning &&
			info.State >= ContainerStateRunning {
			glog.V(2).Infof("Sending CONTAINER_RUNNING for %s", info.ID)
			info.cache.enqueueContainerEvent(
				info.cache.ContainerRunningEventID, sampleID,
				info)
		}
		if oldState < ContainerStateRestarting &&
			info.State >= ContainerStateRestarting {
			glog.V(2).Infof("Sending CONTAINER_EXITED for %s", info.ID)
			info.cache.enqueueContainerEvent(
				info.cache.ContainerExitedEventID,
				sampleID, info)
		}
	} else if dataChanged {
		glog.V(2).Infof("Sending CONTAINER_UPDATED for %s", info.ID)
		info.cache.enqueueContainerEvent(
			info.cache.ContainerUpdatedEventID, sampleID, info)
	}
}

func registerContainerEvents(
	sensor *Sensor,
	groupID int32,
	eventMap subscriptionMap,
	events []*api.ContainerEventFilter,
) {
	var (
		filters       [6]*api.Expression
		subscriptions [6]*subscription
	)

	for _, cef := range events {
		t := cef.Type
		if t < 1 || t > 5 {
			continue
		}
		if subscriptions[t] == nil {
			var eventID uint64
			switch t {
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED:
				eventID = sensor.ContainerCache.ContainerCreatedEventID
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING:
				eventID = sensor.ContainerCache.ContainerRunningEventID
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED:
				eventID = sensor.ContainerCache.ContainerExitedEventID
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED:
				eventID = sensor.ContainerCache.ContainerDestroyedEventID
			case api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED:
				eventID = sensor.ContainerCache.ContainerUpdatedEventID
			}
			subscriptions[t] = eventMap.subscribe(eventID)
		}
		filters[t] = expression.LogicalOr(filters[t], cef.FilterExpression)
	}

	for i, s := range subscriptions {
		if filters[i] == nil {
			// No filter, no problem
			continue
		}

		expr, err := expression.NewExpression(filters[i])
		if err != nil {
			// Bad filter. Remove subscription
			glog.V(1).Infof("Invalid container filter expression: %s", err)
			eventMap.unsubscribe(s.eventID)
			continue
		}

		err = expr.Validate(containerEventTypes)
		if err != nil {
			// Bad filter. Remove subscription
			glog.V(1).Infof("Invalid container filter expression: %s", err)
			eventMap.unsubscribe(s.eventID)
			continue
		}

		s.filter = expr
	}
}

///////////////////////////////////////////////////////////////////////////////

func newContainerFilter(ecf *api.ContainerFilter) (*containerFilter, error) {
	if len(ecf.Ids) == 0 && len(ecf.Names) == 0 &&
		len(ecf.ImageIds) == 0 && len(ecf.ImageNames) == 0 {
		return nil, errors.New("Container filter is empty")
	}

	cf := &containerFilter{}

	for _, v := range ecf.Ids {
		cf.addContainerID(v)
	}

	for _, v := range ecf.Names {
		cf.addContainerName(v)
	}

	for _, v := range ecf.ImageIds {
		cf.addImageID(v)
	}

	for _, v := range ecf.ImageNames {
		cf.addImageName(v)
	}

	return cf, nil
}

type containerFilter struct {
	containerIds   map[string]bool
	containerNames map[string]bool
	imageIds       map[string]bool
	imageGlobs     map[string]glob.Glob
}

func (c *containerFilter) addContainerID(cid string) {
	if len(cid) > 0 {
		if c.containerIds == nil {
			c.containerIds = make(map[string]bool)
		}
		c.containerIds[cid] = true
	}
}

func (c *containerFilter) removeContainerID(cid string) {
	delete(c.containerIds, cid)
}

func (c *containerFilter) addContainerName(cname string) {
	if len(cname) > 0 {
		if c.containerNames == nil {
			c.containerNames = make(map[string]bool)
		}
		c.containerNames[cname] = true
	}
}

func (c *containerFilter) addImageID(iid string) {
	if len(iid) > 0 {
		if c.imageIds == nil {
			c.imageIds = make(map[string]bool)
		}
		c.imageIds[iid] = true
	}
}

func (c *containerFilter) addImageName(iname string) {
	if len(iname) > 0 {
		if c.imageGlobs == nil {
			c.imageGlobs = make(map[string]glob.Glob)
		} else {
			_, ok := c.imageGlobs[iname]
			if ok {
				return
			}
		}

		g, err := glob.Compile(iname, '/')
		if err == nil {
			c.imageGlobs[iname] = g
		}
	}
}

// match evaluates the container filter for an event and determines whether the
// event matches the criteria set forth by the filter.
func (c *containerFilter) match(e *api.TelemetryEvent) bool {
	// Fast path: Check if containerId is in containerIds map
	if c.containerIds[e.ContainerId] {
		return true
	}

	// Slow path: Check if other identifiers are in maps. If they are, add
	// the containerId to containerIds map to take fast path next time.
	switch ev := e.Event.(type) {
	case *api.TelemetryEvent_Container:
		cev := ev.Container
		if c.containerNames[cev.Name] {
			c.addContainerID(e.ContainerId)
			return true
		}

		if c.imageIds[cev.ImageId] {
			c.addContainerID(e.ContainerId)
			return true
		}

		if c.imageGlobs != nil && cev.ImageName != "" {
			for _, g := range c.imageGlobs {
				if g.Match(cev.ImageName) {
					c.addContainerID(e.ContainerId)
					return true
				}
			}
		}
	}

	return false
}
