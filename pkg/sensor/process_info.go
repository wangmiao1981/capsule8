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

// This file implements a process information cache that uses a sensor's
// system-global EventMonitor to keep it up-to-date. The cache also monitors
// for runc container starts to identify the containerID for a given PID
// namespace. Process information gathered by the cache may be retrieved via
// the LookupTask and LookupTaskAndLeader methods.
//
// glog levels used:
//   10 = cache operation level tracing for debugging

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/capsule8/capsule8/pkg/sys/proc"

	"github.com/golang/glog"

	"golang.org/x/sys/unix"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var processExecEventTypes = expression.FieldTypeMap{
	"filename": int32(api.ValueType_STRING),
}

var processForkEventTypes = expression.FieldTypeMap{
	"fork_child_pid": int32(api.ValueType_SINT32),
	"fork_child_id":  int32(api.ValueType_STRING),
}

var processExitEventTypes = expression.FieldTypeMap{
	"code":             int32(api.ValueType_SINT32),
	"exit_status":      int32(api.ValueType_UINT32),
	"exit_signal":      int32(api.ValueType_UINT32),
	"exit_core_dumped": int32(api.ValueType_BOOL),
}

const taskReuseThreshold = int64(10 * time.Millisecond)

const (
	commitCredsAddress = "commit_creds"
	commitCredsArgs    = "usage=+0(%di):u64 " +
		"uid=+4(%di):u32 gid=+8(%di):u32 " +
		"suid=+12(%di):u32 sgid=+16(%di):u32 " +
		"euid=+20(%di):u32 egid=+24(%di):u32 " +
		"fsuid=+28(%di):u32 fsgid=+32(%di):u32"

	execveArgCount = 6

	doExecveAddress         = "do_execve"
	doExecveatAddress       = "do_execveat"
	doExecveatCommonAddress = "do_execveat_common"
	sysExecveAddress        = "sys_execve"
	sysExecveatAddress      = "sys_execveat"

	doExitAddress = "do_exit"
	doExitArgs    = "code=%di:s64"

	doForkAddress   = "do_fork"
	doForkFetchargs = "clone_flags=%di:u64"
)

var (
	procFS *proc.FileSystem
	once   sync.Once
)

// Cred contains task credential information
type Cred struct {
	// UID is the real UID
	UID uint32
	// GID is the real GID
	GID uint32
	// EUID is the effective UID
	EUID uint32
	// EGID is the effective GID
	EGID uint32
	// SUID is the saved UID
	SUID uint32
	// SGID is the saved GID
	SGID uint32
	// FSUID is the UID for filesystem operations
	FSUID uint32
	// FSGID is the GID for filesystem operations
	FSGID uint32
}

var rootCredentials = Cred{}

func newCredentials(
	uid, euid, suid, fsuid uint32,
	gid, egid, sgid, fsgid uint32,
) *Cred {
	if uid == 0 && euid == 0 && suid == 0 && fsuid == 0 {
		if gid == 0 && egid == 0 && sgid == 0 && fsgid == 0 {
			return &rootCredentials
		}
	}

	return &Cred{
		UID:   uid,
		GID:   gid,
		EUID:  euid,
		EGID:  egid,
		SUID:  suid,
		SGID:  sgid,
		FSUID: fsuid,
		FSGID: fsgid,
	}
}

// Task represents a schedulable task. All Linux tasks are uniquely identified
// at a given time by their PID, but those PIDs may be reused after hitting the
// maximum PID value.
type Task struct {
	// PID is the kernel's internal process identifier, which is equivalent
	// to the TID in userspace.
	PID int

	// TGID is the kernel's internal thread group identifier, which is
	// equivalent to the PID in userspace. All threads within a process
	// have differing PIDs, but all share the same TGID. The thread group
	// leader process's PID will be the same as its TGID.
	TGID int

	// Command is the kernel's comm field, which is initialized to the
	// first 15 characters of the basename of the executable being run.
	// It is also set via pthread_setname_np(3) and prctl(2) PR_SET_NAME.
	// It is always NULL-terminated and no longer than 16 bytes (including
	// NUL byte).
	Command string

	// CommandLine is the command-line used when the process was exec'd via
	// execve(). It is composed of the first 6 elements of argv. It may
	// not be complete if argv contained more than 6 elements.
	CommandLine []string

	// Creds are the credentials (uid, gid) for the task. This is kept
	// up-to-date by recording changes observed via a kprobe on
	// commit_creds().
	Creds *Cred

	// ContainerID is the ID of the container to which the task belongs,
	// if any.
	ContainerID string

	// ContainerInfo is a pointer to the cached container information for
	// the container to which the task belongs, if any.
	ContainerInfo *ContainerInfo

	// StartTime is the time at which a task started.
	StartTime int64

	// ExitTime is the time at which a task exited.
	ExitTime int64

	// ProcessID is a unique ID for the task.
	ProcessID string

	// parent is an internal reference to the parent of this task, which
	// could be either the thread group leader or another process. Use
	// Parent() to get the parent of a container.
	parent *Task

	// pendingCloneFlags is used internally for tracking the flags passed
	// to the clone(2) system call.
	pendingCloneFlags uint64
}

var rootTask = Task{}

func newTask(pid int) *Task {
	return &Task{
		PID:               pid,
		pendingCloneFlags: ^uint64(0),
	}
}

var sensorPID = os.Getpid()

// IsSensor returns true if the task belongs to the sensor process.
func (t *Task) IsSensor() bool {
	return t.TGID == sensorPID
}

// Leader returns a reference to a task's leader task.
func (t *Task) Leader() *Task {
	if t.PID == t.TGID {
		return t
	}
	return t.Parent()
}

// Parent returns a reference to a task's parent task.
func (t *Task) Parent() *Task {
	if t.parent == nil {
		// t.parent may not be set yet if events arrive out of order.
		if t.TGID != 0 {
			glog.Fatalf("Internal error: t.PID == %d && t.TGID == %d && t.parent == nil", t.PID, t.TGID)
		}
		// We don't know anything about the parent, so return this task
		// as the parent. Don't store the reference, though.
		return t
	}
	return t.parent
}

// Update updates a task instance with new data. It returns true if any data
// was actually changed.
func (t *Task) Update(data map[string]interface{}, timestamp uint64) bool {
	dataChanged := false
	changedContainerInfo := false
	changedPID := false
	changedStartTime := false

	s := reflect.ValueOf(t).Elem()
	st := s.Type()
	for i := st.NumField() - 1; i >= 0; i-- {
		f := st.Field(i)
		if !unicode.IsUpper(rune(f.Name[0])) {
			continue
		}
		v, ok := data[f.Name]
		if !ok {
			continue
		}
		if !reflect.TypeOf(v).AssignableTo(f.Type) {
			glog.Fatalf("Cannot assign %v to %s %v",
				v, f.Name, f.Type)
		}

		// Assume field types that are not compareable always change
		// Examples of uncompareable types: []string (e.g. CommandLine)
		if !reflect.TypeOf(v).Comparable() ||
			s.Field(i).Interface() != v {
			dataChanged = true
			s.Field(i).Set(reflect.ValueOf(v))

			switch f.Name {
			case "PID", "TGID":
				changedPID = true
			case "StartTime":
				changedStartTime = true
			case "ContainerID":
				// Invalidate ContainerInfo if it hasn't
				// already been changed in this update.
				if !changedContainerInfo {
					t.ContainerInfo = nil
				}
			case "ContainerInfo":
				changedContainerInfo = true
			}
		}
	}

	if changedPID || changedStartTime {
		if !changedStartTime {
			if ps := procFS.Stat(t.TGID, t.PID); ps != nil {
				t.StartTime = int64(ps.StartTime())
			} else {
				t.StartTime = int64(timestamp)
			}
		}
		if t.StartTime > 0 {
			t.ProcessID = proc.DeriveUniqueID(t.PID,
				uint64(t.StartTime))
		} else {
			t.ProcessID = ""
		}
	}

	return dataChanged
}

type taskCache interface {
	LookupTask(int) *Task
}

type arrayTaskCache struct {
	entries []*Task
}

func newArrayTaskCache(size uint) *arrayTaskCache {
	return &arrayTaskCache{
		entries: make([]*Task, size),
	}
}

func (c *arrayTaskCache) LookupTask(pid int) *Task {
	if pid <= 0 || pid > len(c.entries) {
		glog.Fatalf("Invalid pid for lookup: %d", pid)
	}

	var t *Task
	for {
		var old *Task

		t = c.entries[pid-1]
		if t != nil {
			if t.ExitTime == 0 ||
				sys.CurrentMonotonicRaw()-t.ExitTime <
					taskReuseThreshold {
				break
			}
			old = t
		}
		t = newTask(pid)
		if atomic.CompareAndSwapPointer(
			(*unsafe.Pointer)(unsafe.Pointer(&c.entries[pid-1])),
			unsafe.Pointer(old),
			unsafe.Pointer(t)) {
			break
		}
	}
	glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	return t
}

type mapTaskCache struct {
	sync.Mutex
	entries map[int]*Task
}

func newMapTaskCache(size uint) *mapTaskCache {
	// The size here is likely to be quite large, so we don't really want
	// to size the map to it initially. On the other hand, we don't want
	// to let the map grow naturally using Go defaults, because we assume
	// that we will have a fairly large number of tasks.
	return &mapTaskCache{
		entries: make(map[int]*Task, size/4),
	}
}

func (c *mapTaskCache) LookupTask(pid int) *Task {
	if pid <= 0 {
		glog.Fatalf("Invalid pid for lookup: %d", pid)
	}

	c.Lock()
	t, ok := c.entries[pid]
	if !ok || (t.ExitTime != 0 &&
		sys.CurrentMonotonicRaw()-t.ExitTime >= taskReuseThreshold) {
		t = newTask(pid)
		c.entries[pid] = t
	}
	c.Unlock()
	glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	return t
}

// ProcessInfoCache is an object that caches process information. It is
// maintained automatically via an existing sensor object.
type ProcessInfoCache struct {
	cache taskCache

	sensor *Sensor

	// These are external event IDs registered with the sensor's event
	// monitor instance. The cache will enqueue these events as appropriate
	// as the cache is updated.
	ProcessExecEventID uint64 // api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC
	ProcessForkEventID uint64 // api.ProcessEventType_PROCESS_EVENT_TYPE_FORK
	ProcessExitEventID uint64 // api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT

	haveSchedProcessExecTracepoint bool

	scanningLock  sync.Mutex
	scanning      bool
	scanningQueue []scannerDeferredAction
}

type scannerDeferredAction func()

// NewProcessInfoCache creates a new process information cache object. An
// existing sensor object is required in order for the process info cache to
// able to install its probes to monitor the system to maintain the cache.
func NewProcessInfoCache(sensor *Sensor) ProcessInfoCache {
	once.Do(func() {
		procFS = sys.HostProcFS()
		if procFS == nil {
			glog.Fatal("Couldn't find a host procfs")
		}
	})

	cache := ProcessInfoCache{
		sensor:   sensor,
		scanning: true,
	}

	maxPid := proc.MaxPid()
	if maxPid > config.Sensor.ProcessInfoCacheSize {
		cache.cache = newMapTaskCache(maxPid)
	} else {
		cache.cache = newArrayTaskCache(maxPid)
	}

	var err error
	cache.ProcessExecEventID, err = sensor.Monitor.RegisterExternalEvent(
		"PROCESS_EXEC",
		cache.decodeProcessExecEvent,
		processExecEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ProcessForkEventID, err = sensor.Monitor.RegisterExternalEvent(
		"PROCESS_FORK",
		cache.decodeProcessForkEvent,
		processForkEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	cache.ProcessExitEventID, err = sensor.Monitor.RegisterExternalEvent(
		"PROCESS_EXIT",
		cache.decodeProcessExitEvent,
		processExitEventTypes,
	)
	if err != nil {
		glog.Fatalf("Failed to register external event: %s", err)
	}

	// Register with the sensor's global event monitor...
	eventName := "task/task_newtask"
	_, err = sensor.Monitor.RegisterTracepoint(eventName,
		cache.decodeNewTask,
		perf.WithEventEnabled())
	if err != nil {
		eventName = doForkAddress
		_, err = sensor.Monitor.RegisterKprobe(eventName, false,
			doForkFetchargs, cache.decodeDoFork,
			perf.WithEventEnabled())
		if err != nil {
			eventName = "_" + eventName
			_, err = sensor.Monitor.RegisterKprobe(eventName, false,
				doForkFetchargs, cache.decodeDoFork,
				perf.WithEventEnabled())
			if err != nil {
				glog.Fatalf("Couldn't register kprobe %s: %s",
					eventName, err)
			}
		}
		_, err = sensor.Monitor.RegisterKprobe(eventName, true,
			"", cache.decodeDoForkReturn,
			perf.WithEventEnabled())
		if err != nil {
			glog.Fatalf("Couldn't register kretprobe %s: %s",
				eventName, err)
		}

		eventName = "sched/sched_process_fork"
		_, err = sensor.Monitor.RegisterTracepoint(eventName,
			cache.decodeSchedProcessFork,
			perf.WithEventEnabled())
	}

	eventName = doExitAddress
	_, err = sensor.Monitor.RegisterKprobe(eventName, false,
		doExitArgs, cache.decodeDoExit,
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Couldn't register event %s: %s", eventName, err)
	}

	// Attach kprobe on commit_creds to capture task privileges
	_, err = sensor.Monitor.RegisterKprobe(commitCredsAddress, false,
		commitCredsArgs, cache.decodeCommitCreds,
		perf.WithEventEnabled())

	eventName = cgroupProcsWriteAddress
	_, err = sensor.Monitor.RegisterKprobe(eventName, false,
		cgroupProcsWriteArgs, cache.decodeCgroupProcsWrite,
		perf.WithEventEnabled())
	if err != nil {
		major, _, _ := sys.KernelVersion()
		if major >= 3 {
			// Attach a probe for task_rename involving the runc
			// init processes to trigger containerID lookups
			f := "oldcomm == exe || oldcomm == runc:[2:INIT]"
			eventName = "task/task_rename"
			_, err = sensor.Monitor.RegisterTracepoint(eventName,
				cache.decodeRuncTaskRename,
				perf.WithFilter(f),
				perf.WithEventEnabled())
			if err != nil {
				glog.Fatalf("Couldn't register event %s: %s",
					eventName, err)
			}
		}
	}

	eventName = "sched/sched_process_exec"
	_, err = sensor.Monitor.RegisterTracepoint(eventName,
		cache.decodeSchedProcessExec,
		perf.WithEventEnabled())
	if err == nil {
		cache.haveSchedProcessExecTracepoint = true
	}

	// Attach a probe to capture exec events in the kernel. Different
	// kernel versions require different probe attachments, so try to do
	// the best that we can here. Try for do_execveat_common() first, and
	// if that succeeds, it's the only one we need. Otherwise, we need a
	// bunch of others to try to hit everything. We may end up getting
	// duplicate events, which is ok.
	_, err = sensor.Monitor.RegisterKprobe(
		doExecveatCommonAddress, false,
		makeExecveFetchArgs("dx"), cache.decodeExecve,
		perf.WithEventEnabled())
	if err != nil {
		_, err = sensor.Monitor.RegisterKprobe(
			sysExecveAddress, false,
			makeExecveFetchArgs("si"), cache.decodeExecve,
			perf.WithEventEnabled())
		if err != nil {
			glog.Fatalf("Couldn't register event %s: %s",
				sysExecveAddress, err)
		}
		_, _ = sensor.Monitor.RegisterKprobe(
			doExecveAddress, false,
			makeExecveFetchArgs("si"), cache.decodeExecve,
			perf.WithEventEnabled())

		_, err = sensor.Monitor.RegisterKprobe(
			sysExecveatAddress, false,
			makeExecveFetchArgs("dx"), cache.decodeExecve,
			perf.WithEventEnabled())
		if err == nil {
			_, _ = sensor.Monitor.RegisterKprobe(
				doExecveatAddress, false,
				makeExecveFetchArgs("dx"), cache.decodeExecve,
				perf.WithEventEnabled())
		}
	}

	// Scan the proc filesystem to learn about all existing tasks.
	err = cache.scanProcFilesystem()
	if err != nil {
		glog.Fatal(err)
	}

	cache.scanningLock.Lock()
	for len(cache.scanningQueue) > 0 {
		queue := cache.scanningQueue
		cache.scanningQueue = nil
		cache.scanningLock.Unlock()
		for _, f := range queue {
			f()
		}
		cache.scanningLock.Lock()
	}
	cache.scanning = false
	cache.scanningLock.Unlock()

	return cache
}

func makeExecveFetchArgs(reg string) string {
	parts := make([]string, execveArgCount)
	for i := 0; i < execveArgCount; i++ {
		parts[i] = fmt.Sprintf("argv%d=+0(+%d(%%%s)):string", i, i*8, reg)
	}
	return strings.Join(parts, " ")
}

func (pc *ProcessInfoCache) cacheTaskFromProc(tgid, pid int) error {
	var s struct {
		Name string   `Name`
		PID  int      `Pid`
		PPID int      `PPid`
		TGID int      `Tgid`
		UID  []uint32 `Uid`
		GID  []uint32 `Gid`
	}
	err := procFS.ReadProcessStatus(tgid, pid, &s)
	if err != nil {
		return fmt.Errorf("Couldn't read pid %d status: %s",
			pid, err)
	}
	ps := procFS.Stat(tgid, pid)

	t := pc.cache.LookupTask(s.PID)
	t.TGID = s.TGID
	t.Command = s.Name
	t.Creds = newCredentials(s.UID[0], s.UID[1], s.UID[2], s.UID[3],
		s.GID[0], s.GID[1], s.GID[2], s.GID[3])
	if ps != nil {
		t.StartTime = int64(ps.StartTime())
	} else {
		t.StartTime = sys.CurrentMonotonicRaw()
	}
	if t.PID != t.TGID {
		t.parent = pc.cache.LookupTask(t.TGID)
	} else {
		if s.PPID == 0 && (t.PID == 1 || s.Name == "kthreadd") {
			t.parent = &rootTask
		} else {
			t.parent = pc.cache.LookupTask(s.PPID)
		}
		t.CommandLine = procFS.CommandLine(t.TGID)
		t.ContainerID, err = procFS.ContainerID(tgid)
		if err != nil {
			return fmt.Errorf("Couldn't get containerID for tgid %d: %s",
				pid, err)
		}
	}

	return nil
}

func (pc *ProcessInfoCache) scanProcFilesystem() error {
	d, err := os.Open(procFS.MountPoint)
	if err != nil {
		return fmt.Errorf("Cannot open %s: %s", procFS.MountPoint, err)
	}
	procNames, err := d.Readdirnames(0)
	if err != nil {
		return fmt.Errorf("Cannot read directory names from %s: %s",
			procFS.MountPoint, err)
	}
	d.Close()

	for _, procName := range procNames {
		i, err := strconv.ParseInt(procName, 10, 32)
		if err != nil {
			continue
		}
		tgid := int(i)

		err = pc.cacheTaskFromProc(tgid, tgid)
		if err != nil {
			// This is not fatal; the process may have gone away
			continue
		}

		taskPath := fmt.Sprintf("%s/%d/task", procFS.MountPoint, tgid)
		d, err = os.Open(taskPath)
		if err != nil {
			// This is not fatal; the process may have gone away
			continue
		}
		taskNames, err := d.Readdirnames(0)
		if err != nil {
			// This is not fatal; the process may have gone away
			continue
		}
		d.Close()

		for _, taskName := range taskNames {
			i, err = strconv.ParseInt(taskName, 10, 32)
			if err != nil {
				continue
			}
			pid := int(i)
			if tgid == pid {
				continue
			}

			// Ignore errors here; the process may have gone away
			_ = pc.cacheTaskFromProc(tgid, pid)
		}
	}

	return nil
}

// LookupTask finds the task information for the given PID.
func (pc *ProcessInfoCache) LookupTask(pid int) *Task {
	return pc.cache.LookupTask(pid)
}

// LookupTaskAndLeader finds the task information for both a given PID and the
// thread group leader.
func (pc *ProcessInfoCache) LookupTaskAndLeader(pid int) (*Task, *Task) {
	t := pc.cache.LookupTask(pid)
	return t, t.Leader()
}

// LookupTaskContainerInfo returns the container info for a task, possibly
// consulting the sensor's container cache and updating the task cached
// information.
func (pc *ProcessInfoCache) LookupTaskContainerInfo(t *Task) *ContainerInfo {
	if t.PID != t.TGID {
		t = t.Parent()
	}
	if i := t.ContainerInfo; i != nil {
		return t.ContainerInfo
	}

	if ID := t.ContainerID; len(ID) > 0 {
		if i := pc.sensor.ContainerCache.LookupContainer(ID, true); i != nil {
			t.ContainerInfo = i
			return i
		}
	}

	return nil
}

func (pc *ProcessInfoCache) maybeDeferAction(f func()) {
	if pc.scanning {
		pc.scanningLock.Lock()
		if pc.scanning {
			pc.scanningQueue = append(pc.scanningQueue, f)
			pc.scanningLock.Unlock()
			return
		}
		pc.scanningLock.Unlock()
	}

	f()
}

func (pc *ProcessInfoCache) newProcessEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
	eventType api.ProcessEventType,
) (*api.TelemetryEvent, error) {
	event := pc.sensor.NewEventFromSample(sample, data)
	if event == nil {
		return nil, nil
	}

	pev := &api.ProcessEvent{
		Type: eventType,
	}

	switch eventType {
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
		pev.ExecFilename = data["filename"].(string)
		pev.ExecCommandLine = data["exec_command_line"].([]string)
	case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
		pev.ForkChildPid = data["fork_child_pid"].(int32)
		pev.ForkChildId = data["fork_child_id"].(string)
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
		pev.ExitCode = data["code"].(int32)
		pev.ExitStatus = data["exit_status"].(uint32)
		pev.ExitSignal = data["exit_signal"].(uint32)
		pev.ExitCoreDumped = data["exit_core_dumped"].(bool)
	}

	event.Event = &api.TelemetryEvent_Process{
		Process: pev,
	}
	return event, nil
}

func (pc *ProcessInfoCache) decodeProcessExecEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return pc.newProcessEvent(sample, data,
		api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC)
}

func (pc *ProcessInfoCache) decodeProcessForkEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return pc.newProcessEvent(sample, data,
		api.ProcessEventType_PROCESS_EVENT_TYPE_FORK)
}

func (pc *ProcessInfoCache) decodeProcessExitEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	return pc.newProcessEvent(sample, data,
		api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT)
}

func sampleIDFromSample(sample *perf.SampleRecord) perf.SampleID {
	return perf.SampleID{
		Time: sample.Time,
		PID:  sample.Pid,
		TID:  sample.Tid,
		CPU:  sample.CPU,
	}
}

func (pc *ProcessInfoCache) handleSysClone(
	parentTask, parentLeader, childTask *Task,
	cloneFlags uint64,
	childComm string,
	sample *perf.SampleRecord,
) {
	changes := map[string]interface{}{
		"Command": childComm,
	}

	if (cloneFlags & CLONE_THREAD) != 0 {
		changes["TGID"] = parentTask.PID
	} else {
		// This is a new thread group leader, tgid is the new pid
		changes["TGID"] = childTask.PID
		changes["ContainerID"] = parentLeader.ContainerID
		changes["ContainerInfo"] = parentLeader.ContainerInfo
	}

	eventData := map[string]interface{}{
		"__task__":       parentTask,
		"fork_child_pid": int32(childTask.PID),
		"fork_child_id":  childTask.ProcessID,
	}

	childTask.parent = parentTask
	childTask.Update(changes, sample.Time)
	pc.sensor.Monitor.EnqueueExternalSample(
		pc.ProcessForkEventID,
		sampleIDFromSample(sample),
		eventData)
}

func (pc *ProcessInfoCache) decodeNewTask(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	parentPid := int(data["common_pid"].(int32))
	childPid := int(data["pid"].(int32))
	cloneFlags := data["clone_flags"].(uint64)
	childComm := commToString(data["comm"].([]interface{}))

	pc.maybeDeferAction(func() {
		parentTask, parentLeader := pc.LookupTaskAndLeader(parentPid)
		childTask := pc.LookupTask(childPid)

		pc.handleSysClone(parentTask, parentLeader, childTask,
			cloneFlags, childComm, sample)
	})

	return nil, nil
}

// decodeDoExit marks a task as having exited. The time of the exit
// is noted so that the task can be safely reused later. Don't delete it from
// the cache, because out-of-order events could cause it to be recreated and
// then when the pid is reused by the kernel later, it'll contain stale data.
func (pc *ProcessInfoCache) decodeDoExit(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))
	exitCode := data["code"].(int64)

	changes := map[string]interface{}{
		"ExitTime": sys.CurrentMonotonicRaw(),
	}

	ws := unix.WaitStatus(exitCode)
	eventData := map[string]interface{}{
		"code": int32(exitCode),
	}

	if ws.Exited() {
		eventData["exit_status"] = uint32(ws.ExitStatus())
		eventData["exit_signal"] = uint32(0)
		eventData["exit_core_dumped"] = false
	} else {
		eventData["exit_status"] = uint32(0)
		eventData["exit_signal"] = uint32(ws.Signal())
		eventData["exit_core_dumped"] = ws.CoreDump()
	}

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)
		t.Update(changes, sample.Time)
		eventData["__task__"] = t
		pc.sensor.Monitor.EnqueueExternalSample(
			pc.ProcessExitEventID,
			sampleIDFromSample(sample),
			eventData)
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeCommitCreds(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))

	if usage := data["usage"].(uint64); usage == 0 {
		glog.Fatal("Received commit_creds with zero usage")
	}

	changes := map[string]interface{}{
		"Creds": &Cred{
			UID:   data["uid"].(uint32),
			GID:   data["gid"].(uint32),
			EUID:  data["euid"].(uint32),
			EGID:  data["egid"].(uint32),
			SUID:  data["suid"].(uint32),
			SGID:  data["sgid"].(uint32),
			FSUID: data["fsuid"].(uint32),
			FSGID: data["fsgid"].(uint32),
		},
	}

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)
		t.Update(changes, sample.Time)
	})

	return nil, nil
}

// decodeRuncTaskRename is called when runc execs and obtains the containerID
// from /procfs and caches it.
func (pc *ProcessInfoCache) decodeRuncTaskRename(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["pid"].(int32))

	pc.maybeDeferAction(func() {
		glog.V(10).Infof("decodeRuncTaskRename: pid = %d", pid)

		// FIXME There is a race condition here that can result in not
		// getting the containerID at this time. Docker apparently
		// renames the task before adjusting cgroups. A better way of
		// determining the containerID for a process needs to be found.
		// This is why the check for err == nil AND containerID != ""
		// is necessary, rather than just err == nil.

		_, leader := pc.LookupTaskAndLeader(pid)
		containerID, err := procFS.ContainerID(leader.PID)
		if err == nil && containerID != "" && leader.ContainerID != containerID {
			glog.V(10).Infof("containerID(%d) = %s", leader.PID, containerID)
			changes := map[string]interface{}{
				"ContainerID": containerID,
			}
			leader.Update(changes, sample.Time)
		}
	})

	return nil, nil
}

// decodeDoExecve decodes sys_execve() and sys_execveat() events to obtain the
// command-line for the process.
func (pc *ProcessInfoCache) decodeExecve(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))
	commandLine := make([]string, 0, execveArgCount)
	for i := 0; i < execveArgCount; i++ {
		s := data[fmt.Sprintf("argv%d", i)].(string)
		if len(s) == 0 {
			break
		}
		commandLine = append(commandLine, s)
	}

	changes := map[string]interface{}{
		"CommandLine": commandLine,
	}

	var eventData map[string]interface{}
	if !pc.haveSchedProcessExecTracepoint {
		eventData = map[string]interface{}{
			"filename":          commandLine[0],
			"exec_command_line": commandLine,
		}
	}

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)
		t.Update(changes, sample.Time)
		if !pc.haveSchedProcessExecTracepoint {
			eventData["__task__"] = t
			pc.sensor.Monitor.EnqueueExternalSample(
				pc.ProcessExecEventID,
				sampleIDFromSample(sample),
				eventData)
		}
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeSchedProcessExec(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))
	t := pc.LookupTask(pid)

	commandLine := t.CommandLine
	if commandLine == nil {
		commandLine = procFS.CommandLine(t.TGID)
	}

	eventData := map[string]interface{}{
		"__task__":          t,
		"filename":          data["filename"].(string),
		"exec_command_line": commandLine,
	}

	pc.maybeDeferAction(func() {
		pc.sensor.Monitor.EnqueueExternalSample(
			pc.ProcessExecEventID,
			sampleIDFromSample(sample),
			eventData)
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeDoFork(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))
	cloneFlags := data["clone_flags"].(uint64)

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)

		if t.pendingCloneFlags != ^uint64(0) {
			glog.V(2).Infof("decodeDoFork: stale clone flags %x for pid %d\n",
				t.pendingCloneFlags, pid)
		}

		t.pendingCloneFlags = cloneFlags
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeDoForkReturn(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["common_pid"].(int32))

	pc.maybeDeferAction(func() {
		t := pc.LookupTask(pid)

		if t.pendingCloneFlags == ^uint64(0) {
			glog.V(2).Infof("decodeDoFork: no pending clone flags for pid %d\n",
				pid)
		}

		t.pendingCloneFlags = ^uint64(0)
	})

	return nil, nil
}

func (pc *ProcessInfoCache) decodeSchedProcessFork(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	parentPid := int(data["parent_pid"].(int32))
	childPid := int(data["child_pid"].(int32))
	childComm := commToString(data["child_comm"].([]interface{}))

	pc.maybeDeferAction(func() {
		parentTask, parentLeader := pc.LookupTaskAndLeader(parentPid)
		if parentTask.pendingCloneFlags == ^uint64(0) {
			glog.Fatalf("decodeSchedProcessFork: no pending clone flags for pid %d\n",
				parentPid)
		}

		childTask := pc.LookupTask(childPid)

		pc.handleSysClone(parentTask, parentLeader, childTask,
			parentTask.pendingCloneFlags, childComm, sample)
	})

	return nil, nil
}

func commToString(comm []interface{}) string {
	s := make([]byte, len(comm))
	for i, c := range comm {
		switch c := c.(type) {
		case int8:
			s[i] = byte(c)
		case uint8:
			// Kernel 2.6.32 erroneously reports unsigned
			s[i] = byte(c)
		}
		if s[i] == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

func rewriteProcessEventFilter(pef *api.ProcessEventFilter) {
	switch pef.Type {
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
		if pef.ExecFilename != nil {
			newExpr := expression.Equal(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilename.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilename = nil
			pef.ExecFilenamePattern = nil
		} else if pef.ExecFilenamePattern != nil {
			newExpr := expression.Like(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilenamePattern.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilenamePattern = nil
		}
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
		if pef.ExitCode != nil {
			newExpr := expression.Equal(
				expression.Identifier("code"),
				expression.Value(pef.ExitCode.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExitCode = nil
		}
	}
}

func registerProcessEvents(
	sensor *Sensor,
	subscr *subscription,
	events []*api.ProcessEventFilter,
) {
	var (
		filters       [4]*api.Expression
		subscriptions [4]*eventSink
		wildcards     [4]bool
	)

	for _, pef := range events {
		// Translate deprecated fields into an expression
		rewriteProcessEventFilter(pef)

		t := pef.Type
		if t < 1 || t > 3 {
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("ProcessEventType %d is invalid", t))
			continue
		}

		if subscriptions[t] == nil {
			var eventID uint64
			switch t {
			case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
				eventID = sensor.ProcessCache.ProcessExecEventID
			case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
				eventID = sensor.ProcessCache.ProcessForkEventID
			case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
				eventID = sensor.ProcessCache.ProcessExitEventID
			}
			subscriptions[t] = subscr.addEventSink(eventID)
		}
		if pef.FilterExpression == nil {
			wildcards[t] = true
			filters[t] = nil
		} else if !wildcards[t] {
			filters[t] = expression.LogicalOr(
				filters[t],
				pef.FilterExpression)
		}
	}

	for t, s := range subscriptions {
		if filters[t] == nil {
			// No filter, no problem
			continue
		}

		expr, err := expression.NewExpression(filters[t])
		if err != nil {
			// Bad filter. Remove subscription
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("Invalid process filter expression: %v", err))
			subscr.removeEventSink(s)
			continue
		}

		switch api.ProcessEventType(t) {
		case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
			err = expr.Validate(processExecEventTypes)
		case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
			err = expr.Validate(processForkEventTypes)
		case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
			err = expr.Validate(processExitEventTypes)
		}
		if err != nil {
			// Bad filter. Remove subscription
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("Invalid process filter expression: %v", err))
			subscr.removeEventSink(s)
			continue
		}

		s.filter = expr
	}
}
