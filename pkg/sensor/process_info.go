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
	"unicode"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/capsule8/capsule8/pkg/sys/proc"
	"github.com/golang/glog"
)

const (
	commitCredsAddress = "commit_creds"
	commitCredsArgs    = "usage=+0(%di):u64 " +
		"uid=+8(%di):u32 gid=+12(%di):u32 " +
		"suid=+16(%di):u32 sgid=+20(%di):u32 " +
		"euid=+24(%di):u32 egid=+28(%di):u32 " +
		"fsuid=+32(%di):u32 fsgid=+36(%di):u32"

	execveArgCount = 6

	doExecveAddress         = "do_execve"
	doExecveatAddress       = "do_execveat"
	doExecveatCommonAddress = "do_execveat_common"
	sysExecveAddress        = "sys_execve"
	sysExecveatAddress      = "sys_execveat"
)

var (
	procFS *proc.FileSystem
	once   sync.Once
)

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

	// PPID is the parent PID of the originating parent process vs. current
	// parent in case the parent terminates and the child is reparented
	// (usually to init).
	PPID int

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

	// processID is a cached unique ID for the process.
	processID string
}

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

// IsValid returns true if the task instance is valid. A valid task instance
// has both PID and TGID fields >= 0.
func (t *Task) IsValid() bool {
	return t.PID > 0 && t.TGID > 0
}

// Invalidate invalidates a task instance.
func (t *Task) Invalidate() {
	t.PID = 0
	t.TGID = 0

	// Clear references for GC
	t.Command = ""
	t.CommandLine = nil
	t.ContainerID = ""
	t.ContainerInfo = nil
	t.Creds = nil
	t.processID = ""
}

// ProcessID returns the unique ID for a task. Normally this is used on the
// thread group leader for a process. The process ID is identical whether it
// is derived inside or outside a container.
func (t *Task) ProcessID() string {
	if t.processID == "" {
		t.processID = proc.DeriveUniqueID(t.PID, t.PPID)
	}
	return t.processID
}

// Update updates a task instance with new data. It returns true if any data
// was actually changed.
func (t *Task) Update(data map[string]interface{}) bool {
	dataChanged := false
	changedContainerInfo := false

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
			glog.Fatalf("Cannot assign %v to %s %",
				v, f.Name, f.Type)
		}

		// Assume field types that are not compareable always change
		// Examples of uncompareable types: []string (e.g. CommandLine)
		if !reflect.TypeOf(v).Comparable() ||
			s.Field(i).Interface() != v {
			dataChanged = true
			s.Field(i).Set(reflect.ValueOf(v))

			switch f.Name {
			case "PID", "PPID":
				// The cached processID depends on PID and PPID.
				// If either changes, invalidate the cached
				// value.
				t.processID = ""
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

	return dataChanged
}

type taskCache interface {
	LookupTask(int) (*Task, bool)
	LookupTaskAndLeader(int) (*Task, *Task, bool)
	InsertTask(int, *Task)
	DeleteTask(int)
}

type arrayTaskCache struct {
	entries []Task
}

func newArrayTaskCache(size uint) *arrayTaskCache {
	return &arrayTaskCache{
		entries: make([]Task, size),
	}
}

func (c *arrayTaskCache) LookupTask(pid int) (*Task, bool) {
	t := &c.entries[pid]
	if !t.IsValid() {
		glog.V(10).Infof("LookupTask(%d) -> nil", pid)
		return nil, false
	}
	glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	return t, true
}

func (c *arrayTaskCache) LookupTaskAndLeader(pid int) (*Task, *Task, bool) {
	t, ok := c.LookupTask(pid)
	if ok {
		if pid != t.TGID {
			leader, ok := c.LookupTask(t.TGID)
			return t, leader, ok
		}
		return t, t, true
	}
	return nil, nil, false
}

func (c *arrayTaskCache) InsertTask(pid int, t *Task) {
	glog.V(10).Infof("InsertTask(%d, %+v)", pid, t)
	if pid <= 0 || !t.IsValid() {
		glog.Fatalf("Invalid task for pid %d: %+v", pid, t)
	}
	c.entries[pid] = *t
}

func (c *arrayTaskCache) DeleteTask(pid int) {
	glog.V(10).Infof("DeleteTask(%d)", pid)
	c.entries[pid].Invalidate()
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

func (c *mapTaskCache) lookupTaskUnlocked(pid int) (*Task, bool) {
	t, ok := c.entries[pid]
	if !ok {
		glog.V(10).Infof("LookupTask(%d) -> nil", pid)
		return nil, false
	}
	if !t.IsValid() {
		glog.Fatalf("Found invalid task in cache for pid %d: %+v",
			pid, t)
	}

	glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	return t, true
}

func (c *mapTaskCache) LookupTask(pid int) (*Task, bool) {
	c.Lock()
	t, ok := c.lookupTaskUnlocked(pid)
	c.Unlock()

	return t, ok
}

func (c *mapTaskCache) LookupTaskAndLeader(pid int) (*Task, *Task, bool) {
	c.Lock()
	t, ok := c.lookupTaskUnlocked(pid)
	if ok {
		if pid != t.TGID {
			leader, ok := c.lookupTaskUnlocked(t.TGID)
			return t, leader, ok
		}
		c.Unlock()
		return t, t, true
	}
	c.Unlock()
	return nil, nil, false
}

func (c *mapTaskCache) InsertTask(pid int, t *Task) {
	glog.V(10).Infof("InsertTask(%d, %+v)", pid, t)
	if pid <= 0 || !t.IsValid() {
		glog.Fatalf("Invalid task for pid %d: %+v", pid, t)
	}

	taskCopy := *t

	c.Lock()
	c.entries[pid] = &taskCopy
	c.Unlock()
}

func (c *mapTaskCache) DeleteTask(pid int) {
	glog.V(10).Infof("DeleteTask(%d)", pid)

	c.Lock()
	delete(c.entries, pid)
	c.Unlock()
}

// ProcessInfoCache is an object that caches process information. It is
// maintained automatically via an existing sensor object.
type ProcessInfoCache struct {
	cache taskCache

	sensor *Sensor

	scanningLock  sync.Mutex
	scanning      bool
	scanningQueue []scannerDeferredAction
}

type scannerDeferredAction func()

// newProcessInfoCache creates a new process information cache object. An
// existing sensor object is required in order for the process info cache to
// able to install its probes to monitor the system to maintain the cache.
func newProcessInfoCache(sensor *Sensor) ProcessInfoCache {
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

	// Register with the sensor's global event monitor...
	eventName := "task/task_newtask"
	_, err := sensor.monitor.RegisterTracepoint(eventName,
		cache.decodeNewTask,
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Couldn't register event %s: %s", eventName, err)
	}

	// Attach kprobe on commit_creds to capture task privileges
	_, err = sensor.monitor.RegisterKprobe(commitCredsAddress, false,
		commitCredsArgs, cache.decodeCommitCreds,
		perf.WithEventEnabled())

	// Attach a probe for task_rename involving the runc
	// init processes to trigger containerID lookups
	f := "oldcomm == exe || oldcomm == runc:[2:INIT]"
	eventName = "task/task_rename"
	_, err = sensor.monitor.RegisterTracepoint(eventName,
		cache.decodeRuncTaskRename,
		perf.WithFilter(f),
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Couldn't register event %s: %s", eventName, err)
	}

	// Attach a probe to capture exec events in the kernel. Different
	// kernel versions require different probe attachments, so try to do
	// the best that we can here. Try for do_execveat_common() first, and
	// if that succeeds, it's the only one we need. Otherwise, we need a
	// bunch of others to try to hit everything. We may end up getting
	// duplicate events, which is ok.
	_, err = sensor.monitor.RegisterKprobe(
		doExecveatCommonAddress, false,
		makeExecveFetchArgs("dx"), cache.decodeExecve,
		perf.WithEventEnabled())
	if err != nil {
		_, err = sensor.monitor.RegisterKprobe(
			sysExecveAddress, false,
			makeExecveFetchArgs("si"), cache.decodeExecve,
			perf.WithEventEnabled())
		if err != nil {
			glog.Fatalf("Couldn't register event %s: %s",
				sysExecveAddress, err)
		}
		_, _ = sensor.monitor.RegisterKprobe(
			doExecveAddress, false,
			makeExecveFetchArgs("si"), cache.decodeExecve,
			perf.WithEventEnabled())

		_, err = sensor.monitor.RegisterKprobe(
			sysExecveatAddress, false,
			makeExecveFetchArgs("dx"), cache.decodeExecve,
			perf.WithEventEnabled())
		if err == nil {
			_, _ = sensor.monitor.RegisterKprobe(
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

	containerID, err := procFS.ContainerID(tgid)
	if err != nil {
		return fmt.Errorf("Couldn't get containerID for tgid %d: %s",
			pid, err)
	}

	t := Task{
		PID:         s.PID,
		TGID:        s.TGID,
		PPID:        s.PPID,
		Command:     s.Name,
		CommandLine: procFS.CommandLine(tgid),
		ContainerID: containerID,
		Creds: &Cred{
			UID:   s.UID[0],
			EUID:  s.UID[1],
			SUID:  s.UID[2],
			FSUID: s.UID[3],
			GID:   s.GID[0],
			EGID:  s.GID[1],
			SGID:  s.GID[2],
			FSGID: s.GID[3],
		},
	}

	pc.cache.InsertTask(t.PID, &t)
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
			return err
		}

		taskPath := fmt.Sprintf("%s/%d/task", procFS.MountPoint, tgid)
		d, err = os.Open(taskPath)
		if err != nil {
			return fmt.Errorf("Cannot open %s: %s", taskPath, err)
		}
		taskNames, err := d.Readdirnames(0)
		if err != nil {
			return fmt.Errorf("Cannot read tasks from %s: %s",
				taskPath, err)
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

			err = pc.cacheTaskFromProc(tgid, pid)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// LookupTask finds the task information for the given PID.
func (pc *ProcessInfoCache) LookupTask(pid int) (*Task, bool) {
	return pc.cache.LookupTask(pid)
}

// LookupTaskAndLeader finds the task information for both a given PID and the
// thread group leader.
func (pc *ProcessInfoCache) LookupTaskAndLeader(pid int) (*Task, *Task, bool) {
	return pc.cache.LookupTaskAndLeader(pid)
}

// LookupTaskContainerInfo returns the container info for a task, possibly
// consulting the sensor's container cache and updating the task cached
// information.
func (pc *ProcessInfoCache) LookupTaskContainerInfo(t *Task) *ContainerInfo {
	if i := t.ContainerInfo; i != nil {
		return t.ContainerInfo
	}

	if ID := t.ContainerID; len(ID) > 0 {
		if i := pc.sensor.containerCache.lookupContainer(ID, true); i != nil {
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

//
// Decodes each task/task_newtask tracepoint event into a processCacheEntry
//
func (pc *ProcessInfoCache) decodeNewTask(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	parentPid := int(data["common_pid"].(int32))
	childPid := int(data["pid"].(int32))
	cloneFlags := data["clone_flags"].(uint64)
	childComm := commToString(data["comm"].([]interface{}))

	var (
		commandLine   []string
		containerID   string
		containerInfo *ContainerInfo
	)

	parentTask, ok := pc.LookupTask(parentPid)
	if ok {
		commandLine = parentTask.CommandLine
		containerID = parentTask.ContainerID
		containerInfo = parentTask.ContainerInfo
	}

	childTask := Task{
		PID:           childPid,
		PPID:          parentPid,
		Command:       childComm,
		CommandLine:   commandLine,
		ContainerID:   containerID,
		ContainerInfo: containerInfo,
	}

	const cloneThread = 0x10000 // CLONE_THREAD from the kernel
	if cloneFlags&cloneThread != 0 {
		childTask.TGID = parentPid
	} else {
		// This is a new thread group leader, tgid is the new pid
		childTask.TGID = childPid
	}

	pc.maybeDeferAction(func() {
		pc.cache.InsertTask(childPid, &childTask)
	})

	return nil, nil
}

//
// Decodes each commit_creds dynamic tracepoint event and updates cache
//
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
		if t, ok := pc.LookupTask(pid); ok {
			t.Update(changes)
		}
	})

	return nil, nil
}

//
// decodeRuncTaskRename is called when runc exec's and obtains the containerID
// from /procfs and caches it.
//
func (pc *ProcessInfoCache) decodeRuncTaskRename(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	pid := int(data["pid"].(int32))

	pc.maybeDeferAction(func() {
		glog.V(10).Infof("decodeRuncTaskRename: pid = %d", pid)

		t, ok := pc.LookupTask(pid)
		if !ok {
			return
		}

		if len(t.ContainerID) == 0 {
			containerID, err := procFS.ContainerID(pid)
			glog.V(10).Infof("containerID(%d) = %s", pid, containerID)
			if err == nil && len(containerID) > 0 {
				changes := map[string]interface{}{
					"ContainerID": containerID,
				}
				t.Update(changes)
			}
		} else if parent, parentok := pc.LookupTask(t.PPID); parentok {
			if len(parent.ContainerID) == 0 {
				containerID, err := procFS.ContainerID(parent.PID)
				glog.V(10).Infof("containerID(%d) = %s", pid, containerID)
				if err == nil && len(containerID) > 0 {
					changes := map[string]interface{}{
						"ContainerID": containerID,
					}
					parent.Update(changes)
				}

			}
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
	pc.maybeDeferAction(func() {
		if t, ok := pc.LookupTask(pid); ok {
			t.Update(changes)
		}
	})

	return nil, nil
}

func commToString(comm []interface{}) string {
	s := make([]byte, len(comm))
	for i, c := range comm {
		s[i] = byte(c.(int8))
		if s[i] == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}
