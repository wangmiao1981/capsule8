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

//
// This file implements a process information cache that uses a sensor's
// system-global EventMonitor to keep it up-to-date. The cache also monitors
// for runc container starts to identify the containerID for a given PID
// namespace. Process information gathered by the cache may be retrieved via
// the ProcessID and ProcessContainerID methods.
//
// glog levels used:
//   10 = cache operation level tracing for debugging
//

import (
	"fmt"
	"strings"
	"sync"

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

type taskCache interface {
	LookupTask(int, *task) bool
	LookupLeader(int) (task, bool)
	InsertTask(int, task)
	SetTaskContainerID(int, string)
	SetTaskContainerInfo(int, *ContainerInfo)
	SetTaskCredentials(int, Cred)
	SetTaskCommandLine(int, []string)
}

type arrayTaskCache struct {
	entries []task
}

func newArrayTaskCache(size uint) *arrayTaskCache {
	return &arrayTaskCache{
		entries: make([]task, size),
	}
}

func (c *arrayTaskCache) LookupTask(pid int, t *task) bool {
	*t = c.entries[pid]
	ok := t.tgid != 0

	if ok {
		glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	} else {
		glog.V(10).Infof("LookupTask(%d) -> nil", pid)
	}

	return ok
}

func (c *arrayTaskCache) LookupLeader(pid int) (task, bool) {
	var t task

	for p := pid; c.LookupTask(p, &t) && t.pid != t.tgid; p = t.ppid {
		// Do nothing
	}

	return t, t.pid == t.tgid
}

func (c *arrayTaskCache) InsertTask(pid int, t task) {
	glog.V(10).Infof("InsertTask(%d, %+v)", pid, t)
	c.entries[pid] = t
}

func (c *arrayTaskCache) SetTaskContainerID(pid int, cID string) {
	glog.V(10).Infof("SetTaskContainerID(%d) = %s", pid, cID)
	if c.entries[pid].containerID != cID {
		c.entries[pid].containerID = cID
		c.entries[pid].containerInfo = nil
	}
}

func (c *arrayTaskCache) SetTaskContainerInfo(pid int, info *ContainerInfo) {
	glog.V(10).Infof("SetTaskContainerInfo(ID(%d) = %+v", pid, info)
	if c.entries[pid].containerInfo != info {
		c.entries[pid].containerID = info.ID
		c.entries[pid].containerInfo = info
	}
}

func (c *arrayTaskCache) SetTaskCredentials(pid int, creds Cred) {
	glog.V(10).Infof("SetTaskCredentials(%d) = %+v", pid, creds)

	c.entries[pid].creds = creds
}

func (c *arrayTaskCache) SetTaskCommandLine(pid int, commandLine []string) {
	glog.V(10).Infof("SetTaskCommandLine(%d) = %s", pid, commandLine)
	c.entries[pid].commandLine = commandLine
}

type mapTaskCache struct {
	sync.Mutex
	entries map[int]task
}

func newMapTaskCache() *mapTaskCache {
	return &mapTaskCache{
		entries: make(map[int]task),
	}
}

func (c *mapTaskCache) lookupTaskUnlocked(pid int, t *task) (ok bool) {
	*t, ok = c.entries[pid]
	ok = ok && t.tgid != 0

	if ok {
		glog.V(10).Infof("LookupTask(%d) -> %+v", pid, t)
	} else {
		glog.V(10).Infof("LookupTask(%d) -> nil", pid)
	}

	return ok
}

func (c *mapTaskCache) LookupTask(pid int, t *task) bool {
	c.Lock()
	defer c.Unlock()
	return c.lookupTaskUnlocked(pid, t)
}

func (c *mapTaskCache) LookupLeader(pid int) (task, bool) {
	c.Lock()
	defer c.Unlock()

	var t task

	for p := pid; c.lookupTaskUnlocked(p, &t) && t.pid != t.tgid; p = t.ppid {
		// Do nothing
	}

	return t, t.pid == t.tgid
}

func (c *mapTaskCache) InsertTask(pid int, t task) {
	glog.V(10).Infof("InsertTask(%d, %+v)", pid, t)

	c.Lock()
	defer c.Unlock()

	c.entries[pid] = t
}

func (c *mapTaskCache) SetTaskContainerID(pid int, cID string) {
	glog.V(10).Infof("SetTaskContainerID(%d) = %s", pid, cID)

	c.Lock()
	defer c.Unlock()
	if t, ok := c.entries[pid]; ok && t.containerID != cID {
		t.containerID = cID
		t.containerInfo = nil
		c.entries[pid] = t
	}
}

func (c *mapTaskCache) SetTaskContainerInfo(pid int, info *ContainerInfo) {
	glog.V(10).Infof("SetTaskContainerInfo(%d) = %+v", pid, info)

	c.Lock()
	defer c.Unlock()
	if t, ok := c.entries[pid]; ok && t.containerInfo != info {
		t.containerID = info.ID
		t.containerInfo = info
		c.entries[pid] = t
	}
}

func (c *mapTaskCache) SetTaskCredentials(pid int, creds Cred) {
	glog.V(10).Infof("SetTaskCredentials(%d) = %+v", pid, creds)

	c.Lock()
	defer c.Unlock()
	t, ok := c.entries[pid]
	if ok {
		t.creds = creds
		c.entries[pid] = t
	}
}

func (c *mapTaskCache) SetTaskCommandLine(pid int, commandLine []string) {
	glog.V(10).Infof("SetTaskCommandLine(%d) = %s", pid, commandLine)

	c.Lock()
	defer c.Unlock()
	t, ok := c.entries[pid]
	if ok {
		t.commandLine = commandLine
		c.entries[pid] = t
	}
}

// ProcessInfoCache is an object that caches process information. It is
// maintained automatically via an existing sensor object.
type ProcessInfoCache struct {
	sensor *Sensor
	cache  taskCache
}

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
		sensor: sensor,
	}

	maxPid := proc.MaxPid()
	if maxPid > config.Sensor.ProcessInfoCacheSize {
		cache.cache = newMapTaskCache()
	} else {
		cache.cache = newArrayTaskCache(maxPid)
	}

	// Register with the sensor's global event monitor...
	eventName := "task/task_newtask"
	_, err := sensor.monitor.RegisterTracepoint(eventName,
		cache.decodeNewTask)
	if err != nil {
		glog.Fatalf("Couldn't register event %s: %s", eventName, err)
	}

	// Attach kprobe on commit_creds to capture task privileges
	_, err = sensor.monitor.RegisterKprobe(commitCredsAddress, false,
		commitCredsArgs, cache.decodeCommitCreds)

	// Attach a probe for task_rename involving the runc
	// init processes to trigger containerID lookups
	f := "oldcomm == exe || oldcomm == runc:[2:INIT]"
	eventName = "task/task_rename"
	_, err = sensor.monitor.RegisterTracepoint(eventName,
		cache.decodeRuncTaskRename, perf.WithFilter(f))
	if err != nil {
		glog.Fatalf("Couldn't register event %s: %s", eventName, err)
	}

	// Attach a probe to capture exec events in the kernel. Different
	// kernel versions require different probe attachments, so try to do
	// the best that we can here. Try for do_execveat_common() first, and
	// if that succeeds, it's the only one we need. Otherwise, we need a
	// bunch of others to try to hit everything. We may end up getting
	// duplicate events, which is ok.
	_, err = sensor.monitor.RegisterKprobe(doExecveatCommonAddress, false,
		makeExecveFetchArgs("dx"), cache.decodeExecve)
	if err != nil {
		_, err = sensor.monitor.RegisterKprobe(sysExecveAddress, false,
			makeExecveFetchArgs("si"), cache.decodeExecve)
		if err != nil {
			glog.Fatalf("Couldn't register event %s: %s",
				sysExecveAddress, err)
		}
		_, _ = sensor.monitor.RegisterKprobe(doExecveAddress, false,
			makeExecveFetchArgs("si"), cache.decodeExecve)

		_, err = sensor.monitor.RegisterKprobe(sysExecveatAddress, false,
			makeExecveFetchArgs("dx"), cache.decodeExecve)
		if err == nil {
			_, _ = sensor.monitor.RegisterKprobe(doExecveatAddress, false,
				makeExecveFetchArgs("dx"), cache.decodeExecve)
		}
	}

	return cache
}

func makeExecveFetchArgs(reg string) string {
	parts := make([]string, execveArgCount)
	for i := 0; i < execveArgCount; i++ {
		parts[i] = fmt.Sprintf("argv%d=+0(+%d(%%%s)):string", i, i*8, reg)
	}
	return strings.Join(parts, " ")
}

// lookupLeader finds the task info for the thread group leader of the given pid
func (pc *ProcessInfoCache) lookupLeader(pid int) (task, bool) {
	return pc.cache.LookupLeader(pid)
}

// ProcessID returns the unique ID for the thread group of the process
// indicated by the given PID. This process ID is identical whether it
// is derived inside or outside a container.
func (pc *ProcessInfoCache) ProcessID(pid int) (string, bool) {
	leader, ok := pc.lookupLeader(pid)
	if ok {
		return proc.DeriveUniqueID(leader.pid, leader.ppid), true
	}

	return "", false
}

// ProcessContainerID returns the container ID that the process
// indicated by the given host PID.
func (pc *ProcessInfoCache) ProcessContainerID(pid int) (string, bool) {
	t, ok := pc.cache.LookupLeader(pid)
	if ok && len(t.containerID) > 0 {
		return t.containerID, true
	}
	return "", false
}

// ProcessContainerInfo returns the container info for a process
func (pc *ProcessInfoCache) ProcessContainerInfo(pid int) (*ContainerInfo, bool) {
	t, ok := pc.cache.LookupLeader(pid)
	if ok {
		if t.containerInfo != nil {
			return t.containerInfo, true
		}
		if len(t.containerID) > 0 {
			cc := pc.sensor.containerCache
			info := cc.lookupContainer(t.containerID, true)
			if info != nil {
				pc.cache.SetTaskContainerInfo(t.pid, info)
				return info, true
			}
		}
	}

	return nil, false
}

// ProcessCommandLine returns the command-line for a process. The command-line
// is constructed from argv passed to execve(), but is limited to a fixed number
// of elements of argv; therefore, it may not be complete.
func (pc *ProcessInfoCache) ProcessCommandLine(pid int) ([]string, bool) {
	var t task
	ok := pc.cache.LookupTask(pid, &t)
	return t.commandLine, ok
}

// ProcessCredentials returns the uid and gid for a process.
func (pc *ProcessInfoCache) ProcessCredentials(pid int, c *Cred) bool {
	var t task
	ok := pc.cache.LookupTask(pid, &t)
	*c = t.creds
	return ok && t.creds.Initialized
}

//
// task represents a schedulable task. All Linux tasks are uniquely
// identified at a given time by their PID, but those PIDs may be
// reused after hitting the maximum PID value.
//
type task struct {
	// All Linux schedulable tasks are identified by a PID. This includes
	// both processes and threads.
	pid int

	// Thread groups all have a leader, identified by its PID. The
	// thread group leader has tgid == pid.
	tgid int

	// This ppid is of the originating parent process vs. current
	// parent in case the parent terminates and the child is
	// reparented (usually to init).
	ppid int

	// Flags passed to clone(2) when this process was created.
	cloneFlags uint64

	// This is the kernel's comm field, which is initialized to a
	// the first 15 characters of the basename of the executable
	// being run. It is also set via pthread_setname_np(3) and
	// prctl(2) PR_SET_NAME. It is always NULL-terminated and no
	// longer than 16 bytes (including NULL byte).
	command string

	// This is the command-line used when the process was exec'd via
	// execve(). It is composed of the first 6 elements of argv. It may
	// not be complete if argv contained more than 6 elements.
	commandLine []string

	// Process credentials (uid, gid). This is kept up-to-date by
	// recording changes observed via a probe on commit_creds().
	creds Cred

	// Unique ID for the container instance
	containerID   string
	containerInfo *ContainerInfo
}

// Cred contains process credential information
type Cred struct {
	// Initialized is true when this struct has been initialized. This
	// helps differentiate from processes running as root (all cred fields
	// are legitimately set to 0).
	Initialized bool

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

	// This is not ideal
	comm := data["comm"].([]interface{})
	comm2 := make([]byte, len(comm))
	for i, c := range comm {
		b := c.(int8)
		if b == 0 {
			break
		}

		comm2[i] = byte(b)
	}
	command := string(comm2)

	var tgid int

	const cloneThread = 0x10000 // CLONE_THREAD from the kernel
	if (cloneFlags & cloneThread) != 0 {
		tgid = parentPid
	} else {
		// This is a new thread group leader, tgid is the new pid
		tgid = childPid
	}

	// Inherit container information from parent
	var containerID string
	containerInfo, _ := pc.ProcessContainerInfo(parentPid)
	if containerInfo != nil {
		containerID = containerInfo.ID
	}

	t := task{
		pid:           childPid,
		ppid:          parentPid,
		tgid:          tgid,
		cloneFlags:    cloneFlags,
		command:       command,
		containerID:   containerID,
		containerInfo: containerInfo,
	}

	pc.cache.InsertTask(t.pid, t)

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

	c := Cred{
		Initialized: true,
		UID:         data["uid"].(uint32),
		GID:         data["gid"].(uint32),
		EUID:        data["euid"].(uint32),
		EGID:        data["egid"].(uint32),
		SUID:        data["suid"].(uint32),
		SGID:        data["sgid"].(uint32),
		FSUID:       data["fsuid"].(uint32),
		FSGID:       data["fsgid"].(uint32),
	}

	pc.cache.SetTaskCredentials(pid, c)

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

	glog.V(10).Infof("decodeRuncTaskRename: pid = %d", pid)

	var t task
	pc.cache.LookupTask(pid, &t)

	if len(t.containerID) == 0 {
		containerID, err := procFS.ContainerID(pid)
		glog.V(10).Infof("containerID(%d) = %s", pid, containerID)
		if err == nil && len(containerID) > 0 {
			pc.cache.SetTaskContainerID(pid, containerID)
		}
	} else {
		var parent task
		pc.cache.LookupTask(t.ppid, &parent)

		if len(parent.containerID) == 0 {
			containerID, err := procFS.ContainerID(parent.pid)
			glog.V(10).Infof("containerID(%d) = %s", pid, containerID)
			if err == nil && len(containerID) > 0 {
				pc.cache.SetTaskContainerID(parent.pid, containerID)
			}

		}
	}

	return nil, nil
}

// decodeDoExecve decodes sys_execve() and sys_execveat() events to obtain the
// command-line for the process.
func (pc *ProcessInfoCache) decodeExecve(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	commandLine := make([]string, 0, execveArgCount)
	for i := 0; i < execveArgCount; i++ {
		s := data[fmt.Sprintf("argv%d", i)].(string)
		if len(s) == 0 {
			break
		}
		commandLine = append(commandLine, s)
	}

	pid := int(data["common_pid"].(int32))
	pc.cache.SetTaskCommandLine(pid, commandLine)

	return nil, nil
}
