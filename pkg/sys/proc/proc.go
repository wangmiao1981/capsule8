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

package proc

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
)

//
// Docker cgroup paths may look like either of:
// - /docker/[CONTAINER_ID]
// - /kubepods/[...]/[CONTAINER_ID]
// - /system.slice/docker-[CONTAINER_ID].scope
//
const cgroupContainerPattern = "^(/docker/|/kubepods/.*/|/system.slice/docker-)([[:xdigit:]]{64})(.scope|$)"

var (
	// Default procfs mounted on /proc
	procFSOnce sync.Once
	procFS     *FileSystem

	// Boot ID taken from /proc/sys/kernel/random/boot_id
	bootID string

	// "Once" control for getting the boot ID
	bootIDOnce sync.Once

	// A regular expression to match docker container cgroup names
	cgroupContainerRE = regexp.MustCompile(cgroupContainerPattern)
)

// FS creates a FileSystem instance representing the default
// procfs mountpoint /proc. When running inside a container, this will
// contain information from the container's pid namespace.
func FS() *FileSystem {
	procFSOnce.Do(func() {
		//
		// Do some quick sanity checks to make sure /proc is our procfs
		//

		fi, err := os.Stat("/proc")
		if err != nil {
			glog.Fatal("/proc not found")
		}

		if !fi.IsDir() {
			glog.Fatal("/proc not a directory")
		}

		self, err := os.Readlink("/proc/self")
		if err != nil {
			glog.Fatal("couldn't read /proc/self")
		}

		_, file := filepath.Split(self)
		pid, err := strconv.Atoi(file)
		if err != nil {
			glog.Fatalf("Couldn't parse %s as pid", file)
		}

		if pid != os.Getpid() {
			glog.Fatalf("/proc/self points to wrong pid: %d", pid)
		}

		procFS = &FileSystem{
			MountPoint: "/proc",
		}
	})

	return procFS
}

// FileSystem represents data accessible through the proc pseudo-filesystem.
type FileSystem struct {
	MountPoint string
}

// Open opens the procfs file indicated by the given relative path.
func (fs *FileSystem) Open(relativePath string) (*os.File, error) {
	return os.Open(filepath.Join(fs.MountPoint, relativePath))
}

// ReadFile returns the contents of the procfs file indicated by
// the given relative path.
func ReadFile(relativePath string) ([]byte, error) {
	return FS().ReadFile(relativePath)
}

// ReadFile returns the contents of the procfs file indicated by the
// given relative path.
func (fs *FileSystem) ReadFile(relativePath string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(fs.MountPoint, relativePath))
}

// CommandLine gets the full command-line arguments for the process
// indicated by the given PID.
func CommandLine(pid int) []string {
	return FS().CommandLine(pid)
}

// CommandLine gets the full command-line arguments for the process
// indicated by the given PID.
func (fs *FileSystem) CommandLine(pid int) []string {
	//
	// This misses the command-line arguments for short-lived processes,
	// which is clearly not ideal.
	//
	filename := fmt.Sprintf("%d/cmdline", pid)
	cmdline, err := fs.ReadFile(filename)
	if err != nil {
		return nil
	}

	var commandLine []string

	reader := bufio.NewReader(bytes.NewReader(cmdline[:]))
	for {
		s, err := reader.ReadString(0)
		if err != nil {
			break
		}

		if len(s) > 1 {
			commandLine = append(commandLine, s[:len(s)-1])
		} else {
			break
		}
	}

	return commandLine
}

// Cgroups returns the cgroup membership of the process
// indicated by the given PID.
func Cgroups(pid int) ([]Cgroup, error) {
	return FS().Cgroups(pid)
}

// Cgroups returns the cgroup membership of the process
// indicated by the given PID.
func (fs *FileSystem) Cgroups(pid int) ([]Cgroup, error) {
	filename := fmt.Sprintf("%d/cgroup", pid)
	cgroup, err := fs.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	cgroups := parseProcPidCgroup(cgroup)
	return cgroups, nil
}

// parseProcPidCgroup parses the contents of /proc/[pid]/cgroup
func parseProcPidCgroup(cgroup []byte) []Cgroup {
	var cgroups []Cgroup

	scanner := bufio.NewScanner(bytes.NewReader(cgroup))
	for scanner.Scan() {
		t := scanner.Text()
		parts := strings.Split(t, ":")
		ID, err := strconv.Atoi(parts[0])
		if err != nil {
			glog.Fatalf("Couldn't parse cgroup line: %s", t)
		}

		c := Cgroup{
			ID:          ID,
			Controllers: strings.Split(parts[1], ","),
			Path:        parts[2],
		}

		cgroups = append(cgroups, c)
	}

	return cgroups
}

// Cgroup describes the cgroup membership of a process
type Cgroup struct {
	// Unique hierarchy ID
	ID int

	// Cgroup controllers (subsystems) bound to the hierarchy
	Controllers []string

	// Path is the pathname of the control group to which the process
	// belongs. It is relative to the mountpoint of the hierarchy.
	Path string
}

// ContainerID returns the container ID running the process indicated
// by the given PID. Returns the empty string if the process is not
// running within a container. Returns a non-nil error if the process
// indicated by the given PID wasn't found.
func ContainerID(pid int) (string, error) {
	return FS().ContainerID(pid)
}

// ContainerID returns the container ID running the process indicated
// by the given PID. Returns the empty string if the process is not
// running within a container. Returns a  non-nil error if the process
// indicated by the given PID wasn't found.
func (fs *FileSystem) ContainerID(pid int) (string, error) {
	cgroups, err := fs.Cgroups(pid)
	if err != nil {
		return "", err
	}

	glog.V(10).Infof("pid:%d cgroups:%+v", pid, cgroups)

	containerID := containerIDFromCgroups(cgroups)
	return containerID, nil
}

func containerIDFromCgroups(cgroups []Cgroup) string {
	for _, pci := range cgroups {
		matches := cgroupContainerRE.FindStringSubmatch(pci.Path)
		if len(matches) > 2 {
			return matches[2]
		}
	}

	return ""
}

// ReadProcessStatus reads the status of a process from the proc filesystem,
// parsing each field and storing it in the supplied struct.
func (fs *FileSystem) ReadProcessStatus(tgid, pid int, i interface{}) error {
	var filename string
	if tgid == pid {
		filename = fmt.Sprintf("%d/status", tgid)
	} else {
		filename = fmt.Sprintf("%d/task/%d/status", tgid, pid)
	}
	f, err := fs.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return parseProcessStatus(f, tgid, pid, i)
}

func parseProcessStatus(r io.Reader, tgid, pid int, i interface{}) error {
	v := reflect.ValueOf(i)
	if v.Kind() != reflect.Ptr {
		return errors.New("Destination must be a pointer to struct")
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return errors.New("Destination pointer must be to a struct")
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		field := findFieldByTag(v, parts[0])
		if !field.IsValid() {
			continue
		}

		if err := setValueFromString(field, parts[0],
			strings.TrimSpace(parts[1])); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func findFieldByTag(v reflect.Value, name string) reflect.Value {
	t := v.Type()
	for i := t.NumField() - 1; i >= 0; i-- {
		f := t.Field(i)
		if f.Tag == reflect.StructTag(name) {
			return v.Field(i)
		}
	}
	return reflect.Value{}
}

func setValueFromString(v reflect.Value, name, s string) error {
	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if x, err := strconv.ParseInt(s, 0, 64); err == nil {
			v.SetInt(x)
		} else {
			return err
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64:
		if x, err := strconv.ParseUint(s, 0, 64); err == nil {
			v.SetUint(x)
		} else {
			return err
		}
	case reflect.Bool:
		if x, err := strconv.ParseBool(s); err == nil {
			v.SetBool(x)
		} else {
			return err
		}
	case reflect.Float32, reflect.Float64:
		if x, err := strconv.ParseFloat(s, 64); err == nil {
			v.SetFloat(x)
		} else {
			return err
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Slice {
			return fmt.Errorf("Nested arrays are unsupported (%s)", name)
		}
		l := strings.Fields(s)
		a := reflect.MakeSlice(v.Type(), len(l), len(l))
		for i, x := range l {
			n := fmt.Sprintf("%s[%d]", name, i)
			if err := setValueFromString(a.Index(i), n, x); err != nil {
				return err
			}
		}
		v.Set(a)
	default:
		return fmt.Errorf("Cannot set field %s", name)
	}

	return nil
}

// UniqueID returns a reproducible namespace-independent
// unique identifier for the process indicated by the given PID.
func UniqueID(tgid, pid int) string {
	return FS().UniqueID(tgid, pid)
}

// UniqueID returns a reproducible namespace-independent
// unique identifier for the process indicated by the given PID.
func (fs *FileSystem) UniqueID(tgid, pid int) string {
	ps := fs.Stat(tgid, pid)
	if ps == nil {
		return ""
	}

	return ps.UniqueID()
}

// Stat reads the given process's status and returns a ProcessStatus
// with methods to parse and return information from that status as
// needed.
func Stat(tgid, pid int) *ProcessStatus {
	return FS().Stat(tgid, pid)
}

// statFields parses the contents of a /proc/PID/stat field into fields.
func statFields(stat string) []string {
	//
	// Parse out the command field.
	//
	// This requires special care because the command can contain white space
	// and / or punctuation. Fortunately, we are guaranteed that the command
	// will always be between the first '(' and the last ')'.
	//
	firstLParen := strings.IndexByte(stat, '(')
	lastRParen := strings.LastIndexByte(stat, ')')
	if firstLParen < 0 || lastRParen < 0 || lastRParen < firstLParen {
		return nil
	}
	command := stat[firstLParen+1 : lastRParen]
	statFields := []string{
		strings.TrimRight(stat[:firstLParen], " "),
		command,
	}
	return append(statFields, strings.Fields(stat[lastRParen+1:])...)
}

// Stat reads the given process's status from the ProcFS receiver and
// returns a ProcessStatus with methods to parse and return
// information from that status as needed.
func (fs *FileSystem) Stat(tgid, pid int) *ProcessStatus {
	var filename string
	if tgid == pid {
		filename = fmt.Sprintf("%d/stat", pid)
	} else {
		filename = fmt.Sprintf("%d/task/%d/stat", tgid, pid)
	}
	stat, err := fs.ReadFile(filename)
	if err != nil {
		return nil
	}

	return &ProcessStatus{
		statFields: statFields(string(stat)),
	}
}

// ProcessStatus represents process status available via /proc/[pid]/stat
type ProcessStatus struct {
	statFields []string
	pid        int
	comm       string
	ppid       int
	startTime  uint64
	startStack uint64
	uniqueID   string
}

// PID returns the PID of the process.
func (ps *ProcessStatus) PID() int {
	if ps.pid == 0 {
		pid := ps.statFields[0]
		i, err := strconv.ParseInt(pid, 0, 32)
		if err != nil {
			glog.Fatalf("Couldn't parse PID: %s", pid)
		}

		ps.pid = int(i)
	}

	return ps.pid
}

// Command returns the command name associated with the process (this is
// typically referred to as the comm value in Linux kernel interfaces).
func (ps *ProcessStatus) Command() string {
	if len(ps.comm) == 0 {
		ps.comm = ps.statFields[1]
	}

	return ps.comm
}

// ParentPID returns the PID of the parent of the process.
func (ps *ProcessStatus) ParentPID() int {
	if ps.ppid == 0 {
		ppid := ps.statFields[3]
		i, err := strconv.ParseInt(ppid, 0, 32)
		if err != nil {
			glog.Fatalf("Couldn't parse PPID: %s", ppid)
		}

		ps.ppid = int(i)
	}

	return ps.ppid
}

// StartTime returns the time in jiffies (< 2.6) or clock ticks (>= 2.6)
// after system boot when the process started.
func (ps *ProcessStatus) StartTime() uint64 {
	if ps.startTime == 0 {
		st := ps.statFields[22-1]
		i, err := strconv.ParseUint(st, 0, 64)
		if err != nil {
			glog.Fatalf("Couldn't parse starttime: %s", st)
		}

		ps.startTime = i
	}

	return ps.startTime
}

// StartStack returns the address of the start (i.e., bottom) of the stack.
func (ps *ProcessStatus) StartStack() uint64 {
	if ps.startStack == 0 {
		ss := ps.statFields[28-1]
		i, err := strconv.ParseUint(ss, 0, 64)
		if err != nil {
			glog.Fatalf("Couldn't parse startstack: %s", ss)
		}

		ps.startStack = i
	}

	return ps.startStack
}

// UniqueID returns a reproducible unique identifier for the
// process indicated by the given PID.
func (ps *ProcessStatus) UniqueID() string {
	if len(ps.uniqueID) == 0 {
		ps.uniqueID = DeriveUniqueID(ps.PID(), ps.StartTime())
	}

	return ps.uniqueID
}

// DeriveUniqueID returns a unique ID for thye process with the given
// PID and start time
func DeriveUniqueID(pid int, startTime uint64) string {
	// Hash the bootID, PID, and parent PID to create a
	// unique process identifier that can also be calculated
	// from perf records and trace events

	h := sha256.New()

	err := binary.Write(h, binary.LittleEndian, []byte(BootID()))
	if err != nil {
		glog.Fatal(err)
	}

	err = binary.Write(h, binary.LittleEndian, int32(pid))
	if err != nil {
		glog.Fatal(err)
	}

	err = binary.Write(h, binary.LittleEndian, startTime)
	if err != nil {
		glog.Fatal(err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// BootID gets the host system boot identifier
func BootID() string {
	bootIDOnce.Do(func() {
		data, err := ReadFile("/sys/kernel/random/boot_id")
		if err != nil {
			panic(err)
		}

		bootID = strings.TrimSpace(string(data))
	})

	return bootID
}
