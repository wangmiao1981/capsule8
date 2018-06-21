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

package sys

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/capsule8/capsule8/pkg/sys/proc"
	"github.com/capsule8/capsule8/pkg/sys/proc/procfs"
	"github.com/golang/glog"
)

var (
	// Host procfs mounted into our namespace when running as a container
	hostProcFSOnce sync.Once
	hostProcFS     proc.FileSystem
)

// ProcFS creates a proc.FileSystem representing the default procfs mountpoint
// /proc. When running inside a container, this will contain information from
// the container's pid namespace.
func ProcFS() proc.FileSystem {
	fs, err := procfs.NewFileSystem("")
	if err != nil {
		glog.Fatal(err)
	}
	return fs
}

// HostProcFS creates a proc.FileSystem representing the underlying host's
// procfs. If we are running in the host pid namespace, it uses /proc.
// Otherwise, it identifies a mounted-in host procfs by it being mounted on a
// directory that isn't /proc and /proc/self linking to a differing PID than
// that returned by os.Getpid(). If we are running in a container and no
// mounted-in host procfs was identified, then it returns nil.
func HostProcFS() proc.FileSystem {
	hostProcFSOnce.Do(func() {
		hostProcFS = findHostProcFS()
	})

	return hostProcFS
}

func findHostProcFS() proc.FileSystem {
	// Look at /proc's init to see if it is in one or more root
	// cgroup paths.
	procFS := ProcFS()
	if cgroups, err := procFS.TaskControlGroups(1, 1); err != nil {
		glog.Fatalf("Cannot get cgroups for pid 1: %v", err)
	} else {
		for _, cg := range cgroups {
			if cg.Path == "/" {
				// /proc is a host procfs, return it
				return procFS
			}
		}
	}

	// /proc isn't a host procfs, so search all mounted filesystems for it
	for _, mi := range procFS.Mounts() {
		if mi.FilesystemType == "proc" {
			if mi.MountPoint != "/proc" {
				fs, err := procfs.NewFileSystem(mi.MountPoint)
				if err != nil {
					glog.Warning(err)
					continue
				}

				if cgroups, err := fs.TaskControlGroups(1, 1); err != nil {
					glog.Warningf("Cannot get cgroups for pid 1 on procfs %s: %v",
						mi.MountPoint, err)
				} else {
					for _, cg := range cgroups {
						if cg.Path == "/" {
							return fs
						}
					}
				}
			}
		}
	}

	return nil
}

// TracingDir returns the directory on either the debugfs or tracefs
// used to control the Linux kernel trace event subsystem.
func TracingDir() string {
	mounts := HostProcFS().Mounts()

	// Look for an existing tracefs
	for _, m := range mounts {
		if m.FilesystemType == "tracefs" {
			glog.V(1).Infof("Found tracefs at %s", m.MountPoint)
			return m.MountPoint
		}
	}

	// If no mounted tracefs has been found, look for it as a
	// subdirectory of the older debugfs
	for _, m := range mounts {
		if m.FilesystemType == "debugfs" {
			d := filepath.Join(m.MountPoint, "tracing")
			s, err := os.Stat(filepath.Join(d, "events"))
			if err == nil && s.IsDir() {
				glog.V(1).Infof("Found debugfs w/ tracing at %s", d)
				return d
			}

			return m.MountPoint
		}
	}

	return ""
}

// PerfEventDir returns the mountpoint of the perf_event cgroup
// pseudo-filesystem or an empty string if it wasn't found.
func PerfEventDir() string {
	for _, mi := range HostProcFS().Mounts() {
		if mi.FilesystemType == "cgroup" {
			for option := range mi.SuperOptions {
				if option == "perf_event" {
					return mi.MountPoint
				}
			}
		}
	}

	return ""
}

// MountTempFS mounts a filesystem. It is primarily a wrapper around unix.Mount,
// but it also ensures that the mountpoint exists before attempting to mount to
// it.
func MountTempFS(source string, target string, fstype string, flags uintptr, data string) error {
	// Make sure that `target` exists.
	err := os.MkdirAll(target, 0500)
	if err != nil {
		glog.V(2).Infof("Couldn't create temp %s mountpoint: %s", fstype, err)
		return err
	}

	err = unix.Mount(source, target, fstype, flags, data)
	if err != nil {
		glog.V(2).Infof("Couldn't mount %s on %s: %s", fstype, target, err)
		return err
	}

	return nil
}

// UnmountTempFS unmounts a filesystem. It is primarily a wrapper around
// unix.Unmount, but it also removes the mountpoint after the filesystem
// is unmounted.
func UnmountTempFS(dir string, fstype string) error {
	err := unix.Unmount(dir, 0)
	if err != nil {
		glog.V(2).Infof("Couldn't unmount %s at %s: %s", fstype, dir, err)
		return err
	}

	err = os.Remove(dir)
	if err != nil {
		glog.V(2).Infof("Couldn't remove %s: %s", dir, err)
		return err
	}

	return nil
}
