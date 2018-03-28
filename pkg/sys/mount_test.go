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
	"testing"

	"github.com/golang/glog"
	"github.com/stretchr/testify/assert"
)

var mockMounts = []struct {
	mount     Mount
	mountLine string
}{
	{
		Mount{
			MountID:        uint(260),
			ParentID:       uint(89),
			Major:          uint(253),
			Minor:          uint(6),
			Root:           "/containers/ab63f6eab155cf698a20e7d5e03298dd8baf442ff6e4e20e2dff320f3e2fee3e/mounts",
			MountPoint:     "/var/lib/docker/containers/ab63f6eab155cf698a20e7d5e03298dd8baf442ff6e4e20e2dff320f3e2fee3e/mounts",
			MountOptions:   []string{"rw", "relatime"},
			OptionalFields: map[string]string{"unbindable": ""},
			FilesystemType: "xfs",
			MountSource:    "/dev/mapper/rootvg-docker_lv",
			SuperOptions: map[string]string{
				"attr2":    "",
				"inode64":  "",
				"noquota":  "",
				"rw":       "",
				"seclabel": "",
			},
		},
		"260 89 253:6 /containers/ab63f6eab155cf698a20e7d5e03298dd8baf442ff6e4e20e2dff320f3e2fee3e/mounts /var/lib/docker/containers/ab63f6eab155cf698a20e7d5e03298dd8baf442ff6e4e20e2dff320f3e2fee3e/mounts rw,relatime unbindable - xfs /dev/mapper/rootvg-docker_lv rw,seclabel,attr2,inode64,noquota",
	},
	{
		Mount{
			MountID:        uint(287),
			ParentID:       uint(26),
			Major:          uint(0),
			Minor:          uint(47),
			Root:           "/",
			MountPoint:     "/run/user/42",
			MountOptions:   []string{"rw", "nosuid", "nodev", "relatime"},
			OptionalFields: map[string]string{"shared": "226"},
			FilesystemType: "tmpfs",
			MountSource:    "tmpfs",
			SuperOptions: map[string]string{
				"gid":      "42",
				"mode":     "700",
				"rw":       "",
				"seclabel": "",
				"size":     "1632548k",
				"uid":      "42",
			},
		},
		"287 26 0:47 / /run/user/42 rw,nosuid,nodev,relatime shared:226 - tmpfs tmpfs rw,seclabel,size=1632548k,mode=700,uid=42,gid=42",
	},
}

func TestMockMounts(t *testing.T) {
	for _, m := range mockMounts {
		obtainedMount, err := parseMount(m.mountLine)
		if err != nil {
			t.Error("Could not parse mount, got: ", err)
		}
		assert.Equal(t, m.mount, obtainedMount)
	}
}

func TestLiveMounts(t *testing.T) {
	mounts := Mounts()

	if len(mounts) == 0 {
		t.Error("Empty mountInfo returned by GetMountInfo()")
	}

	glog.V(1).Infof("Discovered %v mounts", len(mounts))
}

func TestGetCgroupPerfEventFSMountPoint(t *testing.T) {
	perfEventDir := PerfEventDir()

	if len(perfEventDir) == 0 {
		t.Skip("Couldn't find a mounted perf_event cgroup filesystem")
	}

	glog.V(1).Infof("Found perf_event cgroup filesystem mounted at %s",
		perfEventDir)
}

func TestGetProcFs(t *testing.T) {
	procFS := ProcFS()

	if procFS == nil {
		t.Fatal("Couldn't find procfs")
	}
}

func TestGetTraceFSMountPoint(t *testing.T) {
	tracingDir := TracingDir()

	if len(tracingDir) == 0 {
		t.Skip("Could not find tracefs")
	}

	glog.V(1).Infof("Found tracefs at %s", tracingDir)
}
