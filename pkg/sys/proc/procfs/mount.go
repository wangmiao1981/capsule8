// Copyright 2018 Capsule8, Inc.
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

package procfs

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/capsule8/capsule8/pkg/sys/proc"

	"github.com/golang/glog"
)

func parseMount(line string) (proc.Mount, error) {
	fields := strings.Fields(line)

	mountID, err := strconv.Atoi(fields[0])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse mountID %q", fields[0])
	}

	parentID, err := strconv.Atoi(fields[1])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse parentID %q", fields[1])
	}

	mm := strings.Split(fields[2], ":")
	major, err := strconv.Atoi(mm[0])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse major %q", mm[0])
	}

	minor, err := strconv.Atoi(mm[1])
	if err != nil {
		return proc.Mount{}, fmt.Errorf("Couldn't parse minor %q", mm[1])
	}

	mountOptions := strings.Split(fields[5], ",")

	optionalFieldsMap := make(map[string]string)
	var i int
	for i = 6; fields[i] != "-"; i++ {
		tagValue := strings.Split(fields[i], ":")
		if len(tagValue) == 1 {
			optionalFieldsMap[tagValue[0]] = ""
		} else {
			optionalFieldsMap[tagValue[0]] = strings.Join(tagValue[1:], ":")
		}
	}

	filesystemType := fields[i+1]
	mountSource := fields[i+2]
	superOptions := fields[i+3]

	superOptionsMap := make(map[string]string)
	for _, option := range strings.Split(superOptions, ",") {
		nameValue := strings.Split(option, "=")
		if len(nameValue) == 1 {
			superOptionsMap[nameValue[0]] = ""
		} else {
			superOptionsMap[nameValue[0]] = strings.Join(nameValue[1:], ":")
		}
	}

	return proc.Mount{
		MountID:        uint(mountID),
		ParentID:       uint(parentID),
		Major:          uint(major),
		Minor:          uint(minor),
		Root:           fields[3],
		MountPoint:     fields[4],
		MountOptions:   mountOptions,
		OptionalFields: optionalFieldsMap,
		FilesystemType: filesystemType,
		MountSource:    mountSource,
		SuperOptions:   superOptionsMap,
	}, nil
}

// Mounts returns the list of currently mounted filesystems.
func (fs *FileSystem) Mounts() []proc.Mount {
	data, err := fs.ReadFile("self/mountinfo")
	if err != nil {
		glog.Fatalf("Couldn't read self/mountinfo from proc")
	}

	var mounts []proc.Mount
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		m, err := parseMount(line)
		if err != nil {
			glog.Fatal(err)
		}
		mounts = append(mounts, m)
	}

	return mounts
}
