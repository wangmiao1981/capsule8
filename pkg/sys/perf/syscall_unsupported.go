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

// +build !linux

package perf

import (
	"syscall"
)

func enable(fd int) error {
	return syscall.ENOSYS
}

func setFilter(fd int, filter string) error {
	return syscall.ENOSYS
}

func disable(fd int) error {
	return syscall.ENOSYS
}

func open(attr *EventAttr, pid int, cpu int, groupFd int, flags uintptr) (int, error) {
	return -1, syscall.ENOSYS
}
