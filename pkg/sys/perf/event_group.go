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
	"bytes"
	"runtime"

	"github.com/golang/glog"
	"golang.org/x/sys/unix"
)

// EventGroup represents an event group created through perf_event_open(2)
type EventGroup struct {
	eventAttrs []*EventAttr
	options    eventMonitorOptions

	fds      []int
	groupFds []int

	EventAttrsByID eventAttrMap
	ringBuffers    []*ringBuffer
	onSample       func(Sample)
}

// NewEventGroup creates a new event group described by the given attributes
func NewEventGroup(eventAttrs []*EventAttr, options ...EventMonitorOption) (*EventGroup, error) {
	eg := EventGroup{}
	eg.eventAttrs = eventAttrs

	for _, o := range options {
		o(&eg.options)
	}

	return &eg, nil
}

// Open opens the event group on all CPUs.
func (eg *EventGroup) Open() error {
	ncpu := runtime.NumCPU()

	// Create format map
	eg.EventAttrsByID = newEventAttrMap()

	eg.groupFds = make([]int, ncpu)

	for cpu := 0; cpu < ncpu; cpu++ {
		eg.groupFds[cpu] = int(-1)

		for _, ea := range eg.eventAttrs {
			flags := eg.options.flags | PERF_FLAG_FD_CLOEXEC

			// The parsers currently require this (requires kernel 3.12)
			ea.SampleType |= PERF_SAMPLE_IDENTIFIER

			fd, err := open(ea, -1, cpu, eg.groupFds[cpu], flags)
			if err != nil {
				glog.Fatal(err)
			}

			streamID, err := unix.IoctlGetInt(fd, PERF_EVENT_IOC_ID)
			if err != nil {
				glog.Fatal(err)
			}

			eg.EventAttrsByID[uint64(streamID)] = ea

			eg.fds = append(eg.fds, fd)

			if eg.groupFds[cpu] < 0 {
				// NB: We must open ring buffer before we can redirect output to it
				rb, err := newRingBuffer(fd, eg.options.ringBufferNumPages)
				if err != nil {
					glog.Fatal(err)
				}

				eg.ringBuffers = append(eg.ringBuffers, rb)

				eg.groupFds[cpu] = fd
			}
		}
	}

	return nil
}

// Run enables all of the events in the event group and begins
// collecting samples from them. It only returns on an error.
func (eg *EventGroup) Run(onSample func(Sample)) error {
	eg.onSample = onSample

	pollFds := make([]unix.PollFd, len(eg.groupFds))

	// Enable all events
	for i, fd := range eg.groupFds {
		err := enable(fd)
		if err != nil {
			glog.Fatal(err)
		}

		pollFds[i].Fd = int32(fd)
		pollFds[i].Events = unix.POLLIN
	}

	for {
		n, err := unix.Poll(pollFds, -1)
		if err != nil && err != unix.EINTR {
			return err
		}

		if n > 0 {
			for i, fd := range pollFds {
				if (fd.Revents & unix.POLLIN) != 0 {
					eg.ringBuffers[i].read(eg.readSample)
				}
			}
		}
	}
}

func (eg *EventGroup) readSample(data []byte) {
	reader := bytes.NewReader(data)
	sample := &Sample{}

	err := sample.read(reader, nil, eg.EventAttrsByID)
	if err != nil {
		glog.Fatal(err)
	}

	if eg.onSample != nil {
		eg.onSample(*sample)
	}
}
