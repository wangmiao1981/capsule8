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

// Package inotify provides an interface to the Linux inotify(7) API
// for monitoring filesystem events.
package inotify

//
// Background on challenges with inotify(7):
// https://lwn.net/Articles/605128/
//

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/stream"

	"golang.org/x/sys/unix"
)

const inotifyBufferSize = (unix.SizeofInotifyEvent + unix.NAME_MAX + 1) * 128

// Event represents an inotify event
type Event struct {
	unix.InotifyEvent

	// Name within watched path if it's a directory
	Name string

	// Watched path associated with the event
	Path string
}

// Instance represents an initialized inotify instance
type Instance struct {
	fd   int
	pipe [2]int32

	events chan Event
	ctrl   chan interface{}
	elem   chan interface{}

	watch map[int]*watch
	path  map[string]*watch

	eventStream *stream.Stream
	wg          sync.WaitGroup
}

type watch struct {
	descriptor int
	path       string
	mask       uint32
}

func (is *Instance) add(path string, mask uint32) error {
	wd, err := unix.InotifyAddWatch(is.fd, path, mask)
	if err == nil {
		watch := &watch{
			descriptor: wd,
			path:       path,
			mask:       mask,
		}

		is.watch[wd] = watch
		is.path[path] = watch
	}

	return err
}

func (is *Instance) remove(path string) error {
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			watch := is.path[path]
			if watch != nil {
				_, err := unix.InotifyRmWatch(is.fd, uint32(watch.descriptor))
				return err
			}
		}

		return nil
	}

	return filepath.Walk(path, walkFn)
}

// -----------------------------------------------------------------------------

type inotifyAdd struct {
	reply chan<- error
	path  string
	mask  uint32
}

type inotifyRemove struct {
	reply chan<- error
	path  string
}

func (is *Instance) handleControlMessage(msg interface{}) {
	switch msg := msg.(type) {
	case inotifyAdd:
		err := is.add(msg.path, msg.mask)
		msg.reply <- err

	case inotifyRemove:
		err := is.remove(msg.path)
		msg.reply <- err

	default:
		panic(fmt.Sprintf("Unknown control message type: %T", msg))
	}
}

func (is *Instance) handleInotifyEvent(ev Event) {
	if w, ok := is.watch[int(ev.Wd)]; ok {
		ev.Path = filepath.Join(w.path, ev.Name)
	} else {
		return
	}

	if (ev.Mask & unix.IN_IGNORED) != 0 {
		// Watch was removed explicitly or automatically
		delete(is.watch, int(ev.Wd))
		delete(is.path, ev.Path)
	} else {
		is.elem <- &ev
	}
}

func (is *Instance) pollLoop() {
	for {
		select {
		case msg, ok := <-is.ctrl:
			// This is a control message (add, remove)
			if !ok {
				return
			}
			is.handleControlMessage(msg)
		case ev, ok := <-is.events:
			// This is an event from inotify
			if !ok {
				return
			}
			is.handleInotifyEvent(ev)
		}
	}
}

func (is *Instance) processInotifyBuffer(b []byte) {
	buf := bytes.NewBuffer(b)
	for buf.Len() > 0 {
		ev := Event{}
		binary.Read(buf, binary.LittleEndian, &ev.InotifyEvent)

		// The name field from kernel is padded w/ NULLs to an
		// alignment boundary, remove them when converting to
		// a string.
		name := buf.Next(int(ev.Len))
		ev.Name = string(bytes.Trim(name, "\x00"))

		is.events <- ev
	}
}

func (is *Instance) inotifyReader() {
	pollFDs := []unix.PollFd{
		{
			Fd:     is.pipe[0],
			Events: unix.POLLIN,
		},
		{
			Fd:     int32(is.fd),
			Events: unix.POLLIN,
		},
	}
	buffer := make([]byte, inotifyBufferSize)
	for {
		n, err := unix.Poll(pollFDs, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			break
		}

		if n <= 0 {
			continue
		}
		if pollFDs[0].Revents&(unix.POLLNVAL|unix.POLLERR|unix.POLLHUP|unix.POLLRDHUP) != 0 {
			break
		}
		if pollFDs[1].Revents&unix.POLLIN == 0 {
			continue
		}

		n, err = unix.Read(is.fd, buffer)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			break
		}
		if n > 0 {
			is.processInotifyBuffer(buffer[:n])
		}
	}
}

// -----------------------------------------------------------------------------

func (is *Instance) sendAdd(path string, mask uint32) error {
	reply := make(chan error)
	msg := inotifyAdd{
		reply: reply,
		path:  path,
		mask:  mask,
	}

	is.ctrl <- msg
	return <-reply
}

func (is *Instance) removeWatch(path string) error {
	reply := make(chan error)
	msg := inotifyRemove{
		reply: reply,
		path:  path,
	}

	is.ctrl <- msg
	return <-reply
}

// -----------------------------------------------------------------------------

// NewInstance creates a new inotify instance
func NewInstance() (*Instance, error) {
	fd, err := unix.InotifyInit()
	if err != nil {
		return nil, err
	}

	stop := make(chan interface{})
	elem := make(chan interface{}, config.Sensor.ChannelBufferLength)
	ctrl := make(chan interface{})
	events := make(chan Event, config.Sensor.ChannelBufferLength)

	is := &Instance{
		fd:     fd,
		events: events,
		ctrl:   ctrl,
		elem:   elem,
		watch:  make(map[int]*watch),
		path:   make(map[string]*watch),
		eventStream: &stream.Stream{
			Ctrl: stop,
			Data: elem,
		},
	}

	var p [2]int
	err = unix.Pipe(p[:])
	if err != nil {
		close(events)
		close(ctrl)
		is.eventStream.Close()
		unix.Close(fd)
		return nil, err
	}
	is.pipe[0] = int32(p[0])
	is.pipe[1] = int32(p[1])

	is.wg.Add(1)
	go func() {
		defer is.wg.Done()
		is.inotifyReader()
	}()

	is.wg.Add(1)
	go func() {
		defer is.wg.Done()
		is.pollLoop()
	}()

	return is, nil
}

// Events returns a Event stream.Stream of the inotify instance's events
func (is *Instance) Events() *stream.Stream {
	return is.eventStream
}

// AddWatch adds the given path to the inotify instance's watch list for
// events specified in the given mask. If the path is already being watched,
// the existing watch is modified.
func (is *Instance) AddWatch(path string, mask uint32) error {
	return is.sendAdd(path, mask)
}

// RemoveWatch removes the given path from the inotify instance's watch list.
func (is *Instance) RemoveWatch(path string) error {
	return is.removeWatch(path)
}

// Close the inotify instance and allow the kernel to free its associated
// resources. All associated watches are automatically freed.
func (is *Instance) Close() {
	fd := int32(is.pipe[1])
	if fd == -1 {
		return
	}
	if !atomic.CompareAndSwapInt32(&is.pipe[1], fd, -1) {
		return
	}

	// Close the write side of the pipe so that the inotifyReader will
	// terminate.
	unix.Close(int(fd))

	// Close the control channel so that the pollLoop will terminate.
	close(is.ctrl)

	// Wait for the pollLoop to exit
	is.wg.Wait()

	// Cleanup remaining resources
	is.eventStream.Close()
	close(is.events)
	unix.Close(int(is.pipe[0]))
	unix.Close(is.fd)
}
