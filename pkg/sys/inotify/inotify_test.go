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

package inotify

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/capsule8/capsule8/pkg/stream"
	"golang.org/x/sys/unix"
)

var timerDelay = 5 * time.Second

func TestFile(t *testing.T) {
	ticker := time.After(5 * time.Second)
	gotOne := make(chan struct{})

	instance, err := NewInstance()
	if err != nil {
		t.Error(err)
	}
	defer instance.Close()

	s := instance.Events()

	s = stream.Do(s, func(e interface{}) {
		gotOne <- struct{}{}
	})
	_ = stream.Wait(s)

	f, err := ioutil.TempFile("", "inotify_test_TestFile")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f.Name())

	//
	// TempFile opens for read/write, so closing it should result in
	// an IN_CLOSE_WRITE inotify event.
	//
	instance.AddWatch(f.Name(), unix.IN_CLOSE_WRITE)
	f.Close()

	// Success means not hanging
	select {
	case <-gotOne:
	// Success

	case <-ticker:
		t.Fatal("Timeout")
	}
}

func TestFiveFiles(t *testing.T) {
	instance, err := NewInstance()
	if err != nil {
		t.Error(err)
	}
	defer instance.Close()

	f1, err := ioutil.TempFile("", "inotify_test_TestFile")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f1.Name())

	f2, err := ioutil.TempFile("", "inotify_test_TestFile")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f2.Name())

	f3, err := ioutil.TempFile("", "inotify_test_TestFile")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f3.Name())

	f4, err := ioutil.TempFile("", "inotify_test_TestFile")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f4.Name())

	f5, err := ioutil.TempFile("", "inotify_test_TestFile")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f5.Name())

	ch := make(chan bool)
	go func() {
		time.Sleep(timerDelay)
		ch <- true
	}()

	var receivedEvents = 0
	go func() {
		for {
			_, ok := <-instance.Events().Data
			if !ok {
				return
			}

			receivedEvents++

			if receivedEvents == 5 {
				ch <- false
				return
			}
		}
	}()

	//
	// TempFile opens for read/write, so closing it should result in
	// an IN_CLOSE_WRITE inotify event.
	//
	instance.AddWatch(f1.Name(), unix.IN_CLOSE_WRITE)
	instance.AddWatch(f2.Name(), unix.IN_CLOSE_WRITE)
	instance.AddWatch(f3.Name(), unix.IN_CLOSE_WRITE)
	instance.AddWatch(f4.Name(), unix.IN_CLOSE_WRITE)
	instance.AddWatch(f5.Name(), unix.IN_CLOSE_WRITE)

	f1.Close()
	f2.Close()
	f3.Close()
	f4.Close()
	f5.Close()

	timerExpired := <-ch
	if timerExpired {
		t.Error("Expected 5 events, got", receivedEvents)
	}
}

// TestStressInotifyInstances checks inotify.Instance for file descriptor leaks
func TestStressInotifyInstances(t *testing.T) {
	for i := 0; i < 8000; i++ {
		in, err := NewInstance()
		if err != nil {
			t.Error(err)
			break
		}
		in.Close()
	}
}
