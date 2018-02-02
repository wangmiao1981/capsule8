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

import (
	"math/rand"
	"os"
	"testing"
)

/*

Current benchmark results:

BenchmarkArrayCache-8                   	500000000	         3.18 ns/op
BenchmarkMapCache-8                     	10000000	       152 ns/op
BenchmarkArrayCacheParallel-8           	2000000000	         1.56 ns/op
BenchmarkMapCacheParallel-8             	 5000000	       252 ns/op
BenchmarkStatCacheMiss-8                	  200000	     11180 ns/op
BenchmarkStatCacheMissParallel-8        	  500000	      3460 ns/op
BenchmarkContainerCacheMiss-8           	  100000	     14729 ns/op
BenchmarkContainerCacheMissParallel-8   	  300000	      5789 ns/op

*/

const arrayTaskCacheSize = 32768

var values = []task{
	{1, 2, 3, 0x120011, "foo", nil, Cred{}, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil},
	{1, 2, 3, 0x120011, "bar", nil, Cred{}, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil},
	{1, 2, 3, 0x120011, "baz", nil, Cred{}, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil},
	{1, 2, 3, 0x120011, "qux", nil, Cred{}, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil},
}

func TestCaches(t *testing.T) {

	arrayCache := newArrayTaskCache(arrayTaskCacheSize)
	mapCache := newMapTaskCache()

	for i := 0; i < arrayTaskCacheSize; i++ {
		arrayCache.InsertTask(i, values[i%4])
		mapCache.InsertTask(i, values[i%4])
	}

	for i := arrayTaskCacheSize - 1; i >= 0; i-- {
		var tk task
		if arrayCache.LookupTask(i, &tk) {
			cid := tk.containerID

			if cid != values[i%4].containerID {
				t.Fatalf("Expected %s for pid %d, got %s",
					values[i%4].containerID, i, cid)
			}

		}

		if mapCache.LookupTask(i, &tk) {
			cid := tk.containerID

			if cid != values[i%4].containerID {
				t.Fatalf("Expected %s for pid %d, got %s",
					values[i%4].containerID, i, cid)
			}

		}
	}
}

func randomTgid(pidMap map[int]int) int {
	var tgids []int

	for p := range pidMap {
		if pidMap[p] == p {
			tgids = append(tgids, p)
		}
	}

	return tgids[rand.Intn(len(tgids))]
}

func nextPid(pidMap map[int]int, maxPid int, lastPid *int) {
	lp := *lastPid

	for {
		// Advance last pid
		*lastPid = (*lastPid + 1) % maxPid
		if *lastPid == 0 {
			// pid 0 is illegal
			*lastPid = 1
		}

		if *lastPid == lp {
			if lp == 1 {
				panic("Can't delete pid 1")
			}

			for p := range pidMap {
				if pidMap[p] == *lastPid {
					delete(pidMap, *lastPid)
				}
			}

			return
		}

		_, found := pidMap[*lastPid]
		if !found {
			return
		}
	}
}

func TestCacheCycle(t *testing.T) {
	maxPid := 128
	cache := newArrayTaskCache(uint(maxPid))

	// pidMap is a map of pids to tgid
	pidMap := make(map[int]int)

	// Create init process
	lastPid := 1
	pidMap[lastPid] = lastPid

	initTask := task{
		pid:  lastPid,
		ppid: 0,
		tgid: lastPid,
	}

	cache.InsertTask(lastPid, initTask)

	for i := 0; i < 10000; i++ {
		// Choose a random current process
		pid := randomTgid(pidMap)

		r := rand.Intn(100)
		if r < 10 {
			// Fork a new child process

			// Choose a random unused pid
			nextPid(pidMap, maxPid, &lastPid)

			// Add to pidMap with tgid == self
			pidMap[lastPid] = lastPid

			newTask := task{
				pid:  lastPid,
				ppid: pid,
				tgid: lastPid,
			}

			cache.InsertTask(lastPid, newTask)
		} else if r < 20 {
			// Terminate tgid
			if pid != 1 {
				// Delete tgid and all of its threads
				for p := range pidMap {
					if pidMap[p] == pid {
						delete(pidMap, p)
					}
				}
			}

		} else if pid != 1 {
			// Clone a new thread
			nextPid(pidMap, maxPid, &lastPid)

			// Add to pidMap with tgid == parent pid
			pidMap[lastPid] = pid

			newTask := task{
				pid:  lastPid,
				ppid: pid,
				tgid: pid,
			}

			cache.InsertTask(lastPid, newTask)
		}

		// Make sure that we can traverse process ancestry for every
		// pid. If this enters an infinite loop, then we somehow got a
		// cycle.
		for i := range pidMap {
			cache.LookupLeader(i)
		}
	}
}

func BenchmarkArrayCache(b *testing.B) {
	cache := newArrayTaskCache(arrayTaskCacheSize)
	var tk task

	for i := 0; i < b.N; i++ {
		cache.InsertTask((i % arrayTaskCacheSize), values[i%4])
	}

	for i := 0; i < b.N; i++ {
		_ = cache.LookupTask((i % arrayTaskCacheSize), &tk)
	}
}

func BenchmarkMapCache(b *testing.B) {
	cache := newMapTaskCache()
	var tk task

	for i := 0; i < b.N; i++ {
		cache.InsertTask((i % arrayTaskCacheSize), values[i%4])
	}

	for i := 0; i < b.N; i++ {
		_ = cache.LookupTask((i % arrayTaskCacheSize), &tk)
	}
}

func BenchmarkArrayCacheParallel(b *testing.B) {
	cache := newArrayTaskCache(arrayTaskCacheSize)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.InsertTask((i % arrayTaskCacheSize), values[i%4])
			i++
		}
	})

	b.RunParallel(func(pb *testing.PB) {
		var tk task

		i := 0
		for pb.Next() {
			_ = cache.LookupTask((i % arrayTaskCacheSize), &tk)
			i++
		}
	})
}

func BenchmarkMapCacheParallel(b *testing.B) {
	cache := newMapTaskCache()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.InsertTask((i % arrayTaskCacheSize), values[i%4])
			i++
		}
	})

	b.RunParallel(func(pb *testing.PB) {
		var tk task

		i := 0
		for pb.Next() {
			_ = cache.LookupTask((i % arrayTaskCacheSize), &tk)
			i++
		}
	})
}

func BenchmarkStatCacheMiss(b *testing.B) {
	pid := os.Getpid()

	for i := 0; i < b.N; i++ {
		_ = procFS.Stat(pid)
	}
}

func BenchmarkStatCacheMissParallel(b *testing.B) {
	pid := os.Getpid()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = procFS.Stat(pid)
		}
	})
}

func BenchmarkContainerCacheMiss(b *testing.B) {
	pid := os.Getpid()

	for i := 0; i < b.N; i++ {
		_, err := procFS.ContainerID(pid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContainerCacheMissParallel(b *testing.B) {
	pid := os.Getpid()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := procFS.ContainerID(pid)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
