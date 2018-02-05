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
const mapTaskCacheSize = 32768

var values = []Task{
	{1, 2, 3, "foo", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, ""},
	{1, 2, 3, "bar", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, ""},
	{1, 2, 3, "baz", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, ""},
	{1, 2, 3, "qux", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, ""},
}

func TestCaches(t *testing.T) {

	arrayCache := newArrayTaskCache(arrayTaskCacheSize)
	mapCache := newMapTaskCache(mapTaskCacheSize)

	for i := 0; i < arrayTaskCacheSize-1; i++ {
		arrayCache.InsertTask(i+1, &values[i%4])
		mapCache.InsertTask(i+1, &values[i%4])
	}

	for i := arrayTaskCacheSize - 2; i >= 0; i-- {
		if tk, ok := arrayCache.LookupTask(i + 1); ok {
			cid := tk.ContainerID
			if cid != values[i%4].ContainerID {
				t.Fatalf("Expected %s for pid %d, got %s",
					values[i%4].ContainerID, i, cid)
			}

		}

		if tk, ok := mapCache.LookupTask(i + 1); ok {
			cid := tk.ContainerID
			if cid != values[i%4].ContainerID {
				t.Fatalf("Expected %s for pid %d, got %s",
					values[i%4].ContainerID, i, cid)
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

	initTask := &Task{
		PID:  lastPid,
		PPID: 0,
		TGID: lastPid,
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

			newTask := &Task{
				PID:  lastPid,
				PPID: pid,
				TGID: lastPid,
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

			newTask := &Task{
				PID:  lastPid,
				PPID: pid,
				TGID: pid,
			}
			cache.InsertTask(lastPid, newTask)
		}

		// Make sure that we can traverse process ancestry for every
		// pid. If this enters an infinite loop, then we somehow got a
		// cycle.
		for i := range pidMap {
			cache.LookupTaskAndLeader(i)
		}
	}
}

func BenchmarkArrayCache(b *testing.B) {
	cache := newArrayTaskCache(arrayTaskCacheSize)

	for i := 0; i < b.N; i++ {
		cache.InsertTask((i%arrayTaskCacheSize)+1, &values[i%4])
	}

	for i := 0; i < b.N; i++ {
		_, _ = cache.LookupTask((i % arrayTaskCacheSize) + 1)
	}
}

func BenchmarkMapCache(b *testing.B) {
	cache := newMapTaskCache(mapTaskCacheSize)

	for i := 0; i < b.N; i++ {
		cache.InsertTask((i%arrayTaskCacheSize)+1, &values[i%4])
	}

	for i := 0; i < b.N; i++ {
		_, _ = cache.LookupTask((i % arrayTaskCacheSize) + 1)
	}
}

func BenchmarkArrayCacheParallel(b *testing.B) {
	cache := newArrayTaskCache(arrayTaskCacheSize)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.InsertTask((i%arrayTaskCacheSize)+1, &values[i%4])
			i++
		}
	})

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = cache.LookupTask((i % arrayTaskCacheSize) + 1)
			i++
		}
	})
}

func BenchmarkMapCacheParallel(b *testing.B) {
	cache := newMapTaskCache(mapTaskCacheSize)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.InsertTask((i%arrayTaskCacheSize)+1, &values[i%4])
			i++
		}
	})

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = cache.LookupTask((i % arrayTaskCacheSize) + 1)
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
