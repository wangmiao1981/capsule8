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
	"os"
	"testing"
)

/*

Current benchmark results:

BenchmarkArrayCache-8                   	500000000	         3.18 ns/op
BenchmarkMapCache-8                     	10000000	       152 ns/op
BenchmarkStatCacheMiss-8                	  200000	     11180 ns/op
BenchmarkStatCacheMissParallel-8        	  500000	      3460 ns/op
BenchmarkContainerCacheMiss-8           	  100000	     14729 ns/op
BenchmarkContainerCacheMissParallel-8   	  300000	      5789 ns/op

*/

const arrayTaskCacheSize = 32768
const mapTaskCacheSize = 32768

var values = []Task{
	{1, 2, "foo", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", nil, 0},
	{1, 2, "bar", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", nil, 0},
	{1, 2, "baz", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", nil, 0},
	{1, 2, "qux", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", nil, 0},
}

func TestCaches(t *testing.T) {
	arrayCache := newArrayTaskCache(arrayTaskCacheSize)
	mapCache := newMapTaskCache(mapTaskCacheSize)

	var task *Task

	for i := 0; i < arrayTaskCacheSize; i++ {
		task = arrayCache.LookupTask(i + 1)
		task.ContainerID = values[i%4].ContainerID
	}
	for i := 0; i < mapTaskCacheSize; i++ {
		task = mapCache.LookupTask(i + 1)
		task.ContainerID = values[i%4].ContainerID
	}

	for i := arrayTaskCacheSize - 2; i >= 0; i-- {
		task = arrayCache.LookupTask(i + 1)
		cid := task.ContainerID
		if cid != values[i%4].ContainerID {
			t.Fatalf("Expected %s for pid %d, got %s",
				values[i%4].ContainerID, i, cid)
		}
	}

	for i := mapTaskCacheSize - 2; i >= 0; i-- {
		task = mapCache.LookupTask(i + 1)
		cid := task.ContainerID
		if cid != values[i%4].ContainerID {
			t.Fatalf("Expected %s for pid %d, got %s",
				values[i%4].ContainerID, i, cid)
		}
	}
}

func BenchmarkArrayCache(b *testing.B) {
	cache := newArrayTaskCache(arrayTaskCacheSize)
	for i := 0; i < b.N; i++ {
		_ = cache.LookupTask((i % arrayTaskCacheSize) + 1)
	}
}

func BenchmarkMapCache(b *testing.B) {
	cache := newMapTaskCache(mapTaskCacheSize)
	for i := 0; i < b.N; i++ {
		_ = cache.LookupTask((i % arrayTaskCacheSize) + 1)
	}
}

func BenchmarkStatCacheMiss(b *testing.B) {
	pid := os.Getpid()

	for i := 0; i < b.N; i++ {
		_ = procFS.Stat(pid, pid)
	}
}

func BenchmarkStatCacheMissParallel(b *testing.B) {
	pid := os.Getpid()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = procFS.Stat(pid, pid)
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
