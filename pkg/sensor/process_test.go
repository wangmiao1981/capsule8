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
	"testing"
)

const arrayTaskCacheSize = 32768
const mapTaskCacheSize = 32768

var values = []Task{
	{1, 2, "foo", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", "", nil, nil},
	{1, 2, "bar", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", "", nil, nil},
	{1, 2, "baz", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", "", nil, nil},
	{1, 2, "qux", nil, nil, "6e250051f33e0988aa6e549daa6c36de5ddf296bced4f31cf1b8249556f27ed2", nil, 0, 0, "", "", nil, nil},
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
