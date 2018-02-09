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

package main

import (
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/capsule8/capsule8/pkg/sensor"

	"github.com/capsule8/capsule8/pkg/sys/perf"
	"github.com/golang/glog"
)

const (
	// How many cache loads to sample on. After each sample period
	// of this many cache loads, the cache miss rate is calculated
	// and examined. This value tunes the trade-off between CPU
	// load and detection accuracy.
	llcLoadSampleSize = 10000

	// Alarm thresholds as cache miss rates (between 0 and 1).
	// These values tune the trade-off between false negatives and
	// false positives.
	alarmThresholdInfo    = 0.97
	alarmThresholdWarning = 0.98
	alarmThresholdError   = 0.99

	// perf_event_attr config value for LL cache loads
	perfConfigLLCLoads = perf.PERF_COUNT_HW_CACHE_LL |
		(perf.PERF_COUNT_HW_CACHE_OP_READ << 8) |
		(perf.PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16)

	// perf_event_attr config value for LL cache misses
	perfConfigLLCLoadMisses = perf.PERF_COUNT_HW_CACHE_LL |
		(perf.PERF_COUNT_HW_CACHE_OP_READ << 8) |
		(perf.PERF_COUNT_HW_CACHE_RESULT_MISS << 16)
)

type eventCounters struct {
	LLCLoads      uint64
	LLCLoadMisses uint64
}

var cpuCounters []eventCounters

func newSensor() *sensor.Sensor {
	s, err := sensor.NewSensor()
	if err != nil {
		glog.Fatal("Could not create sensor: ", err.Error())
	}
	if err := s.Start(); err != nil {
		glog.Fatal("Could not start sensor: ", err.Error())
	}
	return s
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	glog.Infof("Starting Capsule8 sensor")
	sensor := newSensor()

	glog.Infof("Starting Capsule8 cache side channel detector")

	//
	// Create our event group to read LL cache accesses and misses
	//
	// We ask the kernel to sample every llcLoadSampleSize LLC
	// loads. During each sample, the LLC load misses are also
	// recorded, as well as CPU number, PID/TID, and sample time.
	//
	eventGroup := []*perf.EventAttr{}

	ea := &perf.EventAttr{
		Disabled: true,
		Type:     perf.PERF_TYPE_HW_CACHE,
		Config:   perfConfigLLCLoads,
		SampleType: perf.PERF_SAMPLE_CPU | perf.PERF_SAMPLE_STREAM_ID |
			perf.PERF_SAMPLE_TID | perf.PERF_SAMPLE_READ | perf.PERF_SAMPLE_TIME,
		ReadFormat:   perf.PERF_FORMAT_GROUP | perf.PERF_FORMAT_ID,
		Pinned:       true,
		SamplePeriod: llcLoadSampleSize,
		WakeupEvents: 1,
	}
	eventGroup = append(eventGroup, ea)

	ea = &perf.EventAttr{
		Disabled: true,
		Type:     perf.PERF_TYPE_HW_CACHE,
		Config:   perfConfigLLCLoadMisses,
	}
	eventGroup = append(eventGroup, ea)

	eg, err := perf.NewEventGroup(eventGroup)
	if err != nil {
		glog.Fatal(err)
	}

	//
	// Open the event group on all CPUs
	//
	err = eg.Open()
	if err != nil {
		glog.Fatal(err)
	}

	// Allocate counters per CPU
	cpuCounters = make([]eventCounters, runtime.NumCPU())

	glog.Info("Monitoring for cache side channels")
	eg.Run(func(sample perf.Sample) {
		sr, ok := sample.Record.(*perf.SampleRecord)
		if ok {
			onSample(sensor, sr, eg.EventAttrsByID)
		}
	})
}

func onSample(sensor *sensor.Sensor, sr *perf.SampleRecord, eventAttrMap map[uint64]*perf.EventAttr) {
	var counters eventCounters

	// The sample record contains all values in the event group,
	// tagged with their event ID
	for _, v := range sr.V.Values {
		ea := eventAttrMap[v.ID]

		if ea.Config == perfConfigLLCLoads {
			counters.LLCLoads = v.Value
		} else if ea.Config == perfConfigLLCLoadMisses {
			counters.LLCLoadMisses = v.Value
		}
	}

	cpu := sr.CPU
	prevCounters := cpuCounters[cpu]
	cpuCounters[cpu] = counters

	counterDeltas := eventCounters{
		LLCLoads:      counters.LLCLoads - prevCounters.LLCLoads,
		LLCLoadMisses: counters.LLCLoadMisses - prevCounters.LLCLoadMisses,
	}

	alarm(sensor, sr, counterDeltas)
}

func alarm(s *sensor.Sensor, sr *perf.SampleRecord, counters eventCounters) {
	LLCLoadMissRate := float32(counters.LLCLoadMisses) / float32(counters.LLCLoads)

	var fields []string
	fields = append(fields, fmt.Sprintf("LLCLoadMissRate=%v", LLCLoadMissRate))
	fields = append(fields, fmt.Sprintf("pid=%v", sr.Pid))
	fields = append(fields, fmt.Sprintf("tid=%v", sr.Tid))
	fields = append(fields, fmt.Sprintf("cpu=%v", sr.CPU))

	if task, ok := s.ProcessCache.LookupTask(int(sr.Pid)); ok {
		containerInfo := s.ProcessCache.LookupTaskContainerInfo(task)
		if containerInfo != nil {
			fields = append(fields, fmt.Sprintf("container_name=%v", containerInfo.Name))
			fields = append(fields, fmt.Sprintf("container_id=%v", containerInfo.ID))
			fields = append(fields, fmt.Sprintf("container_image=%v", containerInfo.ImageName))
			fields = append(fields, fmt.Sprintf("container_image_id=%v", containerInfo.ImageID))
		}
	}

	message := strings.Join(fields, " ")

	if LLCLoadMissRate > alarmThresholdError {
		glog.Errorf(message)
	} else if LLCLoadMissRate > alarmThresholdWarning {
		glog.Warningf(message)
	} else if LLCLoadMissRate > alarmThresholdInfo {
		glog.Infof(message)
	}
}
