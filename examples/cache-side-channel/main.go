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
	"os"
	"os/signal"
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

func newSensor() *sensor.Sensor {
	s, err := sensor.NewSensor()
	if err != nil {
		glog.Fatalf("Could not create sensor: %s", err)
	}
	err = s.Start()
	if err != nil {
		glog.Fatalf("Could not start sensor: %s", err)
	}
	return s
}

type counterTracker struct {
	sensor   *sensor.Sensor
	counters []eventCounters
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	glog.Infof("Starting Capsule8 cache side channel detector")
	tracker := counterTracker{
		sensor:   newSensor(),
		counters: make([]eventCounters, runtime.NumCPU()),
	}

	// Create our event group to read LL cache accesses and misses
	//
	// We ask the kernel to sample every llcLoadSampleSize LLC
	// loads. During each sample, the LLC load misses are also
	// recorded, as well as CPU number, PID/TID, and sample time.
	attr := perf.EventAttr{
		SamplePeriod: llcLoadSampleSize,
		SampleType:   perf.PERF_SAMPLE_TID | perf.PERF_SAMPLE_CPU,
	}
	groupID, err := tracker.sensor.Monitor.RegisterHardwareCacheEventGroup(
		[]uint64{
			perfConfigLLCLoads,
			perfConfigLLCLoadMisses,
		},
		tracker.decodeConfigLLCLoads,
		perf.WithEventAttr(&attr))
	if err != nil {
		glog.Fatalf("Could not register hardware cache event: %s", err)
	}

	glog.Info("Monitoring for cache side channels")
	tracker.sensor.Monitor.EnableGroup(groupID)

	signals := make(chan os.Signal)
	signal.Notify(signals, os.Interrupt)
	<-signals
	close(signals)

	glog.Info("Shutting down gracefully")
	tracker.sensor.Monitor.Close()
}

func (t *counterTracker) decodeConfigLLCLoads(
	sample *perf.SampleRecord,
	counters map[uint64]uint64,
	totalTimeElapsed uint64,
	totalTimeRunning uint64,
) (interface{}, error) {
	cpu := sample.CPU
	prevCounters := t.counters[cpu]
	t.counters[cpu] = eventCounters{
		LLCLoads:      counters[perfConfigLLCLoads],
		LLCLoadMisses: counters[perfConfigLLCLoadMisses],
	}

	counterDeltas := eventCounters{
		LLCLoads:      t.counters[cpu].LLCLoads - prevCounters.LLCLoads,
		LLCLoadMisses: t.counters[cpu].LLCLoadMisses - prevCounters.LLCLoadMisses,
	}

	t.alarm(sample, counterDeltas)
	return nil, nil
}

func (t *counterTracker) alarm(
	sample *perf.SampleRecord,
	counters eventCounters,
) {
	LLCLoadMissRate := float32(counters.LLCLoadMisses) /
		float32(counters.LLCLoads)
	if LLCLoadMissRate <= alarmThresholdInfo {
		return
	}

	var fields []string
	fields = append(fields, fmt.Sprintf("LLCLoadMissRate=%v", LLCLoadMissRate))
	fields = append(fields, fmt.Sprintf("pid=%v", sample.Pid))
	fields = append(fields, fmt.Sprintf("tid=%v", sample.Tid))
	fields = append(fields, fmt.Sprintf("cpu=%v", sample.CPU))

	if sample.Pid > 0 {
		task := t.sensor.ProcessCache.LookupTask(int(sample.Pid))
		if ci := t.sensor.ProcessCache.LookupTaskContainerInfo(task); ci != nil {
			fields = append(fields, fmt.Sprintf("container_name=%v", ci.Name))
			fields = append(fields, fmt.Sprintf("container_id=%v", ci.ID))
			fields = append(fields, fmt.Sprintf("container_image=%v", ci.ImageName))
			fields = append(fields, fmt.Sprintf("container_image_id=%v", ci.ImageID))
		}
	}

	message := strings.Join(fields, " ")
	if LLCLoadMissRate > alarmThresholdError {
		glog.Errorf(message)
	} else if LLCLoadMissRate > alarmThresholdWarning {
		glog.Warningf(message)
	} else {
		glog.Infof(message)
	}
}
