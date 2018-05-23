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
	"fmt"

	api "github.com/capsule8/capsule8/api/v0"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
)

type performanceFilter struct {
	sensor *Sensor
}

func (f *performanceFilter) decodePerfCounterEvent(
	sample *perf.SampleRecord,
	counters []perf.CounterEventValue,
	totalTimeEnabled uint64,
	totalTimeRunning uint64,
) (interface{}, error) {
	event := f.sensor.NewEventFromSample(sample, nil)
	if event == nil {
		return nil, nil
	}

	values := make([]*api.PerformanceEventValue, len(counters))
	for i, v := range counters {
		var t api.PerformanceEventType
		switch v.EventType {
		case perf.EventTypeHardware:
			t = api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE
		case perf.EventTypeHardwareCache:
			t = api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE
		case perf.EventTypeSoftware:
			t = api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_SOFTWARE
		}
		values[i] = &api.PerformanceEventValue{
			Type:   t,
			Config: v.Config,
			Value:  v.Value,
		}
	}

	ev := &api.PerformanceEvent{
		TotalTimeEnabled: totalTimeEnabled,
		TotalTimeRunning: totalTimeRunning,
		Values:           values,
	}

	event.Event = &api.TelemetryEvent_Performance{
		Performance: ev,
	}
	return event, nil
}

func registerPerformanceEvents(
	sensor *Sensor,
	subscr *subscription,
	events []*api.PerformanceEventFilter,
) {
	f := performanceFilter{
		sensor: sensor,
	}
	for _, pef := range events {
		attr := perf.EventAttr{
			SampleType: perf.PERF_SAMPLE_CPU | perf.PERF_SAMPLE_RAW,
		}
		switch pef.SampleRateType {
		case api.SampleRateType_SAMPLE_RATE_TYPE_PERIOD:
			if rate, ok := pef.SampleRate.(*api.PerformanceEventFilter_Period); !ok {
				subscr.logStatus(
					code.Code_INVALID_ARGUMENT,
					fmt.Sprintf("Period not properly specified for periodic sample rate"))
				continue
			} else {
				attr.SamplePeriod = rate.Period
				attr.Freq = false
			}
		case api.SampleRateType_SAMPLE_RATE_TYPE_FREQUENCY:
			if rate, ok := pef.SampleRate.(*api.PerformanceEventFilter_Frequency); !ok {
				subscr.logStatus(
					code.Code_INVALID_ARGUMENT,
					fmt.Sprintf("Frequency not properly specified for frequency sample rate"))
				continue
			} else {
				attr.SampleFreq = rate.Frequency
				attr.Freq = true
			}
		default:
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("SampleRateType %d is invalid", pef.SampleRateType))
			continue
		}

		counters := make([]perf.CounterEventGroupMember, 0, len(pef.Events))
		for _, e := range pef.Events {
			m := perf.CounterEventGroupMember{
				Config: e.Config,
			}
			switch e.Type {
			case api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE:
				m.EventType = perf.EventTypeHardware
			case api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE:
				m.EventType = perf.EventTypeHardwareCache
			case api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_SOFTWARE:
				m.EventType = perf.EventTypeSoftware
			default:
				subscr.logStatus(
					code.Code_INVALID_ARGUMENT,
					fmt.Sprintf("PerformanceEventType %d is invalid", e.Type))
				continue
			}
			counters = append(counters, m)
		}

		eventName := fmt.Sprintf("Performance Counters %p", pef)
		groupID, eventID, err := sensor.Monitor.RegisterCounterEventGroup(
			eventName, counters, f.decodePerfCounterEvent,
			perf.WithEventAttr(&attr))
		if err != nil {
			subscr.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Could not register %s performance event: %v",
					eventName, err))
		} else {
			subscr.counterGroupIDs = append(subscr.counterGroupIDs, groupID)
			subscr.addEventSink(eventID)
		}
	}
}
