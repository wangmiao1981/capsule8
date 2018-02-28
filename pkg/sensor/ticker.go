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
	"time"

	api "github.com/capsule8/capsule8/api/v0"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/glog"
)

var tickerEventTypes = expression.FieldTypeMap{
	"seconds":     int32(api.ValueType_SINT64),
	"nanoseconds": int32(api.ValueType_SINT64),
}

type tickerFilter struct {
	sensor *Sensor
}

func (t *tickerFilter) decodeTickerEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	e := t.sensor.NewEvent()
	e.Event = &api.TelemetryEvent_Ticker{
		Ticker: &api.TickerEvent{
			Seconds:     data["seconds"].(int64),
			Nanoseconds: data["nanoseconds"].(int64),
		},
	}
	return e, nil
}

func registerTimerEvents(
	sensor *Sensor,
	groupID int32,
	eventMap subscriptionMap,
	events []*api.TickerEventFilter,
) {
	f := tickerFilter{sensor: sensor}
	eventID, err := sensor.Monitor.RegisterExternalEvent("ticker",
		f.decodeTickerEvent, tickerEventTypes)
	if err != nil {
		glog.V(1).Infof("Could not register ticker event: %v", err)
		return
	}

	done := make(chan struct{})
	ntickers := 0
	for _, e := range events {
		if e.Interval <= 0 {
			continue
		}
		ticker := time.NewTicker(time.Duration(e.Interval))
		ntickers++

		go func() {
			for {
				select {
				case <-done:
					ticker.Stop()
					return
				case <-ticker.C:
					monoNow := sys.CurrentMonotonicRaw()
					sampleID := perf.SampleID{
						Time: uint64(monoNow),
					}
					now := time.Now()
					data := perf.TraceEventSampleData{
						"seconds":     int64(now.Unix()),
						"nanoseconds": int64(now.UnixNano()),
					}
					sensor.Monitor.EnqueueExternalSample(
						eventID, sampleID, data)
				}
			}
		}()
	}
	if ntickers == 0 {
		sensor.Monitor.UnregisterEvent(eventID)
		return
	}

	s := eventMap.subscribe(eventID)
	s.unregister = func(eventID uint64, s *subscription) {
		sensor.Monitor.UnregisterEvent(eventID)
		close(done)
	}
}
