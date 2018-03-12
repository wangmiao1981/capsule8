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

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
	google_rpc "google.golang.org/genproto/googleapis/rpc/status"
)

var chargenEventTypes = expression.FieldTypeMap{
	"index":      int32(api.ValueType_UINT64),
	"characters": int32(api.ValueType_STRING),
}

type chargenFilter struct {
	sensor *Sensor
}

func (c *chargenFilter) decodeChargenEvent(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	e := c.sensor.NewEvent()
	e.Event = &api.TelemetryEvent_Chargen{
		Chargen: &api.ChargenEvent{
			Index:      data["index"].(uint64),
			Characters: data["characters"].(string),
		},
	}

	return e, nil
}

func generateCharacters(start, length uint64) string {
	bytes := make([]byte, length)
	for i := uint64(0); i < length; i++ {
		bytes[i] = ' ' + byte((start+i)%95)
	}
	return string(bytes)
}

func registerChargenEvents(
	sensor *Sensor,
	groupID int32,
	eventMap subscriptionMap,
	events []*api.ChargenEventFilter,
) []*google_rpc.Status {
	var status []*google_rpc.Status

	f := chargenFilter{sensor: sensor}
	eventID, err := sensor.Monitor.RegisterExternalEvent("chargen",
		f.decodeChargenEvent, chargenEventTypes)
	if err != nil {
		status = append(status,
			&google_rpc.Status{
				Code:    int32(code.Code_UNKNOWN),
				Message: fmt.Sprintf("Could not register chargen event: %v", err),
			})
		return status
	}

	done := make(chan struct{})
	nchargens := 0
	for _, e := range events {
		// XXX there should be a maximum bound here too ...
		if e.Length == 0 || e.Length > 1<<16 {
			status = append(status,
				&google_rpc.Status{
					Code:    int32(code.Code_INVALID_ARGUMENT),
					Message: fmt.Sprintf("Chargen length out of range (%d)", e.Length),
				})
			continue
		}
		nchargens++

		go func() {
			index := uint64(0)
			length := e.Length
			for {
				select {
				case <-done:
					return
				default:
					monoNow := sys.CurrentMonotonicRaw()
					sampleID := perf.SampleID{
						Time: uint64(monoNow),
					}
					s := generateCharacters(index, length)
					data := perf.TraceEventSampleData{
						"index":      index,
						"characters": s,
					}
					index += length
					sensor.Monitor.EnqueueExternalSample(
						eventID, sampleID, data)
				}
			}
		}()
	}
	if nchargens == 0 {
		sensor.Monitor.UnregisterEvent(eventID)
	} else {
		s := eventMap.subscribe(eventID)
		s.unregister = func(eventID uint64, s *subscription) {
			sensor.Monitor.UnregisterEvent(eventID)
			close(done)
		}
	}

	return status
}
