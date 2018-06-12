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
	"sync"
	"sync/atomic"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"

	"google.golang.org/genproto/googleapis/rpc/code"
	google_rpc "google.golang.org/genproto/googleapis/rpc/status"
)

type subscription struct {
	sensor          *Sensor
	eventGroupID    int32
	counterGroupIDs []int32
	containerFilter *containerFilter
	eventSinks      map[uint64]*eventSink
	status          []*google_rpc.Status
	dispatchFn      eventSinkDispatchFn
}

func newSubscription(
	sensor *Sensor,
	eventGroupID int32,
	dispatchFn eventSinkDispatchFn,
) *subscription {
	return &subscription{
		sensor:       sensor,
		eventGroupID: eventGroupID,
		dispatchFn:   dispatchFn,
	}
}

type eventSinkDispatchFn func(event *api.TelemetryEvent)
type eventSinkUnregisterFn func(es *eventSink)

type eventSink struct {
	subscription  *subscription
	eventID       uint64
	unregister    eventSinkUnregisterFn
	filter        *expression.Expression
	filterTypes   expression.FieldTypeMap
	containerView api.ContainerEventView
}

func (s *subscription) addEventSink(
	eventID uint64,
	filterExpression *api.Expression,
	filterTypes expression.FieldTypeMap,
) (*eventSink, error) {
	es := &eventSink{
		subscription: s,
		eventID:      eventID,
		filterTypes:  filterTypes,
	}

	if filterExpression != nil {
		expr, err := expression.NewExpression(filterExpression)
		if err != nil {
			return nil, err
		}

		if err = expr.Validate(filterTypes); err != nil {
			return nil, err
		}

		// If this is a valid kernel filter, attempt to set it as a
		// kernel filter. If it is either not a valid kernel filter or
		// it fails to set as a kernel filter, set the filter in the
		// sink to fallback to evaluation via the expression package.
		// The err checking code here looks a little weird, but it is
		// what is intended.
		if err = expr.ValidateKernelFilter(); err == nil {
			err = s.sensor.Monitor.SetFilter(eventID,
				expr.KernelFilterString())
		}
		if err != nil {
			es.filter = expr
		}
	}

	if s.eventSinks == nil {
		s.eventSinks = make(map[uint64]*eventSink)
	}
	s.eventSinks[eventID] = es
	return es, nil
}

func (s *subscription) removeEventSink(es *eventSink) {
	delete(s.eventSinks, es.eventID)
}

func (s *subscription) logStatus(code code.Code, message string) {
	s.status = append(s.status,
		&google_rpc.Status{
			Code:    int32(code),
			Message: message,
		})
}

//
// safeSubscriptionMap
// map[uint64]map[int32]*eventSink
//

type subscriptionMap map[uint64]map[int32]*eventSink

func newSubscriptionMap() subscriptionMap {
	return make(subscriptionMap)
}

type safeSubscriptionMap struct {
	sync.Mutex              // used only by writers
	active     atomic.Value // map[uint64]map[int32]*eventSink
}

func newSafeSubscriptionMap() *safeSubscriptionMap {
	return &safeSubscriptionMap{}
}

func (ssm *safeSubscriptionMap) getMap() subscriptionMap {
	value := ssm.active.Load()
	if value == nil {
		return nil
	}
	return value.(subscriptionMap)
}

func (ssm *safeSubscriptionMap) subscribe(subscr *subscription) {
	ssm.Lock()
	defer ssm.Unlock()

	om := ssm.getMap()
	nm := make(subscriptionMap, len(om)+len(subscr.eventSinks))

	if om != nil {
		for k, v := range om {
			c := make(map[int32]*eventSink, len(v))
			for k2, v2 := range v {
				c[k2] = v2
			}
			nm[k] = c
		}
	}

	for eventID, es := range subscr.eventSinks {
		subscriptionMap, ok := nm[eventID]
		if !ok {
			subscriptionMap = make(map[int32]*eventSink)
			nm[eventID] = subscriptionMap
		}
		subscriptionMap[subscr.eventGroupID] = es
	}

	ssm.active.Store(nm)
}

func (ssm *safeSubscriptionMap) unsubscribe(
	subscr *subscription,
	f func(uint64),
) {
	var (
		deadEventIDs   []uint64
		deadEventSinks []*eventSink
	)
	subscriptionID := subscr.eventGroupID

	ssm.Lock()

	om := ssm.getMap()
	if om != nil {
		nm := make(subscriptionMap, len(om))
		for eventID, v := range om {
			var m map[int32]*eventSink
			for ID, es := range v {
				if ID != subscriptionID {
					if m == nil {
						m = make(map[int32]*eventSink)
					}
					m[ID] = es
				} else if es.unregister != nil {
					deadEventSinks = append(deadEventSinks,
						es)
				}
			}
			if m == nil {
				deadEventIDs = append(deadEventIDs, eventID)
			} else {
				nm[eventID] = m
			}
		}
		ssm.active.Store(nm)
	}

	ssm.Unlock()

	for _, es := range deadEventSinks {
		es.unregister(es)
	}
	if f != nil {
		for _, eventID := range deadEventIDs {
			f(eventID)
		}
	}
}
