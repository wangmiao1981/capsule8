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
	"regexp"
	"strings"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var perfTypeMapping = map[int32]expression.ValueType{
	perf.TraceEventFieldTypeString: expression.ValueTypeString,

	perf.TraceEventFieldTypeSignedInt8:  expression.ValueTypeSignedInt8,
	perf.TraceEventFieldTypeSignedInt16: expression.ValueTypeSignedInt16,
	perf.TraceEventFieldTypeSignedInt32: expression.ValueTypeSignedInt32,
	perf.TraceEventFieldTypeSignedInt64: expression.ValueTypeSignedInt64,

	perf.TraceEventFieldTypeUnsignedInt8:  expression.ValueTypeUnsignedInt8,
	perf.TraceEventFieldTypeUnsignedInt16: expression.ValueTypeUnsignedInt16,
	perf.TraceEventFieldTypeUnsignedInt32: expression.ValueTypeUnsignedInt32,
	perf.TraceEventFieldTypeUnsignedInt64: expression.ValueTypeUnsignedInt64,
}

type kprobeFilter struct {
	symbol    string
	onReturn  bool
	arguments map[string]string
	filter    *api.Expression
	sensor    *Sensor
}

var validSymbolRegex = regexp.MustCompile("^[A-Za-z_]{1}[\\w]*$")

func newKprobeFilter(kef *api.KernelFunctionCallFilter) (*kprobeFilter, error) {
	// The symbol must begin with [A-Za-z_] and contain only [A-Za-z0-9_]
	// We do not accept addresses or offsets
	if !validSymbolRegex.MatchString(kef.Symbol) {
		return nil, fmt.Errorf("Kprobe symbol %q is invalid", kef.Symbol)
	}

	filter := &kprobeFilter{
		symbol:    kef.Symbol,
		arguments: kef.Arguments,
		filter:    kef.FilterExpression,
	}

	switch kef.Type {
	case api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_ENTER:
		filter.onReturn = false
	case api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_EXIT:
		filter.onReturn = true
	default:
		return nil, fmt.Errorf("KernelFunctionCallEventType %d is invalid",
			kef.Type)
	}

	return filter, nil
}

func (f *kprobeFilter) decodeKprobe(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	ev := f.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	args := make(map[string]*api.KernelFunctionCallEvent_FieldValue)
	for k, v := range data {
		value := &api.KernelFunctionCallEvent_FieldValue{}
		switch v := v.(type) {
		case []byte:
			value.FieldType = api.KernelFunctionCallEvent_BYTES
			value.Value = &api.KernelFunctionCallEvent_FieldValue_BytesValue{BytesValue: v}
		case string:
			value.FieldType = api.KernelFunctionCallEvent_STRING
			value.Value = &api.KernelFunctionCallEvent_FieldValue_StringValue{StringValue: v}
		case int8:
			value.FieldType = api.KernelFunctionCallEvent_SINT8
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: int64(v)}
		case int16:
			value.FieldType = api.KernelFunctionCallEvent_SINT16
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: int64(v)}
		case int32:
			value.FieldType = api.KernelFunctionCallEvent_SINT32
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: int64(v)}
		case int64:
			value.FieldType = api.KernelFunctionCallEvent_SINT64
			value.Value = &api.KernelFunctionCallEvent_FieldValue_SignedValue{SignedValue: v}
		case uint8:
			value.FieldType = api.KernelFunctionCallEvent_UINT8
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: uint64(v)}
		case uint16:
			value.FieldType = api.KernelFunctionCallEvent_UINT16
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: uint64(v)}
		case uint32:
			value.FieldType = api.KernelFunctionCallEvent_UINT32
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: uint64(v)}
		case uint64:
			value.FieldType = api.KernelFunctionCallEvent_UINT64
			value.Value = &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{UnsignedValue: v}
		}
		args[k] = value
	}

	ev.Event = &api.TelemetryEvent_KernelCall{
		KernelCall: &api.KernelFunctionCallEvent{
			Arguments: args,
		},
	}

	return ev, nil
}

func (f *kprobeFilter) fetchargs() string {
	args := make([]string, 0, len(f.arguments))
	for k, v := range f.arguments {
		args = append(args, fmt.Sprintf("%s=%s", k, v))
	}

	return strings.Join(args, " ")
}

func registerKernelEvents(
	sensor *Sensor,
	subscr *subscription,
	events []*api.KernelFunctionCallFilter,
) {
	for _, kef := range events {
		f, err := newKprobeFilter(kef)
		if err != nil {
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("Invalid kprobe filter %s: %v", kef.Symbol, err))
			continue
		}

		f.sensor = sensor
		eventID, err := sensor.RegisterKprobe(
			f.symbol, f.onReturn, f.fetchargs(),
			f.decodeKprobe,
			perf.WithEventGroup(subscr.eventGroupID))
		if err != nil {
			var loc string
			if f.onReturn {
				loc = "return"
			} else {
				loc = "entry"
			}

			subscr.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Couldn't register kprobe on %s %s [%s]: %v", f.symbol, loc, f.fetchargs(), err))
			continue
		}

		kprobeFields := sensor.Monitor.RegisteredEventFields(eventID)
		filterTypes := make(expression.FieldTypeMap, len(kprobeFields))
		for k, v := range kprobeFields {
			filterTypes[k] = perfTypeMapping[v]
		}

		_, err = subscr.addEventSink(eventID, f.filter, filterTypes)
		if err != nil {
			subscr.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Invalid filter expression for kernel function call filter: %v", err))
			sensor.Monitor.UnregisterEvent(eventID)
		}
	}
}
