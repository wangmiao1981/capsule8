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
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"google.golang.org/genproto/googleapis/rpc/code"
)

var networkAttemptEventTypes = expression.FieldTypeMap{
	"fd": expression.ValueTypeUnsignedInt64,
}

var networkAttemptWithAddressEventTypes = expression.FieldTypeMap{
	"fd":             expression.ValueTypeUnsignedInt64,
	"sa_family":      expression.ValueTypeUnsignedInt16,
	"sin_port":       expression.ValueTypeUnsignedInt16,
	"sin_addr":       expression.ValueTypeUnsignedInt32,
	"sun_path":       expression.ValueTypeString,
	"sin6_port":      expression.ValueTypeUnsignedInt16,
	"sin6_addr_high": expression.ValueTypeUnsignedInt64,
	"sin6_addr_low":  expression.ValueTypeUnsignedInt64,
}

var networkListenAttemptEventTypes = expression.FieldTypeMap{
	"fd":      expression.ValueTypeUnsignedInt64,
	"backlog": expression.ValueTypeUnsignedInt64,
}

var networkResultEventTypes = expression.FieldTypeMap{
	"ret": expression.ValueTypeSignedInt64,
}

const (
	networkKprobeBindSymbol    = "sys_bind"
	networkKprobeBindFetchargs = "fd=%di sa_family=+0(%si):u16 " +
		"sin_port=+2(%si):u16 sin_addr=+4(%si):u32 " +
		"sun_path=+2(%si):string " +
		"sin6_port=+2(%si):u16 sin6_addr_high=+8(%si):u64 sin6_addr_low=+16(%si):u64"

	networkKprobeConnectSymbol    = "sys_connect"
	networkKprobeConnectFetchargs = "fd=%di sa_family=+0(%si):u16 " +
		"sin_port=+2(%si):u16 sin_addr=+4(%si):u32 " +
		"sun_path=+2(%si):string " +
		"sin6_port=+2(%si):u16 sin6_addr_high=+8(%si):u64 sin6_addr_low=+16(%si):u64"

	networkKprobeSendmsgSymbol    = "sys_sendmsg"
	networkKprobeSendmsgFetchargs = "fd=%di sa_family=+0(+0(%si)):u16 " +
		"sin_port=+2(+0(%si)):u16 sin_addr=+4(+0(%si)):u32 " +
		"sun_path=+2(+0(%si)):string " +
		"sin6_port=+2(+0(%si)):u16 sin6_addr_high=+8(+0(%si)):u64 sin6_addr_low=+16(+0(%si)):u64"

	networkKprobeSendtoSymbol    = "sys_sendto"
	networkKprobeSendtoFetchargs = "fd=%di sa_family=+0(%r8):u16 " +
		"sin_port=+2(%r8):u16 sin_addr=+4(%r8):u32 " +
		"sun_path=+2(%r8):string " +
		"sin6_port=+2(%r8):u16 sin6_addr_high=+8(%r8):u64 sin6_addr_low=+16(%r8):u64"
)

type networkFilter struct {
	sensor *Sensor
}

func (f *networkFilter) newNetworkEvent(
	eventType api.NetworkEventType,
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) *api.TelemetryEvent {
	// If this event contains a network address, throw away any family that
	// we do not support without doing the extra work of creating an event
	// just to throw it away
	family, haveFamily := data["sa_family"].(uint16)
	if haveFamily {
		switch family {
		case 1: // AF_LOCAL
			break
		case 2: // AF_INET
			break
		case 10: // AF_INET6
			break
		default:
			return nil
		}
	}

	event := f.sensor.NewEventFromSample(sample, data)
	if event == nil {
		return nil
	}
	event.Event = &api.TelemetryEvent_Network{
		Network: &api.NetworkEvent{
			Type: eventType,
		},
	}
	network := event.Event.(*api.TelemetryEvent_Network).Network

	if haveFamily {
		switch family {
		case 1: // AF_LOCAL
			network.Address = &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
				Address: &api.NetworkAddress_LocalAddress{
					LocalAddress: data["sun_path"].(string),
				},
			}
		case 2: // AF_INET
			network.Address = &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET,
				Address: &api.NetworkAddress_Ipv4Address{
					Ipv4Address: &api.IPv4AddressAndPort{
						Address: &api.IPv4Address{
							Address: data["sin_addr"].(uint32),
						},
						Port: uint32(data["sin_port"].(uint16)),
					},
				},
			}
		case 10: // AF_INET6
			network.Address = &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET6,
				Address: &api.NetworkAddress_Ipv6Address{
					Ipv6Address: &api.IPv6AddressAndPort{
						Address: &api.IPv6Address{
							High: data["sin6_addr_high"].(uint64),
							Low:  data["sin6_addr_low"].(uint64),
						},
						Port: uint32(data["sin6_port"].(uint16)),
					},
				},
			}
		default:
			// This shouldn't be reachable
			return nil
		}
	}

	if fd, ok := data["fd"]; ok {
		network.Sockfd = fd.(uint64)
	}

	if ret, ok := data["ret"]; ok {
		network.Result = ret.(int64)
	}

	return event
}

func (f *networkFilter) decodeSysEnterAccept(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_ATTEMPT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysExitAccept(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_RESULT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysBind(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_ATTEMPT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysExitBind(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_RESULT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysConnect(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_ATTEMPT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysExitConnect(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_RESULT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysEnterListen(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT, sample, data)

	network := event.Event.(*api.TelemetryEvent_Network).Network
	network.Backlog = data["backlog"].(uint64)

	return event, nil
}

func (f *networkFilter) decodeSysExitListen(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_RESULT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysEnterRecvfrom(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_ATTEMPT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysExitRecvfrom(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_RESULT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysSendto(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_ATTEMPT, sample, data)
	return event, nil
}

func (f *networkFilter) decodeSysExitSendto(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	event := f.newNetworkEvent(api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_RESULT, sample, data)
	return event, nil
}

type networkFilterItem struct {
	filter   *api.Expression
	wildcard bool
}

func (nfi *networkFilterItem) add(nef *api.NetworkEventFilter) {
	if nef.FilterExpression == nil {
		nfi.wildcard = true
		nfi.filter = nil
	} else if nfi.wildcard == false {
		nfi.filter = expression.LogicalOr(nfi.filter,
			nef.FilterExpression)
	}
}

type networkFilterSet struct {
	acceptAttemptFilters   networkFilterItem
	acceptResultFilters    networkFilterItem
	bindAttemptFilters     networkFilterItem
	bindResultFilters      networkFilterItem
	connectAttemptFilters  networkFilterItem
	connectResultFilters   networkFilterItem
	listenAttemptFilters   networkFilterItem
	listenResultFilters    networkFilterItem
	sendtoAttemptFilters   networkFilterItem
	sendtoResultFilters    networkFilterItem
	recvfromAttemptFilters networkFilterItem
	recvfromResultFilters  networkFilterItem
}

func (nfs *networkFilterSet) add(
	subscr *subscription,
	nef *api.NetworkEventFilter,
) {
	switch nef.Type {
	case api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_ATTEMPT:
		nfs.acceptAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_RESULT:
		nfs.acceptResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_ATTEMPT:
		nfs.bindAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_RESULT:
		nfs.bindResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_ATTEMPT:
		nfs.connectAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_RESULT:
		nfs.connectResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT:
		nfs.listenAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_RESULT:
		nfs.listenResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_ATTEMPT:
		nfs.recvfromAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_RESULT:
		nfs.recvfromResultFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_ATTEMPT:
		nfs.sendtoAttemptFilters.add(nef)
	case api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_RESULT:
		nfs.sendtoResultFilters.add(nef)
	default:
		subscr.logStatus(
			code.Code_INVALID_ARGUMENT,
			fmt.Sprintf("Invalid NetworkEventType %d", nef.Type))
	}
}

func registerEvent(
	sensor *Sensor,
	subscr *subscription,
	name string,
	fn perf.TraceEventDecoderFn,
	filter networkFilterItem,
	filterTypes expression.FieldTypeMap,
) {
	if !filter.wildcard && filter.filter == nil {
		return
	}

	eventID, err := sensor.Monitor.RegisterTracepoint(name, fn,
		perf.WithEventGroup(subscr.eventGroupID))
	if err != nil {
		subscr.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Could not register tracepoint %s: %v", name, err))
		return
	}

	_, err = subscr.addEventSink(eventID, filter.filter, filterTypes)
	if err != nil {
		subscr.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Invalid filter expression for network filter: %v", err))
		sensor.Monitor.UnregisterEvent(eventID)
	}
}

func registerKprobe(
	sensor *Sensor,
	subscr *subscription,
	symbol string,
	fetchargs string,
	fn perf.TraceEventDecoderFn,
	filter networkFilterItem,
	filterTypes expression.FieldTypeMap,
) {
	if !filter.wildcard && filter.filter == nil {
		return
	}

	eventID, err := sensor.RegisterKprobe(symbol, false, fetchargs, fn,
		perf.WithEventGroup(subscr.eventGroupID))
	if err != nil {
		subscr.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Could not register network kprobe %s: %v", symbol, err))
		return
	}

	_, err = subscr.addEventSink(eventID, filter.filter, filterTypes)
	if err != nil {
		subscr.logStatus(
			code.Code_UNKNOWN,
			fmt.Sprintf("Invalid filter expression for network filter: %v", err))
		sensor.Monitor.UnregisterEvent(eventID)
	}
}

func registerNetworkEvents(
	sensor *Sensor,
	subscr *subscription,
	events []*api.NetworkEventFilter,
) {
	nfs := networkFilterSet{}
	for _, nef := range events {
		nfs.add(subscr, nef)
	}

	f := networkFilter{
		sensor: sensor,
	}

	registerEvent(sensor, subscr, "syscalls/sys_enter_accept", f.decodeSysEnterAccept, nfs.acceptAttemptFilters, networkAttemptEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_exit_accept", f.decodeSysExitAccept, nfs.acceptResultFilters, networkResultEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_enter_accept4", f.decodeSysEnterAccept, nfs.acceptAttemptFilters, networkAttemptEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_exit_accept4", f.decodeSysExitAccept, nfs.acceptResultFilters, networkResultEventTypes)

	registerKprobe(sensor, subscr, networkKprobeBindSymbol, networkKprobeBindFetchargs, f.decodeSysBind, nfs.bindAttemptFilters, networkAttemptWithAddressEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_exit_bind", f.decodeSysExitBind, nfs.bindResultFilters, networkResultEventTypes)

	registerKprobe(sensor, subscr, networkKprobeConnectSymbol, networkKprobeConnectFetchargs, f.decodeSysConnect, nfs.connectAttemptFilters, networkAttemptWithAddressEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_exit_connect", f.decodeSysExitConnect, nfs.connectResultFilters, networkResultEventTypes)

	registerEvent(sensor, subscr, "syscalls/sys_enter_listen", f.decodeSysEnterListen, nfs.listenAttemptFilters, networkListenAttemptEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_exit_listen", f.decodeSysExitListen, nfs.listenResultFilters, networkResultEventTypes)

	// There are two additional system calls added in Linux 3.0 that are of
	// interest, but there's no way to get all of the data without eBPF
	// support, so don't bother with them for now.

	registerEvent(sensor, subscr, "syscalls/sys_enter_recvfrom", f.decodeSysEnterRecvfrom, nfs.recvfromAttemptFilters, networkAttemptEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_enter_recvmsg", f.decodeSysEnterRecvfrom, nfs.recvfromAttemptFilters, networkAttemptEventTypes)

	registerEvent(sensor, subscr, "syscalls/sys_exit_recvfrom", f.decodeSysExitRecvfrom, nfs.recvfromResultFilters, networkResultEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_exit_recvmsg", f.decodeSysExitRecvfrom, nfs.recvfromResultFilters, networkResultEventTypes)

	registerKprobe(sensor, subscr, networkKprobeSendmsgSymbol, networkKprobeSendmsgFetchargs, f.decodeSysSendto, nfs.sendtoAttemptFilters, networkAttemptWithAddressEventTypes)
	registerKprobe(sensor, subscr, networkKprobeSendtoSymbol, networkKprobeSendtoFetchargs, f.decodeSysSendto, nfs.sendtoAttemptFilters, networkAttemptWithAddressEventTypes)

	registerEvent(sensor, subscr, "syscalls/sys_exit_sendmsg", f.decodeSysExitSendto, nfs.sendtoResultFilters, networkResultEventTypes)
	registerEvent(sensor, subscr, "syscalls/sys_exit_sendto", f.decodeSysExitSendto, nfs.sendtoResultFilters, networkResultEventTypes)
}
