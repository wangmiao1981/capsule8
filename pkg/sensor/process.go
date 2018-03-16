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
	"strings"
	"syscall"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"golang.org/x/sys/unix"

	"google.golang.org/genproto/googleapis/rpc/code"
)

const (
	exitSymbol    = "do_exit"
	exitFetchargs = "code=%di:s64"
)

type processFilter struct {
	sensor *Sensor
}

func (f *processFilter) decodeSchedProcessFork(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	ev := f.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	childPid := data["child_pid"].(int32)
	ev.Event = &api.TelemetryEvent_Process{
		Process: &api.ProcessEvent{
			Type:         api.ProcessEventType_PROCESS_EVENT_TYPE_FORK,
			ForkChildPid: childPid,
		},
	}

	if t := f.sensor.ProcessCache.LookupTask(int(childPid)); t != nil {
		ev.GetProcess().ForkChildId = t.ProcessID
	}

	return ev, nil
}

func (f *processFilter) decodeSchedProcessExec(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	ev := f.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	hostPid := data["common_pid"].(int32)
	filename := data["filename"].(string)

	// Get the command-line from the process info cache. If it's not there
	// for whatever reason, fallback to using procfs
	var commandLine []string
	_, l := f.sensor.ProcessCache.LookupTaskAndLeader(int(hostPid))
	if l.CommandLine == nil || len(l.CommandLine) == 0 {
		commandLine = sys.HostProcFS().CommandLine(int(hostPid))
	} else {
		commandLine = l.CommandLine
	}

	processEvent := &api.ProcessEvent{
		Type:            api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
		ExecFilename:    filename,
		ExecCommandLine: commandLine,
	}

	ev.Event = &api.TelemetryEvent_Process{
		Process: processEvent,
	}

	return ev, nil
}

func (f *processFilter) decodeDoExit(sample *perf.SampleRecord, data perf.TraceEventSampleData) (interface{}, error) {
	ev := f.sensor.NewEventFromSample(sample, data)
	if ev == nil {
		return nil, nil
	}

	var exitStatus int
	var exitSignal syscall.Signal
	var coreDumped bool

	// The kprobe fetches the argument 'long code' as an s64. It's
	// the same value returned as a status via waitpid(2).
	code := data["code"].(int64)

	ws := unix.WaitStatus(code)
	if ws.Exited() {
		exitStatus = ws.ExitStatus()
	} else if ws.Signaled() {
		exitSignal = ws.Signal()
		coreDumped = ws.CoreDump()
	}

	ev.Event = &api.TelemetryEvent_Process{
		Process: &api.ProcessEvent{
			Type:           api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
			ExitCode:       int32(code),
			ExitStatus:     uint32(exitStatus),
			ExitSignal:     uint32(exitSignal),
			ExitCoreDumped: coreDumped,
		},
	}

	return ev, nil
}

func processFilterString(wildcard bool, filters map[string]bool) string {
	if wildcard {
		return ""
	}

	parts := make([]string, 0, len(filters))
	for k := range filters {
		parts = append(parts, fmt.Sprintf("(%s)", k))
	}
	return strings.Join(parts, " || ")
}

func rewriteProcessEventFilter(pef *api.ProcessEventFilter) {
	switch pef.Type {
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
		if pef.ExecFilename != nil {
			newExpr := expression.Equal(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilename.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilename = nil
			pef.ExecFilenamePattern = nil
		} else if pef.ExecFilenamePattern != nil {
			newExpr := expression.Like(
				expression.Identifier("filename"),
				expression.Value(pef.ExecFilenamePattern.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExecFilenamePattern = nil
		}
	case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
		if pef.ExitCode != nil {
			newExpr := expression.Equal(
				expression.Identifier("code"),
				expression.Value(pef.ExitCode.Value))
			pef.FilterExpression = expression.LogicalAnd(
				newExpr, pef.FilterExpression)
			pef.ExitCode = nil
		}
	}
}

func registerProcessEvents(
	sensor *Sensor,
	subscr *subscription,
	events []*api.ProcessEventFilter,
) {
	forkFilter := false
	execFilters := make(map[string]bool)
	execWildcard := false
	exitFilters := make(map[string]bool)
	exitWildcard := false

	for _, pef := range events {
		// Translate deprecated fields into an expression
		rewriteProcessEventFilter(pef)

		switch pef.Type {
		case api.ProcessEventType_PROCESS_EVENT_TYPE_FORK:
			forkFilter = true
		case api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC:
			if pef.FilterExpression == nil {
				execWildcard = true
			} else {
				expr, err := expression.NewExpression(pef.FilterExpression)
				if err != nil {
					subscr.logStatus(
						code.Code_INVALID_ARGUMENT,
						fmt.Sprintf("Invalid process exec event filter: %v", err))
					continue
				}
				err = expr.ValidateKernelFilter()
				if err != nil {
					subscr.logStatus(
						code.Code_INVALID_ARGUMENT,
						fmt.Sprintf("Invalid process exec event filter as kernel filter: %v", err))
					continue
				}
				s := expr.KernelFilterString()
				execFilters[s] = true
			}
		case api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT:
			if pef.FilterExpression == nil {
				exitWildcard = true
			} else {
				expr, err := expression.NewExpression(pef.FilterExpression)
				if err != nil {
					subscr.logStatus(
						code.Code_INVALID_ARGUMENT,
						fmt.Sprintf("Invalid process exit event filter: %v", err))
					continue
				}
				err = expr.ValidateKernelFilter()
				if err != nil {
					subscr.logStatus(
						code.Code_INVALID_ARGUMENT,
						fmt.Sprintf("Invalid process exit event filter as kernel filter: %v", err))
					continue
				}
				s := expr.KernelFilterString()
				exitFilters[s] = true
			}
		default:
			subscr.logStatus(
				code.Code_INVALID_ARGUMENT,
				fmt.Sprintf("ProcessEventType %d is invalid", pef.Type))
			continue
		}
	}

	f := processFilter{
		sensor: sensor,
	}

	if forkFilter {
		eventName := "sched/sched_process_fork"
		eventID, err := sensor.Monitor.RegisterTracepoint(eventName,
			f.decodeSchedProcessFork,
			perf.WithEventGroup(subscr.eventGroupID))
		if err != nil {
			subscr.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Could not register tracepoint %s: %v", eventName, err))
		} else {
			subscr.addEventSink(eventID)
		}
	}

	if execWildcard || len(execFilters) > 0 {
		filterString := processFilterString(execWildcard, execFilters)

		eventName := "sched/sched_process_exec"
		eventID, err := sensor.Monitor.RegisterTracepoint(eventName,
			f.decodeSchedProcessExec,
			perf.WithEventGroup(subscr.eventGroupID),
			perf.WithFilter(filterString))
		if err != nil {
			subscr.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Could not register tracepoint %s: %v", eventName, err))
		} else {
			subscr.addEventSink(eventID)
		}
	}

	if exitWildcard || len(exitFilters) > 0 {
		filterString := processFilterString(exitWildcard, exitFilters)

		eventID, err := sensor.Monitor.RegisterKprobe(exitSymbol,
			false, exitFetchargs, f.decodeDoExit,
			perf.WithEventGroup(subscr.eventGroupID),
			perf.WithFilter(filterString))
		if err != nil {
			subscr.logStatus(
				code.Code_UNKNOWN,
				fmt.Sprintf("Could not register probe %s: %v", exitSymbol, err))
		} else {
			subscr.addEventSink(eventID)
		}
	}
}
