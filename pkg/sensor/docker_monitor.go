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
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/glog"
)

// ----------------------------------------------------------------------------
// Docker container configuration file format V2
// ----------------------------------------------------------------------------

type dockerConfigState struct {
	Running           bool      `json:"Running"`
	Paused            bool      `json:"Paused"`
	Restarting        bool      `json:"Restarting"`
	OOMKilled         bool      `json:"OOMKilled"`
	RemovalInProgress bool      `json:"RemovalInProgress"`
	Dead              bool      `json:"Dead"`
	Pid               int       `json:"Pid"`
	StartedAt         time.Time `json:"StartedAt"`
	FinishedAt        time.Time `json:"FinishedAt"`
	Health            string    `json:"Health"`
	ExitCode          int       `json:"ExitCode"`
}

type dockerConfigConfig struct {
	// XXX: Fill in as needed ...
	Image string `json:"Image"`
	// XXX: ...
}

type dockerConfigV2 struct {
	// XXX: Fill in as needed ...
	ID     string             `json:"ID"`
	Name   string             `json:"Name"`
	Image  string             `json:"Image"`
	State  dockerConfigState  `json:"State"`
	Config dockerConfigConfig `json:"Config"`
	// XXX: ...
}

const (
	dockerRenameKprobeSymbol    = "sys_renameat"
	dockerRenameKprobeFetchargs = "newname=+0(%cx):string"
	dockerRenameKprobeFilter    = "newname ~ */config.v2.json"

	dockerUnlinkKprobeSymbol    = "sys_unlinkat"
	dockerUnlinkKprobeFetchargs = "pathname=+0(%si):string"
	dockerUnlinkKprobeFilter    = "pathname ~ */config.v2.json"
)

type dockerDeferredActionFn func(sampleID perf.SampleID, filename string)

type dockerDeferredAction struct {
	action   dockerDeferredActionFn
	sampleID perf.SampleID
	filename string
}

// dockerMonitor monitors the system for Docker container events
type dockerMonitor struct {
	sensor       *Sensor
	containerDir string

	scanningLock  sync.Mutex
	scanning      bool
	scanningQueue []dockerDeferredAction
}

// newDockerMonitor creates a new Docker monitor that monitors the specified
// container directory using the specified EventMonitor. When changes occur,
// the specified cache is updated.
func newDockerMonitor(sensor *Sensor, containerDir string) *dockerMonitor {
	d, err := os.Open(containerDir)
	if err != nil {
		glog.Infof("Docker monitoring of %s disabled: %s",
			containerDir, err)
		return nil
	}
	defer d.Close()

	dm := &dockerMonitor{
		sensor:       sensor,
		containerDir: containerDir,
		scanning:     true,
	}

	// Register these probes in an enabled state so that we get the events
	// right away. Otherwise there'll be race conditions as we scan the
	// filesystem for existing containers

	_, err = sensor.monitor.RegisterKprobe(dockerRenameKprobeSymbol, false,
		dockerRenameKprobeFetchargs, dm.decodeRename,
		perf.WithFilter(dockerRenameKprobeFilter),
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Could not register Docker monitor %s kprobe: %s",
			dockerRenameKprobeSymbol, err)
	}

	_, err = sensor.monitor.RegisterKprobe(dockerUnlinkKprobeSymbol, false,
		dockerUnlinkKprobeFetchargs, dm.decodeUnlink,
		perf.WithFilter(dockerUnlinkKprobeFilter),
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Could not register Docker monitor %s kprobe: %s",
			dockerUnlinkKprobeSymbol, err)
	}

	// Scan the filesystem looking for existing containers
	names, err := d.Readdirnames(0)
	if err != nil {
		glog.Fatalf("Could not read directory %s: %s", containerDir, err)
	}
	for _, name := range names {
		configFilename := filepath.Join(containerDir, name, "config.v2.json")
		err = dm.processDockerConfig(perf.SampleID{}, configFilename)
		if err == nil {
			glog.V(2).Infof("{DOCKER} Found existing container %s", name)
		}
	}

	dm.scanningLock.Lock()
	for len(dm.scanningQueue) > 0 {
		queue := dm.scanningQueue
		dm.scanningQueue = nil
		dm.scanningLock.Unlock()
		for _, f := range queue {
			f.action(f.sampleID, f.filename)
		}
		dm.scanningLock.Lock()
	}
	dm.scanning = false
	dm.scanningLock.Unlock()

	return dm
}

func (dm *dockerMonitor) processDockerConfig(
	sampleID perf.SampleID,
	configFilename string,
) error {
	configJSON, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return err
	}
	JSONString := string(configJSON)

	paths := strings.Split(configFilename, "/")
	containerID := paths[len(paths)-2]

	containerInfo := dm.sensor.containerCache.lookupContainer(
		containerID, false)
	if containerInfo != nil && containerInfo.JSONConfig == JSONString {
		// No change; do nothing more
		return nil
	}

	var config dockerConfigV2
	err = json.Unmarshal(configJSON, &config)
	if err != nil {
		glog.V(1).Infof("Could not unmarshal %s: %s", configFilename, err)
		return err
	}

	data := make(map[string]interface{})
	// Update the cache with the newly loaded information
	if config.ID != containerID || containerInfo == nil {
		containerID = config.ID
		containerInfo = dm.sensor.containerCache.lookupContainer(
			containerID, true)
	}
	data["JSONConfig"] = JSONString
	data["Name"] = config.Name
	data["ImageID"] = strings.TrimPrefix(config.Image, "sha256:")
	data["ImageName"] = config.Config.Image
	data["Pid"] = config.State.Pid
	data["ExitCode"] = config.State.ExitCode

	var newState ContainerState
	if !config.State.Running && config.State.StartedAt.IsZero() {
		newState = ContainerStateCreated
	} else if config.State.Restarting {
		newState = ContainerStateRestarting
	} else if config.State.Running && !config.State.StartedAt.IsZero() {
		newState = ContainerStateRunning
	} else if config.State.RemovalInProgress {
		newState = ContainerStateRemoving
	} else if config.State.Paused {
		newState = ContainerStatePaused
	} else if !config.State.Running && !config.State.FinishedAt.IsZero() {
		newState = ContainerStateExited
	}

	data["State"] = newState
	containerInfo.Update(ContainerRuntimeDocker, sampleID, data)

	return nil
}

func (dm *dockerMonitor) processRenameAction(
	sampleID perf.SampleID,
	filename string,
) {
	dm.processDockerConfig(sampleID, filename)
}

func (dm *dockerMonitor) processUnlinkAction(
	sampleID perf.SampleID,
	filename string,
) {
	parts := strings.Split(filename, "/")
	if len(parts) >= 2 {
		containerID := parts[len(parts)-2]
		dm.sensor.containerCache.deleteContainer(containerID, ContainerRuntimeDocker, sampleID)
	}
}

func (dm *dockerMonitor) decodeRename(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	configFilename := data["newname"].(string)
	if !strings.HasPrefix(configFilename, dm.containerDir) {
		return nil, nil
	}

	sampleID := perf.SampleID{
		Time: sample.Time,
		PID:  sample.Pid,
		TID:  sample.Tid,
		CPU:  sample.CPU,
	}

	if dm.scanning {
		dm.scanningLock.Lock()
		if dm.scanning {
			dm.scanningQueue = append(dm.scanningQueue,
				dockerDeferredAction{
					action:   dm.processRenameAction,
					sampleID: sampleID,
					filename: configFilename,
				})
			dm.scanningLock.Unlock()
			return nil, nil
		}
		dm.scanningLock.Unlock()
	}

	dm.processRenameAction(sampleID, configFilename)
	return nil, nil
}

func (dm *dockerMonitor) decodeUnlink(
	sample *perf.SampleRecord,
	data perf.TraceEventSampleData,
) (interface{}, error) {
	configFilename := data["pathname"].(string)
	if !strings.HasPrefix(configFilename, dm.containerDir) {
		return nil, nil
	}

	sampleID := perf.SampleID{
		Time: sample.Time,
		PID:  sample.Pid,
		TID:  sample.Tid,
		CPU:  sample.CPU,
	}

	if dm.scanning {
		dm.scanningLock.Lock()
		if dm.scanning {
			dm.scanningQueue = append(dm.scanningQueue,
				dockerDeferredAction{
					action:   dm.processUnlinkAction,
					sampleID: sampleID,
					filename: configFilename,
				})
			dm.scanningLock.Unlock()
			return nil, nil
		}
		dm.scanningLock.Unlock()
	}

	dm.processUnlinkAction(sampleID, configFilename)
	return nil, nil
}
