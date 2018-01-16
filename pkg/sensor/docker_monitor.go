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

// DockerConfigState is a structure representing the state of a container.
type DockerConfigState struct {
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

// DockerConfigConfig is a structure representing a Docker container's
// configuration.
type DockerConfigConfig struct {
	// XXX: Fill in as needed ...
	Image string `json:"Image"`
	// XXX: ...
}

// DockerConfigV2 is a structure representing a Docker container.
type DockerConfigV2 struct {
	// XXX: Fill in as needed ...
	ID     string             `json:"ID"`
	Name   string             `json:"Name"`
	Image  string             `json:"Image"`
	State  DockerConfigState  `json:"State"`
	Config DockerConfigConfig `json:"Config"`
	// XXX: ...
}

const (
	renameKprobeSymbol    = "sys_renameat"
	renameKprobeFetchargs = "newname=+0(%cx):string"
	renameKprobeFilter    = "newname ~ */config.v2.json"

	unlinkKprobeSymbol    = "sys_unlinkat"
	unlinkKprobeFetchargs = "pathname=+0(%si):string"
	unlinkKprobeFilter    = "pathname ~ */config.v2.json"
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
		glog.V(1).Infof("Docker monitoring of %s disabled: %s",
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

	_, err = sensor.monitor.RegisterKprobe(renameKprobeSymbol, false,
		renameKprobeFetchargs, dm.decodeRename,
		perf.WithFilter(renameKprobeFilter),
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Could not register Docker monitor %s kprobe: %s",
			renameKprobeSymbol, err)
	}

	_, err = sensor.monitor.RegisterKprobe(unlinkKprobeSymbol, false,
		unlinkKprobeFetchargs, dm.decodeUnlink,
		perf.WithFilter(unlinkKprobeFilter),
		perf.WithEventEnabled())
	if err != nil {
		glog.Fatalf("Could not register Docker monitor %s kprobe: %s",
			unlinkKprobeSymbol, err)
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
			glog.V(2).Infof("Found existing container %s", name)
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

	var config DockerConfigV2
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
	containerInfo.Update(sampleID, data)

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
	if len(parts) > 2 {
		containerID := parts[len(parts)-2]
		dm.sensor.containerCache.deleteContainer(containerID, sampleID)
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
