package services

import (
	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/sensor"
	"github.com/golang/glog"
)

// Main is the entrypoint into the sensor functionality and its exposed services
// this creates a new service manager and, if configured to, registeres the
// telemetry and/or profiling services
func Main() {

	manager := NewServiceManager()
	if len(config.Global.ProfilingListenAddr) > 0 {
		service := NewProfilingService(
			config.Global.ProfilingListenAddr)
		manager.RegisterService(service)
	}

	if len(config.Sensor.ListenAddr) > 0 {
		sensor, err := sensor.NewSensor()
		if err != nil {
			glog.Fatalf("Could not create sensor: %s", err.Error())
		}
		if err := sensor.Start(); err != nil {
			glog.Fatalf("Could not start sensor: %s", err.Error())
		}
		defer sensor.Stop()
		service := NewTelemetryService(sensor, config.Sensor.ListenAddr)
		manager.RegisterService(service)
	}

	manager.Run()
}
