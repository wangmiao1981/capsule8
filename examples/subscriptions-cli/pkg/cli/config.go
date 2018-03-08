package cli

import (
	"github.com/golang/glog"
	"github.com/kelseyhightower/envconfig"
)

var globalConfig struct {
	SensorAddress string `split_words:"true" default:"unix:/var/run/capsule8/sensor.sock"`
}

func init() {
	err := envconfig.Process("CAPSULE8", &globalConfig)
	if err != nil {
		glog.Fatal(err)
	}
}
