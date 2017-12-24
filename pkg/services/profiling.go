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

package services

import (
	"net/http"

	// Include pprof
	_ "net/http/pprof"

	"golang.org/x/net/context"

	"github.com/golang/glog"
)

// ProfilingService is a service that returns profiling information via a
// HTTP server.
type ProfilingService struct {
	server *http.Server

	address string
}

// NewProfilingService creates a new ProfilingService instance bound to
// a specified address.
func NewProfilingService(address string) *ProfilingService {
	return &ProfilingService{
		address: address,
	}
}

// Name returns a human-readable name for a ProfilingService.
func (ps *ProfilingService) Name() string {
	return "Profiling HTTP endpoint"
}

// Serve runs a ProfilingService. It sets up the HTTP endpoint and services
// requests until the service is stopped. It runs on the calling Goroutine.
func (ps *ProfilingService) Serve() error {
	glog.V(1).Infof("Serving profiling HTTP endpoints on %s",
		ps.address)

	ps.server = &http.Server{
		Addr: ps.address,
	}

	err := ps.server.ListenAndServe()
	if err != nil {
		glog.Errorf("Profiling HTTP error: %s", err)
	}

	return err
}

// Stop stops a running ProfilingService.
func (ps *ProfilingService) Stop() {
	ps.server.Shutdown(context.Background())
}
