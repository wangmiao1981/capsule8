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

package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/golang/glog"
)

// ValidateTLSConfig validates the TLS credentials from their
// configured paths if the UseTLS variable is true.
func ValidateTLSConfig() error {
	if Sensor.UseTLS {
		crt, err := ioutil.ReadFile(Sensor.TLSServerCertPath)
		if err != nil {
			return fmt.Errorf("could not read sensor certificate: %s", err)
		}
		crtBlock, _ := pem.Decode(crt)
		if crtBlock == nil {
			return fmt.Errorf("failed to decode sensor certificate PEM")
		}
		_, err = x509.ParseCertificate(crtBlock.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing sensor certificate: %s", err)
		}

		key, err := ioutil.ReadFile(Sensor.TLSServerKeyPath)
		if err != nil {
			return fmt.Errorf("could not read sensor key: %s", err)
		}
		keyBlock, _ := pem.Decode(key)
		if keyBlock == nil {
			return fmt.Errorf("failed to decode sensor key PEM")
		}
		_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing sensor key: %s", err)
		}

		ca, err := ioutil.ReadFile(Sensor.TLSCACertPath)
		if err != nil {
			return fmt.Errorf("could not read ca certificate: %s", err)
		}
		caBlock, _ := pem.Decode(ca)
		if caBlock == nil {
			return fmt.Errorf("failed to decode certificate authority PEM")
		}
		_, err = x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing certificate authority: %s", err)
		}

		return nil
	}
	glog.V(1).Infoln("UseTLS set to false, TLS credentials will not be used")
	return nil
}
