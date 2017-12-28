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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateTLS(t *testing.T) {
	crtPath, keyPath, caPath, falsePath := createTLSFiles(t)

	// Remove all newly created files after testing
	defer os.Remove(crtPath)
	defer os.Remove(keyPath)
	defer os.Remove(caPath)
	defer os.Remove(falsePath)

	var testTLSObjects = []struct {
		tls   bool
		crt   string
		key   string
		ca    string
		valid bool
	}{
		{
			tls:   true,
			crt:   crtPath,
			key:   keyPath,
			ca:    caPath,
			valid: true,
		},
		{
			tls:   true,
			crt:   falsePath,
			key:   keyPath,
			ca:    caPath,
			valid: false,
		},
		{
			tls:   true,
			crt:   crtPath,
			key:   falsePath,
			ca:    caPath,
			valid: false,
		},
		{
			tls:   true,
			crt:   crtPath,
			key:   keyPath,
			ca:    falsePath,
			valid: false,
		},
		{
			tls:   false,
			crt:   falsePath,
			key:   falsePath,
			ca:    falsePath,
			valid: true,
		},
	}

	for _, testObj := range testTLSObjects {
		Sensor.UseTLS = testObj.tls
		Sensor.TLSServerCertPath = testObj.crt
		Sensor.TLSServerKeyPath = testObj.key
		Sensor.TLSCACertPath = testObj.ca

		if err := ValidateTLSConfig(); (err == nil) != testObj.valid {
			t.Errorf("TLS credentials incorrectly validated: %+v %+v", testObj, err)
		}
	}
}

func createTLSFiles(t *testing.T) (crtPath, keyPath, caPath, falsePath string) {
	workingDirectory, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		t.Fatalf("failed to get working directory: %s", err)
	}

	var testDirectory = fmt.Sprintf("%s/capsule8/tls", workingDirectory)
	err = os.MkdirAll(testDirectory, 0755)
	if err != nil {
		t.Fatalf("failed to create directory capsule8/tls/: %s", err)
	}

	var fileMode = os.FileMode(0664)
	crtPath = fmt.Sprintf("%s/server.crt", testDirectory)
	keyPath = fmt.Sprintf("%s/server.key", testDirectory)
	caPath = fmt.Sprintf("%s/ca.crt", testDirectory)
	falsePath = fmt.Sprintf("%s/false.crt", testDirectory)

	var crt = `
-----BEGIN CERTIFICATE-----
MIIDRDCCAiygAwIBAgIJAJgVaCXvC6HkMA0GCSqGSIb3DQEBBQUAMB8xHTAbBgNV
BAMTFGt1YmVhZG0ta2V5cGlucy10ZXN0MCAXDTE3MDcwNTE3NDMxMFoYDzIxMTcw
NjExMTc0MzEwWjAfMR0wGwYDVQQDExRrdWJlYWRtLWtleXBpbnMtdGVzdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0ba8mHU9UtYlzM1Own2Fk/XGjR
J4uJQvSeGLtz1hID1IA0dLwruvgLCPadXEOw/f/IWIWcmT+ZmvIHZKa/woq2iHi5
+HLhXs7aG4tjKGLYhag1hLjBI7icqV7ovkjdGAt9pWkxEzhIYClFMXDjKpMSynu+
YX6nZ9tic1cOkHmx2yiZdMkuriRQnpTOa7bb03OC1VfGl7gHlOAIYaj4539WCOr8
+ACTUMJUFEHcRZ2o8a/v6F9GMK+7SC8SJUI+GuroXqlMAdhEv4lX5Co52enYaClN
+D9FJLRpBv2YfiCQdJRaiTvCBSxEFz6BN+PtP5l2Hs703ZWEkOqCByM6HV8CAwEA
AaOBgDB+MB0GA1UdDgQWBBRQgUX8MhK2rWBWQiPHWcKzoWDH5DBPBgNVHSMESDBG
gBRQgUX8MhK2rWBWQiPHWcKzoWDH5KEjpCEwHzEdMBsGA1UEAxMUa3ViZWFkbS1r
ZXlwaW5zLXRlc3SCCQCYFWgl7wuh5DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
BQUAA4IBAQCaAUif7Pfx3X0F08cxhx8/Hdx4jcJw6MCq6iq6rsXM32ge43t8OHKC
pJW08dk58a3O1YQSMMvD6GJDAiAfXzfwcwY6j258b1ZlI9Ag0VokvhMl/XfdCsdh
AWImnL1t4hvU5jLaImUUMlYxMcSfHBGAm7WJIZ2LdEfg6YWfZh+WGbg1W7uxLxk6
y4h5rWdNnzBHWAGf7zJ0oEDV6W6RSwNXtC0JNnLaeIUm/6xdSddJlQPwUv8YH4jX
c1vuFqTnJBPcb7W//R/GI2Paicm1cmns9NLnPR35exHxFTy+D1yxmGokpoPMdife
aH+sfuxT8xeTPb3kjzF9eJTlnEquUDLM
-----END CERTIFICATE-----
`
	var key = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA249XwEo9k4tM8fMxV7zxOhcrP+WvXn917koM5Qr2ZXs4vo26
e4ytdlrV0bQ9SlcLpQVSYjIxNfhTZdDt+ecIzshKuv1gKIxbbLQMOuK1eA/4HALy
EkFgmS/tleLJrhc65tKPMGD+pKQ/xhmzRuCG51RoiMgbQxaCyYxGfNLpLAZK9L0T
ctv9a0mJmGIYnIOQM4kC1A1I1n3EsXMWmeJUj7OTh/AjjCnMnkgvKT2tpKxYQ59P
gDgU8Ssc7RDSmSkLxnrv+OrN80j6xrw0OjEiB4Ycr0PqfzZcvy8efTtFQ/Jnc4Bp
1zUtFXt7+QeevePtQ2EcyELXE0i63T1CujRMWwIDAQABAoIBAHJx8GqyCBDNbqk7
e7/hI9iE1S10Wwol5GH2RWxqX28cYMKq+8aE2LI1vPiXO89xOgelk4DN6urX6xjK
ZBF8RRIMQy/e/O2F4+3wl+Nl4vOXV1u6iVXMsD6JRg137mqJf1Fr9elg1bsaRofL
Q7CxPoB8dhS+Qb+hj0DhlqhgA9zG345CQCAds0ZYAZe8fP7bkwrLqZpMn7Dz9WVm
++YgYYKjuE95kPuup/LtWfA9rJyE/Fws8/jGvRSpVn1XglMLSMKhLd27sE8ZUSV0
2KUzbfRGE0+AnRULRrjpYaPu0XQ2JjdNvtkjBnv27RB89W9Gklxq821eH1Y8got8
FZodjxECgYEA93pz7AQZ2xDs67d1XLCzpX84GxKzttirmyj3OIlxgzVHjEMsvw8v
sjFiBU5xEEQDosrBdSknnlJqyiq1YwWG/WDckr13d8G2RQWoySN7JVmTQfXcLoTu
YGRiiTuoEi3ab3ZqrgGrFgX7T/cHuasbYvzCvhM2b4VIR3aSxU2DTUMCgYEA4x7J
T/ErP6GkU5nKstu/mIXwNzayEO1BJvPYsy7i7EsxTm3xe/b8/6cYOz5fvJLGH5mT
Q8YvuLqBcMwZardrYcwokD55UvNLOyfADDFZ6l3WntIqbA640Ok2g1X4U8J09xIq
ZLIWK1yWbbvi4QCeN5hvWq47e8sIj5QHjIIjRwkCgYEAyNqjltxFN9zmzPDa2d24
EAvOt3pYTYBQ1t9KtqImdL0bUqV6fZ6PsWoPCgt+DBuHb+prVPGP7Bkr/uTmznU/
+AlTO+12NsYLbr2HHagkXE31DEXE7CSLa8RNjN/UKtz4Ohq7vnowJvG35FCz/mb3
FUHbtHTXa2+bGBUOTf/5Hw0CgYBxw0r9EwUhw1qnUYJ5op7OzFAtp+T7m4ul8kCa
SCL8TxGsgl+SQ34opE775dtYfoBk9a0RJqVit3D8yg71KFjOTNAIqHJm/Vyyjc+h
i9rJDSXiuczsAVfLtPVMRfS0J9QkqeG4PIfkQmVLI/CZ2ZBmsqEcX+eFs4ZfPLun
Qsxe2QKBgGuPilIbLeIBDIaPiUI0FwU8v2j8CEQBYvoQn34c95hVQsig/o5z7zlo
UsO0wlTngXKlWdOcCs1kqEhTLrstf48djDxAYAxkw40nzeJOt7q52ib/fvf4/UBy
X024wzbiw1q07jFCyfQmODzURAx1VNT7QVUMdz/N8vy47/H40AZJ
-----END RSA PRIVATE KEY-----
`
	var ca = `
-----BEGIN CERTIFICATE-----
MIID9jCCAt6gAwIBAgIJAN5MXZDic7qYMA0GCSqGSIb3DQEBBQUAMFkxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMTCXRlc3RDZXJ0MjAgFw0xNzA3MjQxNjA0
MDFaGA8yMTE3MDYzMDE2MDQwMVowWTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNv
bWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAG
A1UEAxMJdGVzdENlcnQyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0brwpJYN2ytPWzRBtZSVc3dhkQlA59AzxzqeLLkano0Pxo9NIc3T/y58nnRI8uaS
I1P7BzUfJTiUEvmAtX8NggqKK4ld/gPrU+IRww1CUYS4KCkA/0d0ctPy0JwBCjD+
b57G3rmNE8c+0jns6J96ZzNtqmv6N+ZlFBAXm1p4S+k0kGi5+hoQ6H7SYXjk2lG+
r/8jPQEjy/NSdw1dcCA0Nc6o+hPr32927dS6J9KOhBeXNYUNdbuDDmroM9/gN2e/
YMSA1olLeDPQ7Xvhk0PIyEDnHh83AffPCx5yM3htVRGddjIsPAVUJEL3z5leJtxe
fzyPghOhHJY0PXqznDQTcwIDAQABo4G+MIG7MB0GA1UdDgQWBBRP0IJqv/5rQ4Uf
SByl77dJeEapRDCBiwYDVR0jBIGDMIGAgBRP0IJqv/5rQ4UfSByl77dJeEapRKFd
pFswWTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoT
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAxMJdGVzdENlcnQyggkA
3kxdkOJzupgwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEA0RIMHc10
wHHPMh9UflqBgDMF7gfbOL0juJfGloAOcohWWfMZBBJ0CQKMy3xRyoK3HmbW1eeb
iATjesw7t4VEAwf7mgKAd+eTfWYB952uq5qYJ2TI28mSofEq1Wz3RmrNkC1KCBs1
u+YMFGwyl6necV9zKCeiju4jeovI1GA38TvH7MgYln6vMJ+FbgOXj7XCpek7dQiY
KGaeSSH218mGNQaWRQw2Sm3W6cFdANoCJUph4w18s7gjtFpfV63s80hXRps+vEyv
jEQMEQpG8Ss7HGJLGLBw/xAmG0e//XS/o2dDonbGbvzToFByz8OGxjMhk6yV6hdd
+iyvsLAw/MYMSA==
-----END CERTIFICATE-----
`
	var falseCert = "dsjkdfFSBDKJJEF/325234=="

	err = ioutil.WriteFile(crtPath, []byte(crt), fileMode)
	if err != nil {
		t.Fatalf("failed to write the test server crt to capsule8/tls/server.crt: %s", err)
	}
	err = ioutil.WriteFile(keyPath, []byte(key), fileMode)
	if err != nil {
		t.Fatalf("failed to write the test server key capsule8/tls/server.key: %s", err)
	}
	err = ioutil.WriteFile(caPath, []byte(ca), fileMode)
	if err != nil {
		t.Fatalf("failed to write the test certificate authority crt to capsule8/tls/ca.crt: %s", err)
	}
	err = ioutil.WriteFile(falsePath, []byte(falseCert), fileMode)
	if err != nil {
		t.Fatalf("failed to write the test false crt to capsule8/tls/false.crt: %s", err)
	}
	return crtPath, keyPath, caPath, falsePath
}
