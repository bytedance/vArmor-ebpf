// Note: This file is licenced differently from the rest of the project
// Copyright 2023 vArmor-ebpf Authors
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

package bpfenforcer

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gotest.tools/assert"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func Test_loadEbpf(t *testing.T) {

	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))

	err := e.InitEBPF()
	assert.NilError(t, err)
	err = e.RemoveEBPF()
	assert.NilError(t, err)
}

func Test_enforcing(t *testing.T) {

	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()
}

func Test_Enforcement(t *testing.T) {
	testCases := []struct {
		name          string
		ruleSetup     func(*BpfEnforcer, uint32) error
		ruleClear     func(*BpfEnforcer, uint32) error
		command       []string
		expectError   bool
		expectedError string
	}{
		{
			name: "Block CAP_NET_RAW",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				capRule, err := NewBpfCapabilityRule(DenyMode|AuditMode, 1<<unix.CAP_NET_RAW)
				assert.NilError(t, err)
				return e.SetCapableMap(id, capRule)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearCapableMap(id)
			},
			command:       []string{"ping", "-c", "1", "127.0.0.1"},
			expectError:   true,
			expectedError: "Operation not permitted",
		},
		{
			name: "Block CAP_SYS_ADMIN",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				capRule, err := NewBpfCapabilityRule(DenyMode|AuditMode, 1<<unix.CAP_SYS_ADMIN)
				assert.NilError(t, err)
				return e.SetCapableMap(id, capRule)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearCapableMap(id)
			},
			command:       []string{"unshare", "-Um"},
			expectError:   true,
			expectedError: "Operation not permitted",
		},
		{
			name: "Block IP: 11.30.31.68    PORT: 6443",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "11.30.31.68", 6443, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://11.30.31.68:6443"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block CIDR: 192.168.1.0/24",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "192.168.1.0/24", "", 0, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://192.168.1.101"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block CIDR: 172.16.0.0/11 (Allow 172.32.1.101)", // 172.31.0.1 and 172.32.0.1
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "172.16.0.0/11", "", 0, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "http://172.32.1.101"},
			expectError:   true,
			expectedError: "Connection timed out",
		},
		{
			name: "Block IP: fdbd:dc01:ff:307:9329:268d:3a27:2ca7",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "fdbd:dc01:ff:307:9329:268d:3a27:2ca7", 0, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[fdbd:dc01:ff:307:9329:268d:3a27:2ca7]:8080"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block CIDR: 2001:db8::/31", // 2001:db8:1:: and 2001:dba:1::
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "2001:db8::/31", "", 0, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[2001:db9:2:307:9329:268d:3a27:2ca7]:8080"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block CIDR: 2001:db8::/31 (Allow 2001:dba:2:307:9329:268d:3a27:2ca7 )", // 2001:db8:1:: and 2001:dba:1::
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "2001:db8::/31", "", 0, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "-6", "http://[2001:dba:2:307:9329:268d:3a27:2ca7]"},
			expectError:   true,
			expectedError: "Connection timed out",
		},
		{
			name: "Block IP: *    PORT: 10250 (IPv4)",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 10250, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://127.0.0.1:10250"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IP: *    PORT: 10250 (IPv6)",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 10250, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[::1]:10250"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IP: *    PORT: 10250 (Allow 127.0.0.1:18898)",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 10250, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://127.0.0.1:18898"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IP: *    PORT: 10250 (Allow [::1]:18898)",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 10250, 0, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[::1]:18898"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IP: *    PORT: 6670-6680",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 6670, 6680, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://127.0.0.1:6670"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IP: *    PORT: 6670-6680 (Allow :6681)",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 6670, 6680, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://127.0.0.1:6681"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IP: *    PORT: 6670,6672,6673",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 0, 0, &[]uint16{6670, 6672, 6673})
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://127.0.0.1:6672"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IP: *    PORT: 6670,6672,6673 (Allow :6671)",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 0, 0, &[]uint16{6670, 6672, 6673})
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://127.0.0.1:6671"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv4 'pod-self':'80-8080'",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://10.0.2.10:8000"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv4 'pod-self':'80-8080' (Allow IPv4 'pod-self':'8090')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "http://10.0.2.10:8090"},
			expectError:   true,
			expectedError: "Connection timed out",
		},
		{
			name: "Block IPv4 'pod-self':'80-8080' (Allow IPv4 '0.0.0.0':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "http://0.0.0.0:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv4 'pod-self':'80-8080' (Allow IPv6 '::':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "-6", "http://[::]:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv6 'pod-self':'80-8080' (IPv6)",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[fdbd:dc01:ff:307:9329:268d:3a27:3ca7]:8000"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv6 'pod-self':'80,8080' (Allow IPv6 'pod-self':'8090')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 0, 0, &[]uint16{80, 8080})
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "-6", "http://[fdbd:dc01:ff:307:9329:268d:3a27:3ca7]:8090"},
			expectError:   true,
			expectedError: "Connection timed out",
		},
		{
			name: "Block IPv6 'pod-self':'80-8080' (Allow IPv6 '::':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "-6", "http://[::]:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv6 'pod-self':'80-8080' (Allow IPv4 '0.0.0.0':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "--connect-timeout", "1", "http://0.0.0.0:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv4 '0.0.0.0':'80-8080'",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://0.0.0.0:6677"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv4 '0.0.0.0':'80-8080'",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://0.0.0.0:8000"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv4 '0.0.0.0':'80-8080' (Allow '0.0.0.0':'9090')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://0.0.0.0:9090"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv4 '0.0.0.0':'80-8080' (Allow '127.0.0.1':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://127.0.0.1:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv6 '::':'80-8080'",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[::]:6677"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv6 '::':'80-8080'",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[::]:8000"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv6 '::':'80-8080' (Allow '::':'9090')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[::]:9090"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv6 '::':'80-8080' (Allow '::1':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", Unspecified, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[::1]:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv4 & IPv6 'pod-self':'80-8080'",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10", "fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://10.0.2.10:8000"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv6 & IPv4 'pod-self':'80-8080'",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10", "fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[fdbd:dc01:ff:307:9329:268d:3a27:3ca7]:8000"},
			expectError:   true,
			expectedError: "Couldn't connect to server",
		},
		{
			name: "Block IPv4 & IPv6 'pod-self':'80-8080' (Allow '0.0.0.0':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10", "fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "http://0.0.0.0:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
		{
			name: "Block IPv6 & IPv4 'pod-self':'80-8080' (Allow '::':'80')",
			ruleSetup: func(e *BpfEnforcer, id uint32) error {
				// mock pod ip
				err := e.SetPodIps(id, []string{"10.0.2.10", "fdbd:dc01:ff:307:9329:268d:3a27:3ca7"})
				assert.NilError(t, err)

				var rules []bpfNetworkRule
				rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", PodSelfIP, 80, 8080, nil)
				assert.NilError(t, err)
				rules = append(rules, *rule)
				return e.SetNetMap(id, rules)
			},
			ruleClear: func(e *BpfEnforcer, id uint32) error {
				return e.ClearNetMap(id)
			},
			command:       []string{"curl", "-6", "http://[::]:80"},
			expectError:   true,
			expectedError: "Connection refused",
		},
	}

	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))

	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	nsID, cleanup, err := CreateTestNamespace(t)
	if err != nil {
		t.Fatalf("failed to create test namespace: %v", err)
	}
	defer cleanup()
	defer e.RemovePodIps(nsID)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err = e.SetProfileMode(nsID, EnforceMode)
			assert.NilError(t, err)

			if err := tc.ruleSetup(e, nsID); err != nil {
				t.Fatal(err)
			}

			t.Log("Running command:", tc.command)
			_, err = RunCommandInNamespace(nsID, tc.command[0], tc.command[1:]...)
			tc.ruleClear(e, nsID)
			if tc.expectError {
				assert.ErrorContains(t, err, tc.expectedError)
			} else {
				assert.NilError(t, err)
			}
		})
	}
}

func Test_VarmorCapable(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	err = e.SetProfileMode(4026532792, EnforceMode)
	assert.NilError(t, err)

	// CAP_SYS_ADMIN: unshare -Urn
	// CAP_NET_RAW: ping 127.0.0.1
	capRule, _ := NewBpfCapabilityRule(DenyMode|AuditMode, 1<<unix.CAP_NET_RAW|1<<unix.CAP_SYS_ADMIN)
	err = e.SetCapableMap(4026532792, capRule)
	assert.NilError(t, err)

	t.Log("deny tasks(mnt ns id: 4026532792) to use CAP_NET_RAW | CAP_SYS_ADMIN")

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	t.Log("allow tasks(mnt ns id: 4026532792) to use CAP_NET_RAW | CAP_SYS_ADMIN")
	err = e.ClearCapableMap(4026532792)
	assert.NilError(t, err)

	stopTicker = time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_newBpfPathRule(t *testing.T) {
	testCases := []struct {
		pattern     string
		permission  uint32
		expectedErr error
	}{
		{
			pattern:     "/**/devices/ta*",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * and ** in the pattern '/**/devices/ta*' cannot be used at the same time"),
		},
		{
			pattern:     "/dwa**/devices/*",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * and ** in the pattern '/dwa**/devices/*' cannot be used at the same time"),
		},
		{
			pattern:     "/**dwad/devices/*/dwa",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * and ** in the pattern '/**dwad/devices/*/dwa' cannot be used at the same time"),
		},
		{
			pattern:     "/dwad/d**evices/*/",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * and ** in the pattern '/dwad/d**evices/*/' cannot be used at the same time"),
		},
		{
			pattern:     "/dwad/*/**devices/ta*",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * and ** in the pattern '/dwad/*/**devices/ta*' cannot be used at the same time"),
		},
		{
			pattern:     "/**/devices/**/tasks",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * or ** in the pattern '/**/devices/**/tasks' can only be used once"),
		},
		{
			pattern:     "/devices**/**/tasks",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * or ** in the pattern '/devices**/**/tasks' can only be used once"),
		},
		{
			pattern:     "/*/devices/tda*",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * or ** in the pattern '/*/devices/tda*' can only be used once"),
		},
		{
			pattern:     "/*/*",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * or ** in the pattern '/*/*' can only be used once"),
		},
		{
			pattern:     "/*devices/ta*",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the globbing * or ** in the pattern '/*devices/ta*' can only be used once"),
		},
		{
			pattern:     "/devices/*ta",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the pattern '/devices/*ta' with globbing * is not supported"),
		},
		{
			pattern:     "/etc/*",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the pattern '/etc/*' with globbing * is not supported"),
		},
		{
			pattern:     "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*xx",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the length of prefix 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' should be less than the maximum (%d)", MaxFilePathPatternLength),
		},
		{
			pattern:     "x*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			permission:  AaMayWrite,
			expectedErr: fmt.Errorf("the length of suffix 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' should be less than the maximum (%d)", MaxFilePathPatternLength),
		},
		{
			pattern:     "/**/devices/ta",
			permission:  AaMayWrite,
			expectedErr: nil,
		},
		{
			pattern:     "passwd*",
			permission:  AaMayWrite,
			expectedErr: nil,
		},
		{
			pattern:     "*.log",
			permission:  AaMayWrite,
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.pattern, func(t *testing.T) {
			rule, err := NewBpfPathRule(DenyMode, tc.pattern, tc.permission)
			if err != nil {
				assert.Equal(t, err.Error(), tc.expectedErr.Error())
			} else {
				fmt.Printf("Permissions: %d\n", rule.Permissions)
				fmt.Printf("Flags: %d\n", rule.Flags)
				fmt.Println("Prefile: " + string(rule.Prefix[:]))
				fmt.Println("Suffix: " + string(rule.Suffix[:]))
			}
		})
	}
}

func Test_VarmorFileRule(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	err = e.SetProfileMode(4026533472, EnforceMode)
	assert.NilError(t, err)

	// host mnt ns id: 4026531840
	// match /tmp/33**, /**/33, /tmp/**/33, /etc/**,
	rule, err := NewBpfPathRule(DenyMode|AuditMode, "/**/hostname", AaMayWrite|AaMayAppend)
	assert.NilError(t, err)

	err = e.SetFileMap(4026533472, rule)
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorBprmCheckSecurity(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	err = e.SetProfileMode(4026532792, EnforceMode)
	assert.NilError(t, err)

	rule, err := NewBpfPathRule(DenyMode|AuditMode, "/bin/**ng", AaMayExec)
	assert.NilError(t, err)

	err = e.SetBprmMap(4026532792, rule)
	assert.NilError(t, err)

	m, err := e.LoadMap()
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(m)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_newBpfNetworkConnectRule(t *testing.T) {
	testCases := []struct {
		name            string
		cidr            string
		address         string
		port            uint16
		endPort         uint16
		ports           *[]uint16
		expectedFlags   uint32
		expectedAddr    [16]byte
		expectedMask    [16]byte
		expectedPort    uint16
		expectedEndPort uint16
		expectedPorts   [16]uint16
		expectedErr     error
	}{
		{
			name:        "testcase-0",
			expectedErr: fmt.Errorf("cidr, ipAddress, port, endPort and ports cannot be empty at the same time"),
		},
		{
			name:        "testcase-1",
			cidr:        "192.168.1.1/24",
			address:     "192.168.1.1",
			expectedErr: fmt.Errorf("cannot set CIRD and IP address at the same time"),
		},
		{
			name:        "testcase-2",
			port:        80,
			ports:       &[]uint16{63, 6080},
			expectedErr: fmt.Errorf("cannot set port/endPort and ports at the same time"),
		},
		{
			name:        "testcase-3",
			port:        80,
			endPort:     8080,
			ports:       &[]uint16{63, 6080},
			expectedErr: fmt.Errorf("cannot set port/endPort and ports at the same time"),
		},
		{
			name:        "testcase-4",
			port:        8080,
			endPort:     80,
			expectedErr: fmt.Errorf("endPort cannot be less than port"),
		},
		{
			name:        "testcase-5",
			port:        0,
			endPort:     8080,
			expectedErr: fmt.Errorf("port cannot be 0 when endPort is set"),
		},
		{
			name:        "testcase-6",
			ports:       &[]uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18},
			expectedErr: fmt.Errorf("the number of ports cannot be greater than 16"),
		},
		{
			name:        "testcase-7",
			ports:       &[]uint16{1, 2, 0, 3},
			expectedErr: fmt.Errorf("invalid network port in ports"),
		},
		{
			name:          "testcase-8",
			cidr:          "192.168.1.1/24",
			expectedFlags: CidrMatch | Ipv4Match,
			expectedAddr:  [16]byte{192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedMask:  [16]byte{255, 255, 255},
		},
		{
			name:          "testcase-9",
			cidr:          "2001:db8::/32",
			expectedFlags: CidrMatch | Ipv6Match,
			expectedAddr:  [16]byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedMask:  [16]byte{255, 255, 255, 255},
		},
		{
			name:          "testcase-10",
			address:       "11.3.30.68",
			expectedFlags: PreciseMatch | Ipv4Match,
			expectedAddr:  [16]byte{11, 3, 30, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:          "testcase-11",
			address:       "febd:dc01:ff:307:932a:268d:3a27:2ca7",
			expectedFlags: PreciseMatch | Ipv6Match,
			expectedAddr:  [16]byte{254, 189, 220, 1, 0, 255, 3, 7, 147, 42, 38, 141, 58, 39, 44, 167},
		},
		{
			name:          "testcase-12",
			cidr:          "11.37.100.230/16",
			expectedFlags: CidrMatch | Ipv4Match,
			expectedAddr:  [16]byte{11, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedMask:  [16]byte{255, 255},
		},
		{
			name:          "testcase-13",
			cidr:          "172.16.0.0/11",
			port:          10250,
			expectedFlags: CidrMatch | Ipv4Match | PortMatch,
			expectedAddr:  [16]byte{172, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedMask:  [16]byte{255, 224},
			expectedPort:  10250,
		},
		{
			name:            "testcase-14",
			cidr:            "2001:db8::/31",
			port:            1,
			endPort:         1024,
			expectedFlags:   CidrMatch | Ipv6Match | PortRangeMatch,
			expectedAddr:    [16]byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedMask:    [16]byte{255, 255, 255, 254},
			expectedPort:    1,
			expectedEndPort: 1024,
		},
		{
			name:          "testcase-15",
			address:       "11.3.30.68",
			ports:         &[]uint16{80, 8080, 6443},
			expectedFlags: PreciseMatch | Ipv4Match | PortsMatch,
			expectedAddr:  [16]byte{11, 3, 30, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedPorts: [16]uint16{80, 8080, 6443, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:          "testcase-16",
			address:       "11.30.31.68",
			port:          6443,
			expectedFlags: PreciseMatch | Ipv4Match | PortMatch,
			expectedAddr:  [16]byte{11, 30, 31, 68},
			expectedPort:  6443,
		},
		{
			name:          "testcase-17",
			address:       PodSelfIP,
			expectedFlags: PodSelfIPMatch | Ipv4Match | Ipv6Match,
			expectedAddr:  [16]byte{},
		},
		{
			name:          "testcase-18",
			address:       PodSelfIP,
			port:          6443,
			expectedFlags: PodSelfIPMatch | Ipv4Match | Ipv6Match | PortMatch,
			expectedAddr:  [16]byte{},
			expectedPort:  6443,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, tc.cidr, tc.address, tc.port, tc.endPort, tc.ports)
			if err != nil {
				assert.Equal(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.Equal(t, rule.Flags, tc.expectedFlags)
				assert.DeepEqual(t, rule.Address, tc.expectedAddr)
				assert.DeepEqual(t, rule.Mask, tc.expectedMask)
				assert.DeepEqual(t, rule.Port, tc.expectedPort)
				assert.DeepEqual(t, rule.EndPort, tc.expectedEndPort)
				assert.DeepEqual(t, rule.Ports, tc.expectedPorts)
				t.Log(rule.Mode)
				t.Log(rule.Flags)
				t.Log(rule.Address)
				t.Log(rule.Mask)
				t.Log(rule.Port)
				t.Log(rule.EndPort)
				t.Log(rule.Ports)
			}
		})
	}
}

func Test_VarmorNetworkConnectSecurity(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	var rules []bpfNetworkRule

	rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "11.30.31.68", 6443, 0, nil)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	// CIDR: 172.0.0.0/11 (172.0.0.0 ~ 172.31.255.255) test with 172.31.0.1 and 172.32.0.1
	rule, err = NewBpfNetworkConnectRule(DenyMode|AuditMode, "172.16.0.0/11", "", 0, 0, nil)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	rule, err = NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "fdbd:dc01:ff:307:9329:268d:3a27:2ca7", 0, 0, nil)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	// CIDR: 2001:db8::/31 (2001:db8:: ~ 2001:db9:ffff:ffff:ffff:ffff:ffff:ffff ) test with 2001:db8:1:: and 2001:dba:1::
	rule, err = NewBpfNetworkConnectRule(DenyMode|AuditMode, "2001:db8::/31", "", 0, 0, nil)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	rule, err = NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 10250, 0, nil)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	rule, err = NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 10250, 10255, nil)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	rule, err = NewBpfNetworkConnectRule(DenyMode|AuditMode, "", "", 0, 0, &[]uint16{80, 8080, 8060})
	assert.NilError(t, err)
	rules = append(rules, *rule)

	err = e.SetProfileMode(4026533644, EnforceMode)
	assert.NilError(t, err)

	err = e.SetNetMap(4026533644, rules)
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorNetworkCreateSecurity(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	var rules []bpfNetworkRule

	rule, err := NewBpfNetworkConnectRule(DenyMode|AuditMode, "192.168.1.0/24", "", 0, 0, nil)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	rule, err = NewBpfNetworkCreateRule(DenyMode|AuditMode,
		0,
		0,
		1<<unix.IPPROTO_ICMP|1<<unix.IPPROTO_ICMPV6)
	assert.NilError(t, err)
	rules = append(rules, *rule)

	err = e.SetProfileMode(4026533501, EnforceMode)
	assert.NilError(t, err)

	err = e.SetNetMap(4026533501, rules)
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorPtraceAccessCheck(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	rule, _ := NewBpfPtraceRule(DenyMode|AuditMode, AaMayBeRead, GreedyMatch)

	err = e.SetProfileMode(4026532792, EnforceMode)
	assert.NilError(t, err)

	err = e.SetPtraceMap(4026532792, rule)
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorBindMountAccessCheck(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	rule, err := NewBpfMountRule(DenyMode|AuditMode, "/proc**", "none", unix.MS_BIND, 0)
	assert.NilError(t, err)

	err = e.SetProfileMode(4026532792, EnforceMode)
	assert.NilError(t, err)

	err = e.SetMountMap(4026532792, rule)
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorMountNewProcAccessCheck(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	flags := 0xFFFFFFFF &^ unix.MS_REMOUNT &^
		unix.MS_BIND &^ unix.MS_SHARED &^
		unix.MS_PRIVATE &^ unix.MS_SLAVE &^
		unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ AaMayUmount

	rule, err := NewBpfMountRule(DenyMode|AuditMode, "**", "proc", uint32(flags), 0xFFFFFFFF)
	assert.NilError(t, err)

	err = e.SetProfileMode(4026532792, EnforceMode)
	assert.NilError(t, err)

	err = e.SetMountMap(4026532792, rule)
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorComplain(t *testing.T) {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	assert.NilError(t, err)
	defer e.RemoveEBPF()

	err = e.StartEnforcing()
	assert.NilError(t, err)
	defer e.StopEnforcing()

	err = e.SetProfileMode(4026533839, ComplainMode)
	assert.NilError(t, err)

	go e.ReadFromAuditEventRingBuf(e.objs.V_auditRb)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}
