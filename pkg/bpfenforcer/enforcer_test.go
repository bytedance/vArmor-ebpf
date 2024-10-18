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
	"k8s.io/klog/v2/klogr"
	log "sigs.k8s.io/controller-runtime/pkg/log"
)

func Test_loadEbpf(t *testing.T) {

	log.SetLogger(klogr.New())
	enforcer := NewBpfEnforcer(log.Log.WithName("ebpf"))

	err := enforcer.InitEBPF()
	assert.NilError(t, err)
	err = enforcer.RemoveEBPF()
	assert.NilError(t, err)
}

func Test_enforcing(t *testing.T) {

	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()
}

func Test_VarmorCapable(t *testing.T) {
	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()

	// CAP_SYS_ADMIN: unshare -Urn
	// CAP_NET_RAW: ping 127.0.0.1
	capRule, _ := newBpfCapabilityRule(AuditMode, 1<<unix.CAP_NET_RAW|1<<unix.CAP_SYS_ADMIN)
	err = tracer.SetCapableMap(4026532792, capRule)
	assert.NilError(t, err)

	fmt.Println("deny tasks(mnt ns id: 4026532792) to use CAP_NET_RAW | CAP_SYS_ADMIN")

	go tracer.ReadFromAuditEventRingBuf()

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	fmt.Println("allow tasks(mnt ns id: 4026532792) to use CAP_NET_RAW | CAP_SYS_ADMIN")
	err = tracer.ClearCapableMap(4026532792)
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
			rule, err := newBpfPathRule(EnforceMode, tc.pattern, tc.permission)
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
	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()

	// host mnt ns id: 4026531840
	// match /tmp/33**, /**/33, /tmp/**/33, /etc/**,
	rule, err := newBpfPathRule(AuditMode, "/**/hostname", AaMayWrite|AaMayAppend)
	assert.NilError(t, err)

	err = tracer.SetFileMap(4026532792, rule)
	assert.NilError(t, err)

	rule, err = newBpfPathRule(AuditMode, "/bin/**ng", AaMayExec)
	assert.NilError(t, err)

	err = tracer.SetBprmMap(4026532792, rule)
	assert.NilError(t, err)

	go tracer.ReadFromAuditEventRingBuf()

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorBprmCheckSecurity(t *testing.T) {
	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()

	rule, err := newBpfPathRule(EnforceMode, "/bin/**ng", AaMayExec)
	assert.NilError(t, err)

	err = tracer.SetBprmMap(4026532844, rule)
	assert.NilError(t, err)

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_newBpfNetworkRule(t *testing.T) {
	testCases := []struct {
		name          string
		cidr          string
		address       string
		port          uint32
		expectedFlags uint32
		expectedAddr  [16]byte
		expectedErr   error
	}{
		{
			name:        "testcase-0",
			cidr:        "192.168.1.1/24",
			address:     "192.168.1.1",
			port:        0,
			expectedErr: fmt.Errorf("cannot set CIRD and IP address at the same time"),
		},
		{
			name:        "testcase-1",
			cidr:        "192.168.1.1/24",
			address:     "",
			port:        99999,
			expectedErr: fmt.Errorf("invalid network port"),
		},
		{
			name:          "testcase-2",
			cidr:          "192.168.1.1/24",
			address:       "",
			port:          0,
			expectedFlags: 96,
			expectedAddr:  [16]byte{192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedErr:   nil,
		},
		{
			name:          "testcase-3",
			cidr:          "2001:db8::/32",
			address:       "",
			port:          0,
			expectedFlags: 160,
			expectedAddr:  [16]byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedErr:   nil,
		},
		{
			name:          "testcase-4",
			cidr:          "",
			address:       "11.3.30.68",
			port:          0,
			expectedFlags: 65,
			expectedAddr:  [16]byte{11, 3, 30, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedErr:   nil,
		},
		{
			name:          "testcase-5",
			cidr:          "",
			address:       "febd:dc01:ff:307:932a:268d:3a27:2ca7",
			port:          0,
			expectedFlags: 129,
			expectedAddr:  [16]byte{254, 189, 220, 1, 0, 255, 3, 7, 147, 42, 38, 141, 58, 39, 44, 167},
			expectedErr:   nil,
		},
		{
			name:          "testcase-6",
			cidr:          "11.37.100.230/16",
			address:       "",
			port:          0,
			expectedFlags: 96,
			expectedAddr:  [16]byte{11, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedErr:   nil,
		},
		{
			name:          "testcase-7",
			cidr:          "172.16.0.0/11",
			address:       "",
			port:          10250,
			expectedFlags: 352,
			expectedAddr:  [16]byte{172, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedErr:   nil,
		},
		{
			name:          "testcase-8",
			cidr:          "2001:db8::/31",
			address:       "",
			port:          0,
			expectedFlags: 160,
			expectedAddr:  [16]byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedErr:   nil,
		},
		{
			name:        "testcase-9",
			cidr:        "",
			address:     "",
			port:        0,
			expectedErr: fmt.Errorf("cidr, ipAddress and port cannot be empty at the same time"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := newBpfNetworkRule(AuditMode, tc.cidr, tc.address, tc.port)
			if err != nil {
				assert.Equal(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.Equal(t, rule.Flags, tc.expectedFlags)
				assert.DeepEqual(t, rule.Address, tc.expectedAddr)
				fmt.Println(rule.Address)
				fmt.Println(rule.Mask)
			}
		})
	}

	// _, ipNet, _ := net.ParseCIDR("172.16.0.0/11")
	// fmt.Println(ipNet.Mask)
	// fmt.Println(ipNet.Contains(net.ParseIP("172.32.0.1")))
}

func Test_VarmorNetCheckSecurity(t *testing.T) {
	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()

	// rule, err := newBpfNetworkRule(AuditMode, "", "11.30.31.68", 6443)
	// rule, err := newBpfNetworkRule(AuditMode, "", "fdbd:dc01:ff:307:9329:268d:3a27:2ca7", 0)
	// rule, err := newBpfNetworkRule(AuditMode, "", "", 10250)
	// CIDR: 172.0.0.0/11 (172.0.0.0 ~ 172.31.255.255) test with 172.31.0.1 and 172.32.0.1
	// rule, err := newBpfNetworkRule(AuditMode, "172.16.0.0/11", "", 0)
	// CIDR: 2001:db8::/31 (2001:db8:: ~ 2001:db9:ffff:ffff:ffff:ffff:ffff:ffff ) test with 2001:db8:1:: and 2001:dba:1::
	// rule, err := newBpfNetworkRule(AuditMode, "2001:db8::/31", "", 0)
	rule, err := newBpfNetworkRule(AuditMode, "192.168.1.0/24", "", 0)
	assert.NilError(t, err)

	err = tracer.SetNetMap(4026532792, rule)
	assert.NilError(t, err)

	go tracer.ReadFromAuditEventRingBuf()

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorPtraceAccessCheck(t *testing.T) {
	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()

	rule, _ := newBpfPtraceRule(AuditMode, AaMayBeRead, GreedyMatch)
	err = tracer.SetPtraceMap(4026532792, rule)
	assert.NilError(t, err)

	go tracer.ReadFromAuditEventRingBuf()

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorBindMountAccessCheck(t *testing.T) {
	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()

	rule, err := newBpfMountRule(AuditMode, "/proc**", "none", unix.MS_BIND, 0)
	assert.NilError(t, err)

	err = tracer.SetMountMap(4026532792, rule)
	assert.NilError(t, err)

	go tracer.ReadFromAuditEventRingBuf()

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}

func Test_VarmorMountNewProcAccessCheck(t *testing.T) {
	log.SetLogger(klogr.New())
	tracer := NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	err = tracer.StartEnforcing()
	assert.NilError(t, err)
	defer tracer.StopEnforcing()

	flags := 0xFFFFFFFF &^ unix.MS_REMOUNT &^
		unix.MS_BIND &^ unix.MS_SHARED &^
		unix.MS_PRIVATE &^ unix.MS_SLAVE &^
		unix.MS_UNBINDABLE &^ unix.MS_MOVE &^ AaMayUmount

	rule, err := newBpfMountRule(AuditMode, "**", "proc", uint32(flags), 0xFFFFFFFF)
	assert.NilError(t, err)

	err = tracer.SetMountMap(4026532792, rule)
	assert.NilError(t, err)

	go tracer.ReadFromAuditEventRingBuf()

	stopTicker := time.NewTicker(5 * time.Second)
	<-stopTicker.C

	// err = fmt.Errorf("forced error")
	// assert.NilError(t, err)
}
