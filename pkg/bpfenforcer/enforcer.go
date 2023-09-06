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

import "C"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel bpf bpf/enforcer.c -- -I./bpf/headers
import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dlclark/regexp2"
	"github.com/go-logr/logr"
)

const (
	BPF_F_INNER_MAP        = 0x1000
	MAX_FILE_INNER_ENTRIES = 50
	MAX_BPRM_INNER_ENTRIES = 50
	MAX_NET_INNER_ENTRIES  = 50
	PRECISE_MATCH          = 0x00000001
	GREEDY_MATCH           = 0x00000002
	PREFIX_MATCH           = 0x00000004
	SUFFIX_MATCH           = 0x00000008
	CIDR_MATCH             = 0x00000020
	IPV4_MATCH             = 0x00000040
	IPV6_MATCH             = 0x00000080
	PORT_MATCH             = 0x00000100
	AA_MAY_EXEC            = 0x00000001
	AA_MAY_WRITE           = 0x00000002
	AA_MAY_READ            = 0x00000004
	AA_MAY_APPEND          = 0x00000008
	AA_PTRACE_TRACE        = 0x00000002
	AA_PTRACE_READ         = 0x00000004
	AA_MAY_BE_TRACED       = 0x00000008
	AA_MAY_BE_READ         = 0x00000010
)

type bpfPathRule struct {
	Permissions uint32
	Flags       uint32
	Prefix      [64]byte
	Suffix      [64]byte
}

type bpfNetworkRule struct {
	Flags   uint32
	Address [16]byte
	Mask    [16]byte
	Port    uint32
}

type BpfEnforcer struct {
	objs            bpfObjects
	capableLink     link.Link
	openFileLink    link.Link
	pathSymlinkLink link.Link
	pathLinkLink    link.Link
	pathRenameLink  link.Link
	bprmLink        link.Link
	sockConnLink    link.Link
	ptraceLink      link.Link
	log             logr.Logger
}

func NewBpfEnforcer(log logr.Logger) *BpfEnforcer {
	enforcer := BpfEnforcer{
		objs: bpfObjects{},
		log:  log,
	}

	return &enforcer
}

func readMntNsID(pid uint32) (uint32, error) {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	realPath, err := os.Readlink(path)
	if err != nil {
		return 0, err
	}

	index := strings.Index(realPath, "[")
	if index == -1 {
		return 0, fmt.Errorf(fmt.Sprintf("fatel error: can not parser mnt ns id from: %s", realPath))
	}

	id := realPath[index+1 : len(realPath)-1]
	u64, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return 0, fmt.Errorf(fmt.Sprintf("fatel error: can not transform mnt ns id (%s) to uint64 type", realPath))
	}

	return uint32(u64), nil
}

func (enforcer *BpfEnforcer) InitEBPF() error {
	// Allow the current process to lock memory for eBPF resources.
	enforcer.log.Info("remove memory lock")
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("RemoveMemlock() failed: %v", err)
	}

	enforcer.log.Info("parses the ebpf program into a CollectionSpec")
	collectionSpec, err := loadBpf()
	if err != nil {
		return err
	}

	fileInnerMap := ebpf.MapSpec{
		Name:       "v_file_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 64*2,
		MaxEntries: MAX_FILE_INNER_ENTRIES,
	}
	collectionSpec.Maps["v_file_outer"].InnerMap = &fileInnerMap

	bprmInnerMap := ebpf.MapSpec{
		Name:       "v_bprm_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 64*2,
		MaxEntries: MAX_FILE_INNER_ENTRIES,
	}
	collectionSpec.Maps["v_bprm_outer"].InnerMap = &bprmInnerMap

	netInnerMap := ebpf.MapSpec{
		Name:       "v_net_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 16*2,
		MaxEntries: MAX_NET_INNER_ENTRIES,
	}
	collectionSpec.Maps["v_net_outer"].InnerMap = &netInnerMap

	initMntNsId, err := readMntNsID(1)
	if err != nil {
		return err
	}

	// Set the mnt ns id to the BPF program
	collectionSpec.RewriteConstants(map[string]interface{}{
		"init_mnt_ns": initMntNsId,
	})

	// Load pre-compiled programs and maps into the kernel.
	enforcer.log.Info("load ebpf program and maps into the kernel")
	err = collectionSpec.LoadAndAssign(&enforcer.objs, nil)
	if err != nil {
		return err
	}

	// // Load pre-compiled programs and maps into the kernel.
	// enforcer.log.Info("load ebpf program and maps into the kernel")
	// if err := loadBpfObjects(&enforcer.objs, nil); err != nil {
	// 	return fmt.Errorf("loadBpfObjects() failed: %v", err)
	// }

	return nil
}

func (enforcer *BpfEnforcer) RemoveEBPF() error {
	enforcer.log.Info("unload ebpf program")
	return enforcer.objs.Close()
}

func (enforcer *BpfEnforcer) StartEnforcing() error {
	capableLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorCapable,
	})
	if err != nil {
		return err
	}
	enforcer.capableLink = capableLink

	openFileLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorFileOpen,
	})
	if err != nil {
		return err
	}
	enforcer.openFileLink = openFileLink

	pathSymlinkLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathSymlink,
	})
	if err != nil {
		return err
	}
	enforcer.pathSymlinkLink = pathSymlinkLink

	pathLinkLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathLink,
	})
	if err != nil {
		return err
	}
	enforcer.pathLinkLink = pathLinkLink

	pathRenameLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathRename,
	})
	if err != nil {
		return err
	}
	enforcer.pathRenameLink = pathRenameLink

	bprmLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorBprmCheckSecurity,
	})
	if err != nil {
		return err
	}
	enforcer.bprmLink = bprmLink

	sockConnLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorSocketConnect,
	})
	if err != nil {
		return err
	}
	enforcer.sockConnLink = sockConnLink

	ptraceLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPtraceAccessCheck,
	})
	if err != nil {
		return err
	}
	enforcer.ptraceLink = ptraceLink

	enforcer.log.Info("start enforcing")

	return nil
}

func (enforcer *BpfEnforcer) StopEnforcing() {
	enforcer.log.Info("stop enforcing")

	if enforcer.capableLink != nil {
		enforcer.capableLink.Close()
	}

	if enforcer.openFileLink != nil {
		enforcer.openFileLink.Close()
	}

	if enforcer.pathSymlinkLink != nil {
		enforcer.pathSymlinkLink.Close()
	}

	if enforcer.pathLinkLink != nil {
		enforcer.pathLinkLink.Close()
	}

	if enforcer.pathRenameLink != nil {
		enforcer.pathRenameLink.Close()
	}

	if enforcer.bprmLink != nil {
		enforcer.bprmLink.Close()
	}

	if enforcer.sockConnLink != nil {
		enforcer.sockConnLink.Close()
	}

	if enforcer.ptraceLink != nil {
		enforcer.ptraceLink.Close()
	}
}

func (enforcer *BpfEnforcer) SetCapableMap(mntNsID uint32, capability uint64) error {
	return enforcer.objs.V_capable.Put(&mntNsID, &capability)
}

func (enforcer *BpfEnforcer) ClearCapableMap(mntNsID uint32) error {
	return enforcer.objs.V_capable.Delete(&mntNsID)
}

func reverseString(s string) string {
	bytes := []byte(s)
	len := len(bytes)

	for i := 0; i < len/2; i++ {
		bytes[i], bytes[len-i-1] = bytes[len-i-1], bytes[i]
	}

	return string(bytes)
}

func regexp2FindAllString(re *regexp2.Regexp, s string) []string {
	var matches []string
	m, _ := re.FindStringMatch(s)
	for m != nil {
		matches = append(matches, m.String())
		m, _ = re.FindNextMatch(m)
	}
	return matches
}

func newBpfPathRule(pattern string, permissions uint32) (*bpfPathRule, error) {
	// Pre-check
	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, pattern))

	if starWildcardLen > 0 && strings.Contains(pattern, "**") {
		return nil, fmt.Errorf("the globbing * and ** in the pattern cannot be used at the same time")
	}

	if starWildcardLen > 1 || strings.Count(pattern, "**") > 1 {
		return nil, fmt.Errorf("the globbing * or ** in the pattern can only be used once")
	}

	// Create bpfPathRule
	var pathRule bpfPathRule
	var flags uint32

	if starWildcardLen > 0 {
		if strings.Contains(pattern, "/") {
			return nil, fmt.Errorf("the pattern with globbing * is not supported")
		}
		stringList := strings.Split(pattern, "*")

		var prefix, suffix [64]byte
		if len(stringList[0]) > 0 {
			copy(prefix[:], stringList[0])
			pathRule.Prefix = prefix
			flags |= PREFIX_MATCH
		}

		if len(stringList[1]) > 0 {
			copy(suffix[:], reverseString(stringList[1]))
			pathRule.Suffix = suffix
			flags |= SUFFIX_MATCH
		}
	} else if strings.Contains(pattern, "**") {
		flags |= GREEDY_MATCH

		stringList := strings.Split(pattern, "**")

		var prefix, suffix [64]byte
		if len(stringList[0]) > 0 {
			copy(prefix[:], stringList[0])
			pathRule.Prefix = prefix
			flags |= PREFIX_MATCH
		}

		if len(stringList[1]) > 0 {
			copy(suffix[:], reverseString(stringList[1]))
			pathRule.Suffix = suffix
			flags |= SUFFIX_MATCH
		}
	} else {
		var prefix [64]byte
		copy(prefix[:], pattern)
		pathRule.Prefix = prefix
		flags |= PRECISE_MATCH | PREFIX_MATCH
	}

	pathRule.Flags = flags
	pathRule.Permissions = permissions

	return &pathRule, nil
}

func (enforcer *BpfEnforcer) SetFileMap(mntNsID uint32, pathRule *bpfPathRule) error {
	map_name := fmt.Sprintf("v_file_inner_%d", mntNsID)
	innerMapSpec := ebpf.MapSpec{
		Name:       map_name,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 64*2,
		MaxEntries: MAX_FILE_INNER_ENTRIES,
		// Flags:      BPF_F_INNER_MAP,
	}
	innerMap, err := ebpf.NewMap(&innerMapSpec)
	if err != nil {
		return err
	}
	defer innerMap.Close()

	var index uint32 = 0
	err = innerMap.Put(&index, pathRule)
	if err != nil {
		return err
	}

	return enforcer.objs.V_fileOuter.Put(&mntNsID, innerMap)
}

func (enforcer *BpfEnforcer) ClearFileMap(mntNsID uint32) error {
	return enforcer.objs.V_fileOuter.Delete(&mntNsID)
}

func (enforcer *BpfEnforcer) SetBprmMap(mntNsID uint32, pathRule *bpfPathRule) error {
	map_name := fmt.Sprintf("v_bprm_inner_%d", mntNsID)
	innerMapSpec := ebpf.MapSpec{
		Name:       map_name,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 64*2,
		MaxEntries: MAX_BPRM_INNER_ENTRIES,
		// Flags:      BPF_F_INNER_MAP,
	}
	innerMap, err := ebpf.NewMap(&innerMapSpec)
	if err != nil {
		return err
	}
	defer innerMap.Close()

	var index uint32 = 0
	err = innerMap.Put(&index, pathRule)
	if err != nil {
		return err
	}

	return enforcer.objs.V_bprmOuter.Put(&mntNsID, innerMap)
}

func (enforcer *BpfEnforcer) ClearBprmMap(mntNsID uint32) error {
	return enforcer.objs.V_bprmOuter.Delete(&mntNsID)
}

func newBpfNetworkRule(cidr string, ipAddress string, port uint32) (*bpfNetworkRule, error) {
	// Pre-check
	if cidr == "" && ipAddress == "" && port == 0 {
		return nil, fmt.Errorf("cidr, ipAddress and port cannot be empty at the same time")
	}

	if cidr != "" && ipAddress != "" {
		return nil, fmt.Errorf("cannot set CIRD and IP address at the same time")
	}

	if port > 65535 {
		return nil, fmt.Errorf("invalid network port")
	}

	var networkRule bpfNetworkRule

	if cidr != "" {
		networkRule.Flags |= CIDR_MATCH

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		if ipNet.IP.To4() != nil {
			networkRule.Flags |= IPV4_MATCH
			copy(networkRule.Address[:], ipNet.IP.To4())
			copy(networkRule.Mask[:], ipNet.Mask)
		} else {
			networkRule.Flags |= IPV6_MATCH
			copy(networkRule.Address[:], ipNet.IP.To16())
			copy(networkRule.Mask[:], ipNet.Mask)
		}
	}

	if ipAddress != "" {
		networkRule.Flags |= PRECISE_MATCH

		ip := net.ParseIP(ipAddress)
		if ip == nil {
			return nil, fmt.Errorf("the address is not a valid textual representation of an IP address")
		}

		if ip.To4() != nil {
			networkRule.Flags |= IPV4_MATCH
			copy(networkRule.Address[:], ip.To4())
		} else {
			networkRule.Flags |= IPV6_MATCH
			copy(networkRule.Address[:], ip.To16())
		}
	}

	if port != 0 {
		networkRule.Flags |= PORT_MATCH
		networkRule.Port = port
	}

	return &networkRule, nil
}

func (enforcer *BpfEnforcer) SetNetMap(mntNsID uint32, networkRule *bpfNetworkRule) error {
	map_name := fmt.Sprintf("v_net_inner_%d", mntNsID)
	innerMapSpec := ebpf.MapSpec{
		Name:       map_name,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4*2 + 16*2,
		MaxEntries: MAX_NET_INNER_ENTRIES,
	}
	innerMap, err := ebpf.NewMap(&innerMapSpec)
	if err != nil {
		return err
	}
	defer innerMap.Close()

	var index uint32 = 0
	err = innerMap.Put(&index, networkRule)
	if err != nil {
		return err
	}

	return enforcer.objs.V_netOuter.Put(&mntNsID, innerMap)
}

func (enforcer *BpfEnforcer) ClearNetMap(mntNsID uint32) error {
	return enforcer.objs.V_netOuter.Delete(&mntNsID)
}

func newBpfPtraceRule(permissions uint32, flags uint32) uint64 {
	return uint64(permissions)<<32 + uint64(flags)
}

func (enforcer *BpfEnforcer) SetPtraceMap(mntNsID uint32, ptraceRule uint64) error {
	return enforcer.objs.V_ptrace.Put(&mntNsID, &ptraceRule)
}

func (enforcer *BpfEnforcer) ClearPtraceMap(mntNsID uint32) error {
	return enforcer.objs.V_ptrace.Delete(&mntNsID)
}
