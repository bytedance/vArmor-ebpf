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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type audit_event bpf bpf/enforcer.c -- -I./bpf/headers
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dlclark/regexp2"
	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"
)

const (
	BPF_F_INNER_MAP = 0x1000

	// The max count of rules for policy primitives.
	MaxBpfFileRuleCount    = 50
	MaxBpfBprmRuleCount    = 50
	MaxBpfNetworkRuleCount = 50
	MaxBpfMountRuleCount   = 50

	// MaxFilePathPatternLength is the max length of path pattern,
	// it's equal to FILE_PATH_PATTERN_SIZE_MAX in BPF code
	MaxFilePathPatternLength = 64

	// PathPatternSize is the size of `struct path_pattern` in BPF code
	PathPatternSize = 4 + MaxFilePathPatternLength*2

	// PathRuleSize is the size of `struct path_rule` in BPF code, it's
	// also the value size of the inner map for file and execution access control.
	PathRuleSize = 4*2 + PathPatternSize

	// IpAddressSize is the size of IP address and mask.
	IpAddressSize = 16

	// NetRuleSize is the size of `struct net_rule` in BPF code, it's
	// also the value size of the inner map for network access control.
	NetRuleSize = 4*3 + IpAddressSize*2

	// MaxFileSystemTypeLength is the max length of fstype pattern,
	// it's equal to FILE_SYSTEM_TYPE_MAX in BPF code
	MaxFileSystemTypeLength = 16

	// MountRuleSize is the size of `struct mount_rule` in BPF code, it's
	// also the value size of the inner map for mount access control.
	MountRuleSize = 4*2 + MaxFileSystemTypeLength + PathPatternSize

	// BPF enforcer running mode.
	EnforceMode  = 0x00000001
	AuditMode    = 0x00000002
	ComplainMode = 0x00000004

	// Matching Flags
	PreciseMatch = 0x00000001
	GreedyMatch  = 0x00000002
	PrefixMatch  = 0x00000004
	SuffixMatch  = 0x00000008
	CidrMatch    = 0x00000020
	Ipv4Match    = 0x00000040
	Ipv6Match    = 0x00000080
	PortMatch    = 0x00000100

	// Matching Permissions
	AaMayExec     = 0x00000001
	AaMayWrite    = 0x00000002
	AaMayRead     = 0x00000004
	AaMayAppend   = 0x00000008
	AaPtraceTrace = 0x00000002
	AaPtraceRead  = 0x00000004
	AaMayBeTraced = 0x00000008
	AaMayBeRead   = 0x00000010
	AaMayUmount   = 0x00000200

	// Event type
	FileType       = 0x00000001
	BprmType       = 0x00000002
	CapabilityType = 0x00000004
	NetworkType    = 0x00000008
)

type bpfPathRule struct {
	Mode        uint32
	Permissions uint32
	Flags       uint32
	Prefix      [MaxFilePathPatternLength]byte
	Suffix      [MaxFilePathPatternLength]byte
}

type bpfNetworkRule struct {
	Mode    uint32
	Flags   uint32
	Address [IpAddressSize]byte
	Mask    [IpAddressSize]byte
	Port    uint32
}

type bpfMountRule struct {
	MountFlags        uint32
	ReverseMountFlags uint32
	FsType            [MaxFileSystemTypeLength]byte
	Flags             uint32
	Prefix            [MaxFilePathPatternLength]byte
	Suffix            [MaxFilePathPatternLength]byte
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
	mountLink       link.Link
	moveMountLink   link.Link
	umountLink      link.Link
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
		ValueSize:  PathRuleSize,
		MaxEntries: MaxBpfFileRuleCount,
	}
	collectionSpec.Maps["v_file_outer"].InnerMap = &fileInnerMap

	bprmInnerMap := ebpf.MapSpec{
		Name:       "v_bprm_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  PathRuleSize,
		MaxEntries: MaxBpfFileRuleCount,
	}
	collectionSpec.Maps["v_bprm_outer"].InnerMap = &bprmInnerMap

	netInnerMap := ebpf.MapSpec{
		Name:       "v_net_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  NetRuleSize,
		MaxEntries: MaxBpfNetworkRuleCount,
	}
	collectionSpec.Maps["v_net_outer"].InnerMap = &netInnerMap

	mountInnerMap := ebpf.MapSpec{
		Name:       "v_mount_inner_",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  MountRuleSize,
		MaxEntries: MaxBpfMountRuleCount,
	}
	collectionSpec.Maps["v_mount_outer"].InnerMap = &mountInnerMap

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

	mountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorMount,
	})
	if err != nil {
		return err
	}
	enforcer.mountLink = mountLink

	moveMountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorMoveMount,
	})
	if err != nil {
		return err
	}
	enforcer.moveMountLink = moveMountLink

	umountLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorUmount,
	})
	if err != nil {
		return err
	}
	enforcer.umountLink = umountLink

	enforcer.log.Info("start enforcing")

	return nil
}

func (enforcer *BpfEnforcer) StopEnforcing() {
	enforcer.log.Info("stop enforcing")
	enforcer.capableLink.Close()
	enforcer.openFileLink.Close()
	enforcer.pathSymlinkLink.Close()
	enforcer.pathLinkLink.Close()
	enforcer.pathRenameLink.Close()
	enforcer.bprmLink.Close()
	enforcer.sockConnLink.Close()
	enforcer.ptraceLink.Close()
	enforcer.mountLink.Close()
	enforcer.moveMountLink.Close()
	enforcer.umountLink.Close()
}

func newBpfCapabilityRule(mode uint32, capabilities uint64) (*bpfCapabilityRule, error) {
	var capabilityRule bpfCapabilityRule
	capabilityRule.Mode = mode
	capabilityRule.Caps = capabilities
	return &capabilityRule, nil
}

func (enforcer *BpfEnforcer) SetCapableMap(mntNsID uint32, capabilityRule *bpfCapabilityRule) error {
	return enforcer.objs.V_capable.Put(&mntNsID, capabilityRule)
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

func newBpfPathRule(mode uint32, pattern string, permissions uint32) (*bpfPathRule, error) {
	// Pre-check
	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, pattern))

	if starWildcardLen > 0 && strings.Contains(pattern, "**") {
		return nil, fmt.Errorf("the globbing * and ** in the pattern '%s' cannot be used at the same time", pattern)
	}

	if starWildcardLen > 1 || strings.Count(pattern, "**") > 1 {
		return nil, fmt.Errorf("the globbing * or ** in the pattern '%s' can only be used once", pattern)
	}

	// Create bpfPathRule
	var pathRule bpfPathRule
	var flags uint32

	pathRule.Mode = mode

	if starWildcardLen > 0 {
		if strings.Contains(pattern, "/") {
			return nil, fmt.Errorf("the pattern '%s' with globbing * is not supported", pattern)
		}
		stringList := strings.Split(pattern, "*")

		var prefix, suffix [MaxFilePathPatternLength]byte
		if len(stringList[0]) > 0 {
			copy(prefix[:], stringList[0])
			pathRule.Prefix = prefix
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			copy(suffix[:], reverseString(stringList[1]))
			pathRule.Suffix = suffix
			flags |= SuffixMatch
		}
	} else if strings.Contains(pattern, "**") {
		flags |= GreedyMatch

		stringList := strings.Split(pattern, "**")

		var prefix, suffix [MaxFilePathPatternLength]byte
		if len(stringList[0]) > 0 {
			copy(prefix[:], stringList[0])
			pathRule.Prefix = prefix
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			copy(suffix[:], reverseString(stringList[1]))
			pathRule.Suffix = suffix
			flags |= SuffixMatch
		}
	} else {
		var prefix [MaxFilePathPatternLength]byte
		copy(prefix[:], pattern)
		pathRule.Prefix = prefix
		flags |= PreciseMatch | PrefixMatch
	}

	if pathRule.Prefix[MaxFilePathPatternLength-1] != 0 {
		return nil, fmt.Errorf("the length of prefix '%s' should be less than the maximum (%d)", pathRule.Prefix, MaxFilePathPatternLength)
	}

	if pathRule.Suffix[MaxFilePathPatternLength-1] != 0 {
		return nil, fmt.Errorf("the length of suffix '%s' should be less than the maximum (%d)", pathRule.Suffix, MaxFilePathPatternLength)
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
		ValueSize:  PathRuleSize,
		MaxEntries: MaxBpfFileRuleCount,
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
		ValueSize:  PathRuleSize,
		MaxEntries: MaxBpfBprmRuleCount,
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

func newBpfNetworkRule(mode uint32, cidr string, ipAddress string, port uint32) (*bpfNetworkRule, error) {
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

	networkRule.Mode = mode

	if cidr != "" {
		networkRule.Flags |= CidrMatch

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		if ipNet.IP.To4() != nil {
			networkRule.Flags |= Ipv4Match
			copy(networkRule.Address[:], ipNet.IP.To4())
			copy(networkRule.Mask[:], ipNet.Mask)
		} else {
			networkRule.Flags |= Ipv6Match
			copy(networkRule.Address[:], ipNet.IP.To16())
			copy(networkRule.Mask[:], ipNet.Mask)
		}
	}

	if ipAddress != "" {
		networkRule.Flags |= PreciseMatch

		ip := net.ParseIP(ipAddress)
		if ip == nil {
			return nil, fmt.Errorf("the address is not a valid textual representation of an IP address")
		}

		if ip.To4() != nil {
			networkRule.Flags |= Ipv4Match
			copy(networkRule.Address[:], ip.To4())
		} else {
			networkRule.Flags |= Ipv6Match
			copy(networkRule.Address[:], ip.To16())
		}
	}

	if port != 0 {
		networkRule.Flags |= PortMatch
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
		ValueSize:  NetRuleSize,
		MaxEntries: MaxBpfNetworkRuleCount,
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

func newBpfMountRule(sourcePattern string, fstype string, mountFlags uint32, reverseMountFlags uint32) (*bpfMountRule, error) {
	// Pre-check
	if len(fstype) >= MaxFileSystemTypeLength {
		return nil, fmt.Errorf("the length of fstype '%s' should be less than the maximum (%d)", fstype, MaxFileSystemTypeLength)
	}

	re, err := regexp2.Compile(`(?<!\*)\*(?!\*)`, regexp2.None)
	if err != nil {
		return nil, err
	}
	starWildcardLen := len(regexp2FindAllString(re, sourcePattern))

	if starWildcardLen > 0 && strings.Contains(sourcePattern, "**") {
		return nil, fmt.Errorf("the globbing * and ** in the pattern '%s' cannot be used at the same time", sourcePattern)
	}

	if starWildcardLen > 1 || strings.Count(sourcePattern, "**") > 1 {
		return nil, fmt.Errorf("the globbing * or ** in the pattern '%s' can only be used once", sourcePattern)
	}

	var mountRule bpfMountRule
	var flags uint32

	if starWildcardLen > 0 {
		if strings.Contains(sourcePattern, "/") {
			return nil, fmt.Errorf("the pattern '%s' with globbing * is not supported", sourcePattern)
		}
		stringList := strings.Split(sourcePattern, "*")

		var prefix, suffix [MaxFilePathPatternLength]byte
		if len(stringList[0]) > 0 {
			copy(prefix[:], stringList[0])
			mountRule.Prefix = prefix
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			copy(suffix[:], reverseString(stringList[1]))
			mountRule.Suffix = suffix
			flags |= SuffixMatch
		}
	} else if strings.Contains(sourcePattern, "**") {
		flags |= GreedyMatch

		stringList := strings.Split(sourcePattern, "**")

		var prefix, suffix [MaxFilePathPatternLength]byte
		if len(stringList[0]) > 0 {
			copy(prefix[:], stringList[0])
			mountRule.Prefix = prefix
			flags |= PrefixMatch
		}

		if len(stringList[1]) > 0 {
			copy(suffix[:], reverseString(stringList[1]))
			mountRule.Suffix = suffix
			flags |= SuffixMatch
		}
	} else {
		var prefix [MaxFilePathPatternLength]byte
		copy(prefix[:], sourcePattern)
		mountRule.Prefix = prefix
		flags |= PreciseMatch | PrefixMatch
	}

	if mountRule.Prefix[MaxFilePathPatternLength-1] != 0 {
		return nil, fmt.Errorf("the length of prefix '%s' should be less than the maximum (%d)", mountRule.Prefix, MaxFilePathPatternLength)
	}

	if mountRule.Suffix[MaxFilePathPatternLength-1] != 0 {
		return nil, fmt.Errorf("the length of suffix '%s' should be less than the maximum (%d)", mountRule.Suffix, MaxFilePathPatternLength)
	}

	mountRule.Flags = flags
	mountRule.MountFlags = mountFlags
	mountRule.ReverseMountFlags = reverseMountFlags

	var s [MaxFileSystemTypeLength]byte
	copy(s[:], fstype)
	mountRule.FsType = s

	return &mountRule, nil
}

func (enforcer *BpfEnforcer) SetMountMap(mntNsID uint32, mountRule *bpfMountRule) error {
	map_name := fmt.Sprintf("v_mount_inner_%d", mntNsID)
	innerMapSpec := ebpf.MapSpec{
		Name:       map_name,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  MountRuleSize,
		MaxEntries: MaxBpfMountRuleCount,
	}
	innerMap, err := ebpf.NewMap(&innerMapSpec)
	if err != nil {
		return err
	}
	defer innerMap.Close()

	var index uint32 = 0
	err = innerMap.Put(&index, mountRule)
	if err != nil {
		return err
	}

	return enforcer.objs.V_mountOuter.Put(&mntNsID, innerMap)
}

func (enforcer *BpfEnforcer) ClearMountMap(mntNsID uint32) error {
	return enforcer.objs.V_mountOuter.Delete(&mntNsID)
}

func (enforcer *BpfEnforcer) ReadFromAuditEventRingBuf() error {
	rd, err := ringbuf.NewReader(enforcer.objs.V_auditRb)
	if err != nil {
		return err
	}
	defer rd.Close()

	fmt.Println("[+] Waiting for events..")

	var event bpfAuditEvent
	for {
		record, err := rd.Read()
		if err != nil {
			fmt.Printf("[!] Reading from reader: %s", err)
			break
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Printf("[+] Parsing ringbuf event: %s", err)
			continue
		}

		if event.Mode == AuditMode {
			fmt.Println("PID:", event.Tgid)
			fmt.Println("Ktime:", event.Ktime)
			fmt.Println("Mount Namespace ID:", event.MntNs)
			switch event.Type {
			case FileType:
				fmt.Printf("Permissions: 0x%x\n", event.Path.Permissions)
				fmt.Println("Path:", unix.ByteSliceToString(event.Path.Path[:]))
			case BprmType:
				fmt.Printf("Permissions: 0x%x\n", event.Path.Permissions)
				fmt.Println("Path:", unix.ByteSliceToString(event.Path.Path[:]))
			case CapabilityType:
				fmt.Printf("Capability: 0x%x\n", event.Capability)
			case NetworkType:
				fmt.Printf("Egress SockType: 0x%x\n", event.Egress.SockType)
				if event.Egress.SaFamily == unix.AF_INET {
					ip := net.IPv4(byte(event.Egress.SinAddr), byte(event.Egress.SinAddr>>8), byte(event.Egress.SinAddr>>16), byte(event.Egress.SinAddr>>24))
					fmt.Println("Egress IPv4 address:", ip.String())
				} else {
					ip := net.IP(event.Egress.Sin6Addr[:])
					fmt.Println("Egress IPv6 address:", ip.String())
				}
				fmt.Println("Egress Port:", event.Egress.Port)
			}
		}
	}

	return nil
}
