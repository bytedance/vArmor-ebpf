// Note: This file is licenced differently from the rest of the project
// Copyright 2024 vArmor-ebpf Authors
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
	NetRuleSize = 4*3 + 8*3 + IpAddressSize*2

	// MaxFileSystemTypeLength is the max length of fstype pattern,
	// it's equal to FILE_SYSTEM_TYPE_MAX in BPF code
	MaxFileSystemTypeLength = 16

	// MountRuleSize is the size of `struct mount_rule` in BPF code, it's
	// also the value size of the inner map for mount access control.
	MountRuleSize = 4*3 + MaxFileSystemTypeLength + PathPatternSize

	// BPF enforcer running mode.
	EnforceMode  = 0x00000001
	AuditMode    = 0x00000002
	ComplainMode = 0x00000004

	// Matching Flag
	PreciseMatch = 0x00000001
	GreedyMatch  = 0x00000002
	PrefixMatch  = 0x00000004
	SuffixMatch  = 0x00000008

	// Matching Flag for Network Rule
	CidrMatch   = 0x00000020
	Ipv4Match   = 0x00000040
	Ipv6Match   = 0x00000080
	PortMatch   = 0x00000100
	SocketMatch = 0x00000200

	// Matching Permission
	AaMayExec     = 0x00000001
	AaMayWrite    = 0x00000002
	AaMayRead     = 0x00000004
	AaMayAppend   = 0x00000008
	AaPtraceTrace = 0x00000002
	AaPtraceRead  = 0x00000004
	AaMayBeTraced = 0x00000008
	AaMayBeRead   = 0x00000010
	AaMayUmount   = 0x00000200

	// Event Type
	CapabilityType = 0x00000001
	FileType       = 0x00000002
	BprmType       = 0x00000004
	NetworkType    = 0x00000008
	PtraceType     = 0x00000010
	MountType      = 0x00000020

	// Event Subtype for Network Event
	ConnectType = 0x00000001
	SocketType  = 0x00000002

	// EventHeaderSize is the size of bpf audit event header
	EventHeaderSize = 24

	// PinPath is the path we want to pin the maps
	PinPath = "/sys/fs/bpf/varmor"

	// AuditRingBufPinPath is the path we pin the audit ringbuf
	AuditRingBufPinPath = "/sys/fs/bpf/varmor/v_audit_rb"
)
