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

// Rule definition of file policy primitive
type bpfPathRule struct {
	Mode        uint32
	Permissions uint32
	Flags       uint32
	Prefix      [MaxFilePathPatternLength]byte
	Suffix      [MaxFilePathPatternLength]byte
}

// Rule definition of network policy primitive
type bpfNetworkRule struct {
	Mode      uint32
	Flags     uint32
	Domains   uint64
	Types     uint64
	Protocols uint64
	Address   [IPAddressSize]byte
	Mask      [IPAddressSize]byte
	Port      uint16
	EndPort   uint16
	Ports     [MaxPortsCount]uint16
}

// Rule definition of mount policy primitive
type bpfMountRule struct {
	Mode              uint32
	MountFlags        uint32
	ReverseMountFlags uint32
	Flags             uint32
	Prefix            [MaxFilePathPatternLength]byte
	Suffix            [MaxFilePathPatternLength]byte
	FsType            [MaxFileSystemTypeLength]byte
}

// Audit Event
type bpfEventHeader struct {
	Mode  uint32
	Type  uint32
	MntNs uint32
	Tgid  uint32
	Ktime uint64
}

type bpfCapabilityEvent struct {
	Capability uint32
}

type bpfPathEvent struct {
	Permissions uint32
	Path        [4096]byte
	Padding     [20]byte
}

type bpfNetworkSocket struct {
	Domain   uint32
	Type     uint32
	Protocol uint32
}

type bpfNetworkSockAddr struct {
	SaFamily uint32
	SinAddr  uint32
	Sin6Addr [16]byte
	Port     uint16
}

type bpfNetworkEvent struct {
	Type   uint32
	Socket bpfNetworkSocket
	Addr   bpfNetworkSockAddr
}

type bpfPtraceEvent struct {
	Permissions uint32
	External    bool
}

type bpfMountEvent struct {
	DevName [4096]byte
	Type    [16]byte
	Flags   uint32
}
