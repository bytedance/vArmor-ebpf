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
	MaxBpfFileRuleCount = 50

	// MaxFilePathPatternLength is the max length of path pattern,
	// it's equal to FILE_PATH_PATTERN_SIZE_MAX in BPF code
	MaxFilePathPatternLength = 64

	// PathPatternSize is the size of pathPattern in bpfPathRule structure
	PathPatternSize = 4 + MaxFilePathPatternLength*2

	// PathRuleSize is the size of bpfPathRule structure, which must match
	// the size of `struct path_rule` in BPF code for consistent map entry size.
	PathRuleSize = 4*2 + PathPatternSize

	// PinPath is the path we want to pin the maps
	PinPath = "/sys/fs/bpf/varmor"

	// AuditRingBufPinPath is the path we pin the audit ringbuf
	AuditRingBufPinPath = "/sys/fs/bpf/varmor/v_audit_rb"
)
