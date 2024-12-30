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

import (
	"fmt"
	"net"
	"strings"

	"github.com/dlclark/regexp2"
)

func newBpfCapabilityRule(mode uint32, capabilities uint64) (*bpfCapabilityRule, error) {
	var capabilityRule bpfCapabilityRule
	capabilityRule.Mode = mode
	capabilityRule.Caps = capabilities
	return &capabilityRule, nil
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

func newBpfNetworkConnectRule(mode uint32, cidr string, ipAddress string, port uint32) (*bpfNetworkRule, error) {
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

func newBpfNetworkCreateRule(mode uint32, domains uint64, types uint64, protocols uint64) (*bpfNetworkRule, error) {
	if types != 0 && protocols != 0 {
		return nil, fmt.Errorf("types and protocols cannot be set at the same time")
	}
	if domains == 0 && types == 0 && protocols == 0 {
		return nil, fmt.Errorf("domains, types and protocols cannot be empty at the same time")
	}

	return &bpfNetworkRule{
		Mode:      mode,
		Flags:     SocketMatch,
		Domains:   domains,
		Types:     types,
		Protocols: protocols,
	}, nil
}

func newBpfPtraceRule(mode uint32, permissions uint32, flags uint32) (*bpfPtraceRule, error) {
	return &bpfPtraceRule{
		Mode:        mode,
		Permissions: permissions,
		Flags:       flags,
	}, nil
}

func newBpfMountRule(mode uint32, sourcePattern string, fstype string, mountFlags uint32, reverseMountFlags uint32) (*bpfMountRule, error) {
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

	mountRule.Mode = mode

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