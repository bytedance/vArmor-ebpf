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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type audit_event bpf bpf/enforcer.c -- -I../../headers

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
	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"
)

type BpfEnforcer struct {
	objs            bpfObjects
	capableLink     link.Link
	openFileLink    link.Link
	pathSymlinkLink link.Link
	pathLinkLink    link.Link
	pathRenameLink  link.Link
	bprmLink        link.Link
	sockConnLink    link.Link
	socketLink      link.Link
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
		return 0, fmt.Errorf("fatel error: can not parser mnt ns id from: %s", realPath)
	}

	id := realPath[index+1 : len(realPath)-1]
	u64, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("fatel error: can not transform mnt ns id (%s) to uint64 type", realPath)
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
	collectionSpec.Variables["init_mnt_ns"].Set(initMntNsId)

	if err := os.MkdirAll(PinPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create bpf fs subpath: %+v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	enforcer.log.Info("load ebpf program and maps into the kernel")
	err = collectionSpec.LoadAndAssign(&enforcer.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: PinPath,
		},
	})
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
	enforcer.log.Info("unping ebpf map")
	enforcer.objs.V_auditRb.Unpin()
	os.RemoveAll(PinPath)
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

	socketLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorSocketCreate,
	})
	if err != nil {
		return err
	}
	enforcer.socketLink = socketLink

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
	enforcer.socketLink.Close()
	enforcer.ptraceLink.Close()
	enforcer.mountLink.Close()
	enforcer.moveMountLink.Close()
	enforcer.umountLink.Close()
}

func (enforcer *BpfEnforcer) SetCapableMap(mntNsID uint32, capabilityRule *bpfCapabilityRule) error {
	return enforcer.objs.V_capable.Put(&mntNsID, capabilityRule)
}

func (enforcer *BpfEnforcer) ClearCapableMap(mntNsID uint32) error {
	return enforcer.objs.V_capable.Delete(&mntNsID)
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

func (enforcer *BpfEnforcer) SetNetMap(mntNsID uint32, networkRules []bpfNetworkRule) error {
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

	for i, rule := range networkRules {
		index := uint32(i)
		err = innerMap.Put(&index, rule)
		if err != nil {
			return err
		}
	}

	return enforcer.objs.V_netOuter.Put(&mntNsID, innerMap)
}

func (enforcer *BpfEnforcer) ClearNetMap(mntNsID uint32) error {
	return enforcer.objs.V_netOuter.Delete(&mntNsID)
}

func (enforcer *BpfEnforcer) SetPtraceMap(mntNsID uint32, ptraceRule *bpfPtraceRule) error {
	return enforcer.objs.V_ptrace.Put(&mntNsID, ptraceRule)
}

func (enforcer *BpfEnforcer) ClearPtraceMap(mntNsID uint32) error {
	return enforcer.objs.V_ptrace.Delete(&mntNsID)
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

func (enforcer *BpfEnforcer) ReadFromAuditEventRingBuf(ringbufMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return err
	}
	defer rd.Close()

	fmt.Println("[+] Waiting for events..")

	var eventHeader bpfEventHeader
	for {
		// Read audit event from the bpf ringbuf
		record, err := rd.Read()
		if err != nil {
			fmt.Printf("[!] Reading from reader: %s", err)
			break
		}
		fmt.Println("[+] The minimum number of bytes remaining in the ring buffer:", record.Remaining)

		// Parse the header of audit event
		if err := binary.Read(bytes.NewBuffer(record.RawSample[:EventHeaderSize]), binary.LittleEndian, &eventHeader); err != nil {
			fmt.Printf("[+] Parsing ringbuf event: %s", err)
			continue
		}

		// Process the body of audit event
		if eventHeader.Mode&AuditMode == AuditMode {
			fmt.Println("PID:", eventHeader.Tgid)
			fmt.Println("Ktime:", eventHeader.Ktime)
			fmt.Println("Mount Namespace ID:", eventHeader.MntNs)
			switch eventHeader.Type {
			case CapabilityType:
				// Parse the event body of capability
				var event bpfCapabilityEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Printf("Capability: 0x%x\n", event.Capability)

			case FileType:
				// Parse the event body of file operation
				var event bpfPathEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Printf("Permissions: 0x%x\n", event.Permissions)
				fmt.Println("Path:", unix.ByteSliceToString(event.Path[:]))

			case BprmType:
				// Parse the event body of execution file
				var event bpfPathEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Printf("Permissions: 0x%x\n", event.Permissions)
				fmt.Println("Path:", unix.ByteSliceToString(event.Path[:]))

			case NetworkType:
				// Parse the event body of network egress
				var event bpfNetworkEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					fmt.Println(err)
				}

				switch event.Type {
				case ConnectType:
					if event.Addr.SaFamily == unix.AF_INET {
						ip := net.IPv4(byte(event.Addr.SinAddr), byte(event.Addr.SinAddr>>8), byte(event.Addr.SinAddr>>16), byte(event.Addr.SinAddr>>24))
						fmt.Println("Egress IPv4 address:", ip.String())
					} else {
						ip := net.IP(event.Addr.Sin6Addr[:])
						fmt.Println("Egress IPv6 address:", ip.String())
					}
					fmt.Println("Egress Port:", event.Addr.Port)
				case SocketType:
					fmt.Println("Socket Domain", event.Socket.Domain)
					fmt.Println("Socket Type", event.Socket.Type)
					fmt.Println("Socket Protocol", event.Socket.Protocol)
				}

			case PtraceType:
				// Parse the event body of ptrace operation
				var event bpfPtraceEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println("Permissions:", event.Permissions)
				fmt.Println("Externel:", event.External)

			case MountType:
				// Parse the event body of mount operation
				var event bpfMountEvent
				err := binary.Read(bytes.NewBuffer(record.RawSample[EventHeaderSize:]), binary.LittleEndian, &event)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println("Device Name:", unix.ByteSliceToString(event.DevName[:]))
				fmt.Println("FileSystem Type:", unix.ByteSliceToString(event.Type[:]))
				fmt.Println("Flags:", event.Flags)
			}
		}
	}

	return nil
}

func (enforcer *BpfEnforcer) LoadMap() (ringbufMap *ebpf.Map, err error) {
	m, err := ebpf.LoadPinnedMap(AuditRingBufPinPath, nil)
	if err != nil {
		fmt.Println("LoadPinnedMap()", err)
		return nil, err
	}
	return m, nil
}
