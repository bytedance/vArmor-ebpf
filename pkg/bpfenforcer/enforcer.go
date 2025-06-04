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
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"
)

type BpfEnforcer struct {
	objs           bpfObjects
	pathRenameLink link.Link
	log            logr.Logger
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
	pathRenameLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcer.objs.VarmorPathRename,
	})
	if err != nil {
		return err
	}
	enforcer.pathRenameLink = pathRenameLink

	enforcer.log.Info("start enforcing")

	return nil
}

func (enforcer *BpfEnforcer) StopEnforcing() {
	enforcer.log.Info("stop enforcing")
	enforcer.pathRenameLink.Close()
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

func (enforcer *BpfEnforcer) LoadMap() (ringbufMap *ebpf.Map, err error) {
	m, err := ebpf.LoadPinnedMap(AuditRingBufPinPath, nil)
	if err != nil {
		fmt.Println("LoadPinnedMap()", err)
		return nil, err
	}
	return m, nil
}
