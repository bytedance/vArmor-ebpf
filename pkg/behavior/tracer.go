// Note: This file is licenced differently from the rest of the project
// Copyright 2022 vArmor-ebpf Authors
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

package behavior

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type event bpf bpf/tracer.c -- -I./bpf/headers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"
)

const ratelimitSysctl = "/proc/sys/kernel/printk_ratelimit"

type EbpfTracer struct {
	objs           bpfObjects
	execLink       link.Link
	forkLink       link.Link
	reader         *perf.Reader
	eventChs       map[string]chan<- bpfEvent
	enabled        bool
	savedRateLimit uint64
	log            logr.Logger
}

func NewEbpfTracer(log logr.Logger) *EbpfTracer {
	tracer := EbpfTracer{
		objs:           bpfObjects{},
		eventChs:       make(map[string]chan<- bpfEvent),
		enabled:        false,
		savedRateLimit: 0,
		log:            log,
	}

	return &tracer
}

func (tracer *EbpfTracer) InitEBPF() error {
	// Allow the current process to lock memory for eBPF resources.
	tracer.log.Info("remove memory lock")
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("RemoveMemlock() failed: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	tracer.log.Info("load ebpf program and maps into the kernel")
	if err := loadBpfObjects(&tracer.objs, nil); err != nil {
		return fmt.Errorf("loadBpfObjects() failed: %v", err)
	}

	return nil
}

func (tracer *EbpfTracer) RemoveEBPF() error {
	tracer.log.Info("unload ebpf program")
	err := tracer.stopTracing()
	if err != nil {
		return err
	}
	return tracer.objs.Close()
}

func (tracer *EbpfTracer) setRateLimit() error {
	rateLimit, err := sysctl_read(ratelimitSysctl)
	if err != nil {
		return err
	}
	tracer.savedRateLimit, err = strconv.ParseUint(rateLimit, 10, 0)
	if err != nil {
		return err
	}
	if tracer.savedRateLimit != 0 {
		err := sysctl_write(ratelimitSysctl, 0)
		if err != nil {
			return err
		}
	}
	return nil
}

func (tracer *EbpfTracer) restoreRateLimit() error {
	if tracer.savedRateLimit != 0 {
		err := sysctl_write(ratelimitSysctl, tracer.savedRateLimit)
		if err != nil {
			return err
		}
	}
	return nil
}

func (tracer *EbpfTracer) startTracing() error {
	// Set printk_ratelimit to 0 for recording the audit logs of AppArmor
	err := tracer.setRateLimit()
	if err != nil {
		return fmt.Errorf("setRateLimit() failed: %v", err)
	}

	// Link to a sched_process_exec raw_tracepoint
	execLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: tracer.objs.TracepointSchedSchedProcessExec,
	})
	if err != nil {
		return fmt.Errorf("AttachRawTracepoint() failed: %v", err)
	}
	tracer.execLink = execLink

	// Link to a sched_process_fork raw_tracepoint
	forkLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: tracer.objs.TracepointSchedSchedProcessFork,
	})
	if err != nil {
		return fmt.Errorf("AttachRawTracepoint() failed: %v", err)
	}
	tracer.forkLink = forkLink

	// Open a perf event reader from kernel space on the BPF_MAP_TYPE_PERF_EVENT_ARRAY map
	reader, err := perf.NewReader(tracer.objs.Events, 8192*128)
	if err != nil {
		return fmt.Errorf("perf.NewReader() failed: %v", err)
	}
	tracer.reader = reader

	go tracer.traceSyscall()
	tracer.enabled = true

	tracer.log.Info("start tracing")

	return nil
}

func (tracer *EbpfTracer) stopTracing() error {
	tracer.log.Info("stop tracing")

	if tracer.reader != nil {
		tracer.reader.Close()
	}

	if tracer.execLink != nil {
		tracer.execLink.Close()
	}

	if tracer.forkLink != nil {
		tracer.forkLink.Close()
	}

	tracer.enabled = false

	err := tracer.restoreRateLimit()
	if err != nil {
		tracer.log.Error(err, "tracer.restoreRateLimit()")
	}

	return err
}

func (tracer *EbpfTracer) traceSyscall() {
	var event bpfEvent
	for {
		record, err := tracer.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				tracer.log.V(3).Info("perf buffer reader is closed")
				return
			}
			tracer.log.Error(err, "reading from perf buffer failed")
			continue
		}

		if record.LostSamples != 0 {
			tracer.log.Info("perf buffer is full, some events was dropped", "dropped count", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			tracer.log.Error(err, "parsing perf event failed")
			continue
		}

		eventChs := tracer.eventChs
		for _, eventCh := range eventChs {
			eventCh <- event
		}
	}
}

func (tracer *EbpfTracer) AddEventCh(uniqueID string, ch chan bpfEvent) {
	tracer.eventChs[uniqueID] = ch

	if len(tracer.eventChs) == 1 && !tracer.enabled {
		err := tracer.startTracing()
		if err != nil {
			tracer.log.Error(err, "failed to enable tracing")
		}
	}
}

func (tracer *EbpfTracer) DeleteEventCh(uniqueID string) {
	delete(tracer.eventChs, uniqueID)

	if len(tracer.eventChs) == 0 {
		tracer.stopTracing()
	}
}
