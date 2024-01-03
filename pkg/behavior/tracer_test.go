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

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"gotest.tools/assert"
	"k8s.io/klog/v2/klogr"
	log "sigs.k8s.io/controller-runtime/pkg/log"
)

func Test_loadEbpf(t *testing.T) {

	log.SetLogger(klogr.New())
	tracer := NewEbpfTracer(log.Log.WithName("ebpf"))

	err := tracer.InitEBPF()
	assert.NilError(t, err)
	err = tracer.RemoveEBPF()
	assert.NilError(t, err)
}

func Test_customData(t *testing.T) {

	eventCh := make(chan bpfEvent, 200)

	log.SetLogger(klogr.New())
	tracer := NewEbpfTracer(log.Log.WithName("ebpf"))
	err := tracer.InitEBPF()
	assert.NilError(t, err)
	defer tracer.RemoveEBPF()

	tracer.AddEventCh("TEST", eventCh)

	stopTicker := time.NewTicker(3 * time.Second)
	runTicker := time.NewTicker(2 * time.Second)

	var mntNsID, mntCount, initPid, pidCount uint32

LOOP:
	for {
		select {
		case <-runTicker.C:
			cmd := exec.Command("ping", "-c", "10", "127.0.0.1")
			cmd.Start()
			initPid = uint32(cmd.Process.Pid)
			mntNsID, err = readMntNsID(uint32(cmd.Process.Pid))
			assert.NilError(t, err)

		case <-stopTicker.C:
			break LOOP

		case event := <-eventCh:

			len := indexOfZero(event.ParentTask[:])
			parentTask := string(event.ParentTask[:len])

			len = indexOfZero(event.ChildTask[:])
			childTask := string(event.ChildTask[:len])

			len = indexOfZero(event.Filename[:])
			fileName := string(event.Filename[:len])

			eventType := ""
			if event.Type == 1 {
				eventType = "sched_process_fork"
			} else {
				eventType = "sched_process_exec"
			}
			output := fmt.Sprintf("%-24s |%-12d %-12d %-20s | %-12d %-12d %-20s | %-12d %s\n",
				eventType,
				event.ParentPid, event.ParentTgid, parentTask,
				event.ChildPid, event.ChildTgid, childTask,
				event.MntNsId, fileName,
			)
			fmt.Println(output)

			if event.MntNsId == mntNsID {
				mntCount += 1
			}

			if event.ParentTgid == initPid || event.ChildTgid == initPid {
				pidCount += 1
			}
		}
	}
	assert.Equal(t, true, mntCount > 0)
	assert.Equal(t, true, pidCount > 0)
}
