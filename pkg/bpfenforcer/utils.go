package bpfenforcer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	nsPIDMap   = make(map[uint32]int) // nsID -> PID
	pidNsIDMap = make(map[int]uint32) // PID -> nsID
	mapMutex   sync.Mutex
)

// getMountNsID retrieve the mount ns id from procfs
func getMountNsID(pid int) (uint32, error) {
	linkPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	link, err := os.Readlink(linkPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read the mnt ns link")
	}

	parts := strings.SplitN(link, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid namespace format")
	}
	idStr := strings.Trim(parts[1], "[]")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse the mount ns id")
	}
	return uint32(id), nil
}

// CreateTestNamespace creates a new mount namespace.
// It will return the mount ns id and its cleanup function.
func CreateTestNamespace(t *testing.T) (uint32, func(), error) {
	initialNsID, _ := getMountNsID(1)

	cmd := exec.Command("unshare", "-m", "sh", "-c", "sleep 600 & wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return 0, nil, fmt.Errorf("failed to start the process within a new mount ns: %w", err)
	}
	pid := cmd.Process.Pid

	var nsID uint32
	err := wait.PollUntilContextTimeout(
		context.Background(),
		100*time.Millisecond,
		5*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			currentNsID, err := getMountNsID(pid)
			if err != nil {
				return false, nil
			}

			if currentNsID != initialNsID {
				nsID = currentNsID
				return true, nil
			}
			return false, nil
		},
	)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to retrieve the mount ns id of the process (PID: %d): %w", pid, err)
	}

	mapMutex.Lock()
	nsPIDMap[nsID] = pid
	pidNsIDMap[pid] = nsID
	mapMutex.Unlock()

	cleanup := func() {
		mapMutex.Lock()
		delete(nsPIDMap, nsID)
		delete(pidNsIDMap, pid)
		mapMutex.Unlock()

		if err := cmd.Process.Kill(); err != nil {
			t.Logf("failed to kill the process (PID: %d): %v", pid, err)
		}
		cmd.Wait()
	}

	t.Logf("Successfully created the test namespace (PID: %d   MountNsID: %d)", pid, nsID)
	return nsID, cleanup, nil
}

// getPidByMountNsID return the PID corresponding to the mount ns id
func getPidByMountNsID(nsID uint32) (int, error) {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	pid, exists := nsPIDMap[nsID]
	if !exists {
		return 0, fmt.Errorf("can't find the process corresponding to the nsID %d", nsID)
	}

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
		delete(nsPIDMap, nsID)
		delete(pidNsIDMap, pid)
		return 0, fmt.Errorf("the process %d no longer exists", pid)
	}

	return pid, nil
}

// RunCommandInNamespace runs comand in the mount ns
func RunCommandInNamespace(nsID uint32, command string, args ...string) (string, error) {
	pid, err := getPidByMountNsID(nsID)
	if err != nil {
		return "", fmt.Errorf("failed to obtain the namespace process: %w", err)
	}

	cmdArgs := []string{
		"-m",
		"-t", strconv.Itoa(pid),
		"--",
		command,
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("nsenter", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command execution failed: %w (Output: %s)", err, output)
	}

	return string(output), nil
}
