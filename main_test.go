package main

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func TestDiskIOAccuracy(t *testing.T) {
	// 1. Setup eBPF environment
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("failed to remove memlock: %v", err)
	}

	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// 2. Attach the read tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_exit_read", objs.HandleDiskReadExit, nil)
	if err != nil {
		t.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	// 3. Prepare a test file (1MB of random data)
	testData := bytes.Repeat([]byte{0x42}, 1024*1024) // Exactly 1,048,576 bytes
	tmpFile, err := os.CreateTemp("", "ebpf_test_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close and reopen to ensure we are reading from disk/cache via syscalls

	// 4. Trigger the I/O
	// We use os.ReadFile which internally calls the 'read' syscall.
	f, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	
	// Get our current PID to look up in the map later
	currentPid := uint32(os.Getpid())
	
	buf := make([]byte, 1024*1024)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// 5. Verify accuracy
	// Give the kernel a few milliseconds to finish the tracepoint execution
	time.Sleep(50 * time.Millisecond)

	var data BpfDataT
	err = objs.DiskStats.Lookup(currentPid, &data)
	if err != nil {
		t.Fatalf("PID %d not found in BPF map. Did the probe trigger?", currentPid)
	}

	if data.Bytes != uint64(n) {
		t.Errorf("Accuracy Mismatch! Expected %d bytes, BPF caught %d bytes", n, data.Bytes)
	} else {
		t.Logf("Success! BPF caught exactly %s", formatBytes(data.Bytes))
	}
}