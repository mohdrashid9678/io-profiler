package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang Bpf ./bpf/profiler.c -- -I./bpf -D__TARGET_ARCH_x86

func main() {
	// 1. Lift memory limits
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }

    // 2. Load the BPF objects (This is the missing step!)
    // This actually takes the bytecode from the ELF file, 
    // pushes it into the kernel, and populates the 'objs' struct.
    objs := BpfObjects{}
    if err := LoadBpfObjects(&objs, nil); err != nil {
        log.Fatalf("loading objects: %v", err)
    }
    defer objs.Close() // Clean up maps and progs when the app exits

    // 3. Attach the Tracepoint
    // Now objs.HandleReadEnter is a valid pointer to a program in the kernel
    tp, err := link.Tracepoint("syscalls", "sys_enter_read", objs.HandleReadEnter, nil)
    if err != nil {
        log.Fatalf("opening tracepoint: %s", err)
    }
    defer tp.Close()

    fmt.Printf("%-10s %-20s\n", "PID", "BYTES READ")
    fmt.Println("-------------------------------")

	ticker := time.NewTicker(1 * time.Second)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			var pid uint32
			var bytes uint64
			// Iterate through all entries in the BPF map
			entries := objs.IoStats.Iterate()
			for entries.Next(&pid, &bytes) {
				fmt.Printf("%-10d %-20d\n", pid, bytes)
			}
			if err := entries.Err(); err != nil {
				log.Printf("error iterating map: %v", err)
			}
		case <-stop:
			log.Println("Stopping...")
			return
		}
	}
}