package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// This directive triggers the BPF compiler. -D__TARGET_ARCH_x86 is vital for register mapping.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang Bpf ./bpf/profiler.c -- -I./bpf -D__TARGET_ARCH_x86

// ProcessStat helps us group data by name for sorting.
type ProcessStat struct {
	Name     string
	DiskRead uint64
	NetIO    uint64
}

func main() {
	// Parse CLI flags
	topN := flag.Int("n", 10, "Number of top processes to show")
	flag.Parse()

	// eBPF maps are 'locked' memory. We must lift the limit so the kernel can allocate them.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to lift memlock limit:", err)
	}

	// Load our compiled BPF bytecode into the kernel.
	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Attach our handlers to the kernel tracepoints.
	// We use sys_exit here to get the actual return value (byte count).
	tpRead, _ := link.Tracepoint("syscalls", "sys_exit_read", objs.HandleDiskReadExit, nil)
	tpSend, _ := link.Tracepoint("syscalls", "sys_exit_sendto", objs.HandleNetSendExit, nil)
	tpRecv, _ := link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.HandleNetRecvExit, nil)
	
	// Ensure we detach when the program exits.
	defer tpRead.Close()
	defer tpSend.Close()
	defer tpRecv.Close()

	// Handle graceful shutdown on Ctrl+C.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Profiler running... gathering data...")
	ticker := time.NewTicker(1 * time.Second)

	for {
		select {
		case <-ticker.C:
			// Aggregator map keys by Process Name instead of PID to resolve duplicates.
			aggregator := make(map[string]*ProcessStat)

			// 1. Process Disk Data
			var pid uint32
			var data BpfDataT
			itDisk := objs.DiskStats.Iterate()
			for itDisk.Next(&pid, &data) {
				comm := unixByteToString(data.Comm)
				if _, ok := aggregator[comm]; !ok {
					aggregator[comm] = &ProcessStat{Name: comm}
				}
				aggregator[comm].DiskRead += data.Bytes
			}

			// 2. Process Network Data
			itNet := objs.NetStats.Iterate()
			for itNet.Next(&pid, &data) {
				comm := unixByteToString(data.Comm)
				if _, ok := aggregator[comm]; !ok {
					aggregator[comm] = &ProcessStat{Name: comm}
				}
				aggregator[comm].NetIO += data.Bytes
			}

			// 3. Sort by total I/O (Disk + Net) descending.
			stats := []ProcessStat{}
			for _, v := range aggregator {
				stats = append(stats, *v)
			}
			sort.Slice(stats, func(i, j int) bool {
				return (stats[i].DiskRead + stats[i].NetIO) > (stats[j].DiskRead + stats[j].NetIO)
			})

			// 4. Update the terminal view.
			renderUI(stats, *topN)

		case <-stop:
			fmt.Println("\nDetaching and cleaning up...")
			return
		}
	}
}

// formatBytes turns raw numbers like 1024 into "1.00 KB"
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// renderUI clears the screen and prints the sorted table.
func renderUI(stats []ProcessStat, n int) {
	fmt.Print("\033[H\033[2J") // ANSI clear screen
	fmt.Printf("eBPF System I/O Profiler | Top %d Processes\n", n)
	fmt.Printf("%-25s %-15s %-15s\n", "PROCESS NAME", "DISK READ", "NET I/O")
	fmt.Println("------------------------------------------------------------")

	for i := 0; i < n && i < len(stats); i++ {
		fmt.Printf("%-25s %-15s %-15s\n", 
			stats[i].Name, 
			formatBytes(stats[i].DiskRead), 
			formatBytes(stats[i].NetIO))
	}
}

// unixByteToString converts a null-terminated [16]int8 C array into a Go string.
func unixByteToString(b [16]int8) string {
	var buf []byte
	for _, v := range b {
		if v == 0 {
			break
		}
		buf = append(buf, byte(v))
	}
	if len(buf) == 0 {
		return "unknown"
	}
	return string(buf)
}