// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf csl.bpf.c -- -I./headers -I./csl-headers

const (
	mapKey                 uint32 = 0
	counterKey             uint32 = 1
	initDelay, initCounter uint64 = 0, 0
)

func main() {
	fmt.Print("Enter a pid: ")
	var number int32
	_, err := fmt.Fscan(os.Stdin, &number)
	if err != nil {
		fmt.Println(err)
	}
	cgroupPath := "/sys/fs/cgroup/perf_event/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod6497db01_04d2_4777_aad2_f4da0c54e3d8.slice/cri-containerd-c7ff7422d017ad9099ae4f56a0a81bb23442e55258709f171568aedb7a7bceb0.scope"
	f, _ := os.Open(cgroupPath)
	fd := f.Fd()
	defer f.Close()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	args := &bpfArgs{
		TargPid: number,
	}
	objs.Argmap.Put(uint32(0), args)
	objs.Cgroup.Put(uint32(0), uint32(fd))
	objs.Events.Put(mapKey, initDelay)
	objs.Events.Put(counterKey, initCounter)

	// Open a tracepoint and attach the pre-compiled program.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/debug/tracing/events/sched/sched_wakeup
	tpWakeup, err := link.Tracepoint("sched", "sched_wakeup", objs.HandleSchedWakeup, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tpWakeup.Close()

	tpWakeupNew, err := link.Tracepoint("sched", "sched_wakeup_new", objs.HandleSchedWakeupNew, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tpWakeupNew.Close()

	tpSwitch, err := link.Tracepoint("sched", "sched_switch", objs.HandleSwitch, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tpSwitch.Close()

	// Open a perf reader from userspace into the perf event array
	// created earlier.
	// rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	//if err != nil {
	//	log.Fatalf("creating event reader: %s", err)
	//}
	//defer rd.Close()

	// todo: Read loop compute and report the CPU Schedule Latency every 10 seconds.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		// read raw record from BPF map
		// record, err := rd.Read()
		//if err != nil {
		//	if errors.Is(err, perf.ErrClosed) {
		//		log.Println("Received signal, exiting..")
		//		return
		//	}
		//	log.Printf("reading from reader: %s", err)
		//	continue
		//}
		var value uint64
		if err := objs.Events.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("Record: %vns\n", value)
		var counter uint64
		if err := objs.Events.Lookup(counterKey, &counter); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("Counter: %vswitches\n", counter)
		avgDelay := uint64(0)
		if counter >= 0 {
			avgDelay = value / counter
		}
		log.Printf("Avg Delay: %vns\n", avgDelay)

		if err := objs.Pids.Lookup(mapKey, &value); err != nil {
			log.Fatalf("current pid error: %v", err)
		}
		log.Printf("current pid: %vns\n", value)
		if err := objs.Pids.Lookup(counterKey, &counter); err != nil {
			log.Fatalf("ctx pid error: %v", err)
		}
		log.Printf("ctx pid: %v\n", counter)

		objs.Events.Update(mapKey, initDelay, ebpf.UpdateAny)
		objs.Events.Update(counterKey, initCounter, ebpf.UpdateAny)

		// compute cpu sched latency
		//value := handle_event(record)
		//log.Printf("cpu schedule latency of %v: %v", cgroupPath, value)
	}
}

//func handle_event(record perf.Record) uint64{
//	record.RawSample
//	return 0
//}
