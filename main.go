package main

import (
	"context"
	"ehids/user"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	logger := log.Default()
	for k, probe := range user.ProbeMaps {
		if probe.ProbeName() != "EBPFProbeUJavaRASP" && probe.ProbeName() != "EBPFProbeProc" {
			continue
		}

		logger.Printf("start to run %s probe", k)
		//初始化
		err := probe.Init(ctx, logger)
		if err != nil {
			panic(err)
		}

		// 加载ebpf，挂载到hook点上，开始监听
		go func(probe user.IBPFProbe) {
			err := probe.Run()
			if err != nil {
				logger.Fatalf("%v", err)
			}
		}(probe)
	}

	<-stopper
	cancelFun()

	logger.Println("Received signal, exiting program..")
	time.Sleep(time.Millisecond * 100)
}
