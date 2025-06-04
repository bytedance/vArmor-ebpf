package main

import (
	bpfenforcer "github.com/bytedance/vArmor-ebpf/pkg/bpfenforcer"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func main() {
	c := textlogger.NewConfig()
	log.SetLogger(textlogger.NewLogger(c))
	e := bpfenforcer.NewBpfEnforcer(log.Log.WithName("ebpf"))
	err := e.InitEBPF()
	if err != nil {
		log.Log.Error(err, "init ebpf failed")
		return
	}
	defer e.RemoveEBPF()
	err = e.StartEnforcing()
	if err != nil {
		log.Log.Error(err, "start enforcing failed")
		return
	}
	defer e.StopEnforcing()
}
