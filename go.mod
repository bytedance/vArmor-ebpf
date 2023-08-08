module github.com/bytedance/vArmor-ebpf

go 1.19

require (
	github.com/cilium/ebpf v0.10.0
	github.com/dlclark/regexp2 v1.9.0
	github.com/go-logr/logr v1.2.3
	golang.org/x/sys v0.6.0
	gotest.tools v2.2.0+incompatible
	k8s.io/klog/v2 v2.90.1
	sigs.k8s.io/controller-runtime v0.14.5
)

require (
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/pkg/errors v0.9.1 // indirect
)
