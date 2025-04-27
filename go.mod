module github.com/bytedance/vArmor-ebpf

go 1.23.0

toolchain go1.23.7

require (
	github.com/cilium/ebpf v0.17.3
	github.com/dlclark/regexp2 v1.9.0
	github.com/go-logr/logr v1.4.2
	golang.org/x/sys v0.31.0
	gotest.tools v2.2.0+incompatible
	k8s.io/klog/v2 v2.130.1
	sigs.k8s.io/controller-runtime v0.14.5
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sync v0.8.0 // indirect
)
