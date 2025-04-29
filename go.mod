module github.com/bytedance/vArmor-ebpf

go 1.23.0

toolchain go1.23.7

require (
	github.com/cilium/ebpf v0.17.3
	github.com/dlclark/regexp2 v1.9.0
	github.com/go-logr/logr v1.4.2
	golang.org/x/sys v0.32.0
	gotest.tools v2.2.0+incompatible
	k8s.io/apimachinery v0.31.1
	k8s.io/klog/v2 v2.130.1
	sigs.k8s.io/controller-runtime v0.14.5
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20250423184734-337e5dd93bb4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/tools v0.32.0 // indirect
	k8s.io/utils v0.0.0-20241104100929-3ea5e8cea738 // indirect
)
