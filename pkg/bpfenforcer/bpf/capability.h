// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __CAPABILITY_H
#define __CAPABILITY_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"

#define CAP_LAST_CAP 40
#define CAP_TO_MASK(x) (1ULL << x)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, OUTER_MAP_ENTRIES_MAX);
} v_capable SEC(".maps");

static __always_inline u64 *get_capability_rules(u32 mnt_ns) {
    return bpf_map_lookup_elem(&v_capable, &mnt_ns);
}

#endif /* __CAPABILITY_H */