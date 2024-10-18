// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __PTRACE_H
#define __PTRACE_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "perms.h"

struct ptrace_rule {
  u32 mode;
	u32 permissions;
  u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct ptrace_rule);
	__uint(max_entries, OUTER_MAP_ENTRIES_MAX);
} v_ptrace SEC(".maps");

static __always_inline struct ptrace_rule *get_ptrace_rule(u32 mnt_ns) {
    return bpf_map_lookup_elem(&v_ptrace, &mnt_ns);
}

static __always_inline bool ptrace_permission_check(u32 current_mnt_ns, u32 child_mnt_ns, struct ptrace_rule *rule, u32 request_permission) {
  DEBUG_PRINT("current task(mnt ns: %u) request the vArmor ptrace permission(0x%x) of child task(mnt ns: %u)", 
          current_mnt_ns, request_permission, child_mnt_ns);

  if (rule->permissions & request_permission) {
    // deny all tasks
    if (rule->flags & GREEDY_MATCH) {
      DEBUG_PRINT("access denied");
      return false;
    }

    // only deny tasks outside the container
    if (rule->flags & PRECISE_MATCH && current_mnt_ns != child_mnt_ns) {
      DEBUG_PRINT("access denied");
      return false;
    }
  }

  DEBUG_PRINT("access allowed");
  return true;
}

#endif /* __PTRACE_H */