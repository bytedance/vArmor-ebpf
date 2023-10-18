// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __PROCESS_H
#define __PROCESS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "perms.h"

#define BPRM_INNER_MAP_ENTRIES_MAX 50

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, OUTER_MAP_ENTRIES_MAX);
  __type(key, u32);
  __type(value, u32);
} v_bprm_outer SEC(".maps");

static u32 *get_bprm_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_bprm_outer, &mnt_ns);
}

static struct path_rule *get_bprm_rule(u32 *vbprm_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vbprm_inner, &rule_id);
}

static __noinline int iterate_bprm_inner_map_for_executable(u32 *vbprm_inner, struct buffer *buf, struct buffer_offset *offset) {
  for(int inner_id=0; inner_id<BPRM_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct path_rule *rule = get_bprm_rule(vbprm_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    DEBUG_PRINT("rule permissions: 0x%x", rule->permissions);

    // Permission check
    if (head_path_check(&rule->pattern, buf, offset)) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access denied");
      return -EPERM;
    }
  }

  DEBUG_PRINT("");
  DEBUG_PRINT("access allowed");
  return 0;
}

#endif /* __PROCESS_H */