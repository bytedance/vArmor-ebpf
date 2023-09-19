// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __PROCESS_H
#define __PROCESS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "file.h"
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

static __noinline int prepend_bprm_path_to_first_block(const char *filename, struct buffer *buf, struct buffer_offset *buf_offset) {
  int ret = bpf_probe_read_kernel_str(buf->value, PATH_MAX, filename);
  if (ret >= 0) {
    buf_offset->first_path = ret;
  } else {
    return -1;
  }

  int index = 0;
  for (; index < NAME_MAX; index++) {
    if (buf->value[(buf_offset->first_path - 1 - index) & (PATH_MAX - 1)] == '/')
      break;
  }

  if (index != 0 && index != NAME_MAX) {
    ret = bpf_probe_read_kernel_str(&(buf->value[PATH_MAX*2]), NAME_MAX, &(buf->value[(buf_offset->first_path - 1 - index + 1) & (PATH_MAX - 1)]));
    if (ret > 0)
      buf_offset->first_name = ret - 1;
  }

  return 0;
}

static __noinline bool bprm_path_check(struct path_rule *rule, struct buffer *buf, struct buffer_offset *offset) {
  bool match = true;
  if (rule->flags & GREEDY_MATCH || rule->flags & PRECISE_MATCH) {
    // precise match or greedy match for the globbing "**" with file path
    DEBUG_PRINT("bprm_path_check() - path match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("bprm_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, buf->value)) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("bprm_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value, offset->first_path - 2)) {
        match = true;
      } else {
        match = false;
      }
    }
  } else {
    // non-greedy match for the globbing "*" with file name
    DEBUG_PRINT("bprm_path_check() - name match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("bprm_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[PATH_MAX * 2]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("bprm_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value + PATH_MAX*2, offset->first_name - 1)) {
        match = true;
      } else {
        match = false;
      }
    }
  }

  return match;
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
    DEBUG_PRINT("rule permissions: 0x%x, flags: 0x%x", rule->permissions, rule->flags);

    // Permission check
    if (bprm_path_check(rule, buf, offset)) {
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