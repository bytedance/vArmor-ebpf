// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __MOUNT_H
#define __MOUNT_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "file.h"
#include "perms.h"

#define MOUNT_INNER_MAP_ENTRIES_MAX 50
#define FILE_SYSTEM_TYPE_MAX 16

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, OUTER_MAP_ENTRIES_MAX);
  __type(key, u32);
  __type(value, u32);
} v_mount_outer SEC(".maps");

struct mount_rule {
  u32 flags;
  u32 mount_flags;
  u32 neg_mount_flags;
  unsigned char fstype[FILE_SYSTEM_TYPE_MAX];
  unsigned char prefix[FILE_PATH_PATTERN_SIZE_MAX];
  unsigned char suffix[FILE_PATH_PATTERN_SIZE_MAX];
};

static u32 *get_mount_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_mount_outer, &mnt_ns);
}

static struct mount_rule *get_mount_rule(u32 *vmount_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vmount_inner, &rule_id);
}

static __noinline int prepend_source_to_first_block(const char *source, struct buffer *buf, struct buffer_offset *buf_offset) {
  int ret = bpf_probe_read_kernel_str(buf->value, PATH_MAX, source);
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

static __noinline int prepend_fstype_to_third_block(const char *fstype, struct buffer *buf) {
  int ret = bpf_probe_read_kernel_str(&(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]), FILE_SYSTEM_TYPE_MAX, fstype);
  if (ret < 0) {
    buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX] = 0;
    return -1;
  }
  return 0;
}

static __noinline bool mount_fstype_check(unsigned char *rule_fstype, unsigned char *fstype) {
  DEBUG_PRINT("mount_fstype_check()");
  if (rule_fstype[0] == '*') {
    return true;
  }

  for (int i = 0; i < FILE_SYSTEM_TYPE_MAX; i++) {
    if (rule_fstype[i] == 0 && fstype[i] == 0)
      return true;

    if (rule_fstype[i] != fstype[i])
      break;
  }

  return false;
}


static __noinline bool mount_source_check(struct mount_rule *rule, struct buffer *buf, struct buffer_offset *offset) {
  bool match = true;
  if (rule->flags & GREEDY_MATCH || rule->flags & PRECISE_MATCH) {
    // precise match or greedy match for the globbing "**" with file path
    DEBUG_PRINT("mount_source_check() - path match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("mount_source_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, buf->value)) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("mount_source_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value, offset->first_path - 2)) {
        match = true;
      } else {
        match = false;
      }
    }
  } else {
    // non-greedy match for the globbing "*" with file name
    DEBUG_PRINT("mount_source_check() - name match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("mount_source_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[PATH_MAX * 2]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("mount_source_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value + PATH_MAX*2, offset->first_name - 1)) {
        match = true;
      } else {
        match = false;
      }
    }
  }

  return match;
}

static __noinline int iterate_mount_inner_map(u32 *vmount_inner, unsigned long flags, struct buffer *buf, struct buffer_offset *offset) {
  for (int inner_id=0; inner_id<MOUNT_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct mount_rule *rule = get_mount_rule(vmount_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    DEBUG_PRINT("rule mount_flags: 0x%x, neg_mount_flags: 0x%x", rule->mount_flags, rule->neg_mount_flags);
    DEBUG_PRINT("rule fstype: %s", rule->fstype);
    DEBUG_PRINT("rule prefix: %s, suffix: %s", rule->prefix, rule->suffix);

    // Permission check
    if (flags & rule->mount_flags || (~flags) & rule->neg_mount_flags) {
      if (mount_fstype_check(rule->fstype, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX])) && 
          mount_source_check(rule, buf, offset)) {
        DEBUG_PRINT("");
        DEBUG_PRINT("access denied");
        return -EPERM;
      }
    }
  }

  DEBUG_PRINT("");
  DEBUG_PRINT("access allowed");
  return 0;
}

#endif /* __MOUNT_H */