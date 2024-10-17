// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __MOUNT_H
#define __MOUNT_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "perms.h"

// Maximum rule count for network access control
#define MOUNT_INNER_MAP_ENTRIES_MAX 50

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, OUTER_MAP_ENTRIES_MAX);
  __type(key, u32);
  __type(value, u32);
} v_mount_outer SEC(".maps");

struct mount_rule {
  u32 mode;
  u32 mount_flags;
  u32 reverse_mount_flags;
  struct path_pattern pattern;
  unsigned char fstype[FILE_SYSTEM_TYPE_MAX];
};

static u32 *get_mount_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_mount_outer, &mnt_ns);
}

static struct mount_rule *get_mount_rule(u32 *vmount_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vmount_inner, &rule_id);
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

static __noinline int iterate_mount_inner_map(u32 *vmount_inner, unsigned long flags, struct buffer *buf, struct buffer_offset *offset, u32 mnt_ns) {
  for (int inner_id=0; inner_id<MOUNT_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct mount_rule *rule = get_mount_rule(vmount_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    DEBUG_PRINT("rule mount_flags: 0x%x, reverse_mount_flags: 0x%x", rule->mount_flags, rule->reverse_mount_flags);
    DEBUG_PRINT("rule fstype: %s", rule->fstype);

    // Permission check
    if (flags & rule->mount_flags || (~flags) & rule->reverse_mount_flags) {
      if (mount_fstype_check(rule->fstype, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX])) && 
          head_path_check(&rule->pattern, buf, offset)) {
        DEBUG_PRINT("");
        DEBUG_PRINT("access denied");

        // Submit the audit event
        if (rule->mode & AUDIT_MODE) {
          struct audit_event *e;
          e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
          if (e) {
            DEBUG_PRINT("write audit event to ringbuf");
            e->mode = AUDIT_MODE;
            e->type = MOUNT_TYPE;
            e->mnt_ns = mnt_ns;
            e->tgid = bpf_get_current_pid_tgid()>>32;
            e->ktime = bpf_ktime_get_boot_ns();
            bpf_probe_read_kernel_str(e->mount.dev_name, offset->first_path & (PATH_MAX-1), buf->value);
            bpf_probe_read_kernel_str(e->mount.type, FILE_SYSTEM_TYPE_MAX, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
            e->mount.flags = flags;
            bpf_ringbuf_submit(e, 0);
          }
        }
        
        return -EPERM;
      }
    }
  }

  DEBUG_PRINT("");
  DEBUG_PRINT("access allowed");
  return 0;
}

static __noinline int iterate_mount_inner_map_extra(u32 *vmount_inner, unsigned long flags, struct buffer *buf, struct buffer_offset *offset) {
  for (int inner_id=0; inner_id<MOUNT_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct mount_rule *rule = get_mount_rule(vmount_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    DEBUG_PRINT("rule mount_flags: 0x%x, reverse_mount_flags: 0x%x", rule->mount_flags, rule->reverse_mount_flags);
    DEBUG_PRINT("rule fstype: %s", rule->fstype);

    // Permission check
    if (flags & rule->mount_flags) {
      if (mount_fstype_check(rule->fstype, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX])) && 
          old_path_check(&rule->pattern, buf, offset)) {
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