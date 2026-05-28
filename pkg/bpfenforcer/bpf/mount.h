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

// Maximum rule count for mount access control.
//
// Kernel compatibility matrix for the unrolled vs bpf_loop variant:
//
//   Kernel        | Variant   | 64 rules    | 50 rules
//   --------------+-----------+-------------+----------
//   5.10          | unrolled  | load OK     | load OK
//   5.15          | unrolled  | FAIL (>1M)  | load OK
//   >= 5.17 / 6.x | bpf_loop  | load OK     | load OK
//
// The counter-intuitive 5.10-vs-5.15 result is explained by changes to the
// verifier between these kernels: 5.15 backported much stricter state-tracking
// and bounds analysis for unrolled loops (more states per iteration, less
// aggressive state pruning), which inflates the processed-insn count past the
// hard 1M ceiling for varmor_move_mount (two iteration passes over the rules).
// Refactoring the iteration body into __noinline subprograms helped, but was
// not enough on 5.15. Since 5.15 has no bpf_loop (added in 5.17), we keep the
// unrolled path capped at 50 rules.
//
// The bpf_loop path (kernel >= 5.17) is verifier-friendly because each
// callback is validated once; we can safely raise it to 64 there. The Go
// loader picks the correct .o at runtime based on bpf_loop helper detection.
#ifdef USE_BPF_LOOP
#define MOUNT_INNER_MAP_ENTRIES_MAX 64
#else
#define MOUNT_INNER_MAP_ENTRIES_MAX 50
#endif

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

static __always_inline u32 *get_mount_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_mount_outer, &mnt_ns);
}

static __always_inline struct mount_rule *get_mount_rule(u32 *vmount_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vmount_inner, &rule_id);
}

static __always_inline int prepend_fstype_to_third_block(const char *fstype, struct buffer *buf) {
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

#ifdef USE_BPF_LOOP
// bpf_loop callback context for iterate_mount_inner_map
struct mount_iter_ctx {
  u32 *vmount_inner;
  unsigned long flags;
  struct buffer *buf;
  struct buffer_offset *offset;
  u32 mnt_ns;
  int result;
};

static __noinline long mount_iter_cb(u32 idx, struct mount_iter_ctx *ctx) {
  struct mount_rule *rule = get_mount_rule(ctx->vmount_inner, idx);
  if (rule == NULL)
    return 1; // break

  if (!(ctx->flags & rule->mount_flags || (~ctx->flags) & rule->reverse_mount_flags))
    return 0; // continue

  if (!(mount_fstype_check(rule->fstype, &(ctx->buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX])) &&
        head_path_check(&rule->pattern, ctx->buf, ctx->offset)))
    return 0; // continue

  if (rule->mode & AUDIT_MODE) {
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      e->action = rule->mode & DENY_MODE ? DENIED_ACTION : AUDIT_ACTION;
      e->type = MOUNT_TYPE;
      e->mnt_ns = ctx->mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      bpf_probe_read_kernel_str(e->event_u.mount.path, ctx->offset->first_path & (PATH_MAX-1), ctx->buf->value);
      bpf_probe_read_kernel_str(e->event_u.mount.type, FILE_SYSTEM_TYPE_MAX, &(ctx->buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
      e->event_u.mount.flags = ctx->flags;
      bpf_ringbuf_submit(e, 0);
    }
  }

  if (rule->mode & DENY_MODE) {
    ctx->result = -EPERM;
    return 1; // break
  }
  return 0;
}

static __noinline int iterate_mount_inner_map(u32 *vmount_inner, unsigned long flags, struct buffer *buf, struct buffer_offset *offset, u32 mnt_ns) {
  struct mount_iter_ctx ctx = {
    .vmount_inner = vmount_inner,
    .flags = flags,
    .buf = buf,
    .offset = offset,
    .mnt_ns = mnt_ns,
    .result = 0,
  };
  bpf_loop(MOUNT_INNER_MAP_ENTRIES_MAX, mount_iter_cb, &ctx, 0);
  // Clamp return value to satisfy LSM verifier constraint [-4095, 0]
  int ret = ctx.result;
  return ret > 0 ? 0 : ret < -4095 ? -4095 : ret;
}
#else  /* !USE_BPF_LOOP */
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

        // Submit the audit event
        if (rule->mode & AUDIT_MODE) {
          struct audit_event *e;
          e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
          if (e) {
            DEBUG_PRINT("write audit event to ringbuf");
            e->action = rule->mode & DENY_MODE ? DENIED_ACTION : AUDIT_ACTION;
            e->type = MOUNT_TYPE;
            e->mnt_ns = mnt_ns;
            e->tgid = bpf_get_current_pid_tgid()>>32;
            e->ktime = bpf_ktime_get_boot_ns();
            bpf_probe_read_kernel_str(e->event_u.mount.path, offset->first_path & (PATH_MAX-1), buf->value);
            bpf_probe_read_kernel_str(e->event_u.mount.type, FILE_SYSTEM_TYPE_MAX, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
            e->event_u.mount.flags = flags;
            bpf_ringbuf_submit(e, 0);
          }
        }

        if (rule->mode & DENY_MODE) {
          DEBUG_PRINT("access denied");
          return -EPERM;
        }
      }
    }
  }

  DEBUG_PRINT("");
  DEBUG_PRINT("access allowed");
  return 0;
}
#endif /* USE_BPF_LOOP */

#ifdef USE_BPF_LOOP
// bpf_loop callback context for iterate_mount_inner_map_extra
struct mount_extra_iter_ctx {
  u32 *vmount_inner;
  unsigned long flags;
  struct buffer *buf;
  struct buffer_offset *offset;
  u32 mnt_ns;
  int result;
};

static __noinline long mount_extra_iter_cb(u32 idx, struct mount_extra_iter_ctx *ctx) {
  struct mount_rule *rule = get_mount_rule(ctx->vmount_inner, idx);
  if (rule == NULL)
    return 1; // break

  if (!(ctx->flags & rule->mount_flags))
    return 0; // continue

  if (!(mount_fstype_check(rule->fstype, &(ctx->buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX])) &&
        old_path_check(&rule->pattern, ctx->buf, ctx->offset)))
    return 0; // continue

  if (rule->mode & AUDIT_MODE) {
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      e->action = rule->mode & DENY_MODE ? DENIED_ACTION : AUDIT_ACTION;
      e->type = MOUNT_TYPE;
      e->mnt_ns = ctx->mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      bpf_probe_read_kernel_str(e->event_u.mount.path, (PATH_MAX-ctx->offset->first_path) & (PATH_MAX-1), &(ctx->buf->value[ctx->offset->first_path & (PATH_MAX-1)]));
      bpf_probe_read_kernel_str(e->event_u.mount.type, FILE_SYSTEM_TYPE_MAX, &(ctx->buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
      e->event_u.mount.flags = ctx->flags;
      bpf_ringbuf_submit(e, 0);
    }
  }

  if (rule->mode & DENY_MODE) {
    ctx->result = -EPERM;
    return 1; // break
  }
  return 0;
}

static __noinline int iterate_mount_inner_map_extra(u32 *vmount_inner, unsigned long flags, struct buffer *buf, struct buffer_offset *offset, u32 mnt_ns) {
  struct mount_extra_iter_ctx ctx = {
    .vmount_inner = vmount_inner,
    .flags = flags,
    .buf = buf,
    .offset = offset,
    .mnt_ns = mnt_ns,
    .result = 0,
  };
  bpf_loop(MOUNT_INNER_MAP_ENTRIES_MAX, mount_extra_iter_cb, &ctx, 0);
  // Clamp return value to satisfy LSM verifier constraint [-4095, 0]
  int ret = ctx.result;
  return ret > 0 ? 0 : ret < -4095 ? -4095 : ret;
}
#else  /* !USE_BPF_LOOP */
static __noinline int iterate_mount_inner_map_extra(u32 *vmount_inner, unsigned long flags, struct buffer *buf, struct buffer_offset *offset, u32 mnt_ns) {
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

        // Submit the audit event
        if (rule->mode & AUDIT_MODE) {
          struct audit_event *e;
          e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
          if (e) {
            DEBUG_PRINT("write audit event to ringbuf");
            e->action = rule->mode & DENY_MODE ? DENIED_ACTION : AUDIT_ACTION;
            e->type = MOUNT_TYPE;
            e->mnt_ns = mnt_ns;
            e->tgid = bpf_get_current_pid_tgid()>>32;
            e->ktime = bpf_ktime_get_boot_ns();
            bpf_probe_read_kernel_str(e->event_u.mount.path, (PATH_MAX-offset->first_path) & (PATH_MAX-1), &(buf->value[offset->first_path & (PATH_MAX-1)]));
            bpf_probe_read_kernel_str(e->event_u.mount.type, FILE_SYSTEM_TYPE_MAX, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
            e->event_u.mount.flags = flags;
            bpf_ringbuf_submit(e, 0);
          }
        }

        if (rule->mode & DENY_MODE) {
          DEBUG_PRINT("access denied");
          return -EPERM;
        }
      }
    }
  }

  DEBUG_PRINT("");
  DEBUG_PRINT("access allowed");
  return 0;
}
#endif /* USE_BPF_LOOP */

#endif /* __MOUNT_H */