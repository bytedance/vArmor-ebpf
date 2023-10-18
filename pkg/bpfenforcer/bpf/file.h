// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __FILE_H
#define __FILE_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "perms.h"

#define FILE_INNER_MAP_ENTRIES_MAX 50

typedef unsigned int fmode_t;

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, OUTER_MAP_ENTRIES_MAX);
  __type(key, u32);
  __type(value, u32);
} v_file_outer SEC(".maps");

struct path_rule {
  u32 permissions;
  struct path_pattern pattern;
};

static u32 *get_file_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_file_outer, &mnt_ns);
}

static struct path_rule *get_file_rule(u32 *vfile_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vfile_inner, &rule_id);
}

/**
 * map_file_to_perms - map file flags to AppArmor permissions
 * @file: open file to map flags to AppArmor permissions
 *
 * Returns: apparmor permission set for the file
 */
static __noinline u32 map_file_to_perms(struct file *file) {
  u32 perms = 0;
  unsigned int flags = BPF_CORE_READ(file, f_flags);
  fmode_t mode = BPF_CORE_READ(file, f_mode);

  if (mode & FMODE_WRITE)
    perms |= MAY_WRITE;
  if (mode & FMODE_READ)
    perms |= MAY_READ;
  
  if ((flags & O_APPEND) && (perms & MAY_WRITE))
    perms = (perms & ~MAY_WRITE) | MAY_APPEND;
  /* trunc implies write permission */
  if (flags & O_TRUNC)
    perms |= MAY_WRITE;
  if (flags & O_CREAT)
    perms |= AA_MAY_CREATE;

  return perms;
}

static __always_inline int iterate_file_inner_map_for_file(u32 *vfile_inner, struct buffer *buf, struct buffer_offset *offset, u32 requested_perms) {
  for(int inner_id=0; inner_id<FILE_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct path_rule *rule = get_file_rule(vfile_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    DEBUG_PRINT("requested permissions: 0x%x, rule permissions: 0x%x", requested_perms, rule->permissions);

    // Permission check
    if (rule->permissions & requested_perms) {
      if (old_path_check(&rule->pattern, buf, offset)) {
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

static __noinline int iterate_file_inner_map_for_path_pair(u32 *vfile_inner, struct buffer *buf, struct buffer_offset *offset, u32 requested_perms) {
  for(int inner_id=0; inner_id<FILE_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct path_rule *rule = get_file_rule(vfile_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    DEBUG_PRINT("requested permissions: 0x%x, rule permissions: 0x%x", requested_perms, rule->permissions);

    // Permission check
    if (rule->permissions & AA_MAY_READ) {
      if (old_path_check(&rule->pattern, buf, offset)) {
        DEBUG_PRINT("");
        DEBUG_PRINT("access denied");
        return -EPERM;
      }
    }

    if (rule->permissions & AA_MAY_WRITE) {
      if (new_path_check(&rule->pattern, buf, offset)) {
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

SEC("lsm/path_link")
int BPF_PROG(varmor_path_link_tail, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry) {
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;
  
  struct buffer_offset offset;
  bpf_probe_read(&offset, sizeof(offset), &buf->value[PATH_MAX*3-sizeof(offset)]);

  u32 mnt_ns;
  bpf_probe_read(&mnt_ns, 4, &buf->value[PATH_MAX*3-sizeof(offset)-4]);

  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (vfile_inner == NULL) {
    return 0;
  }

  // Iterate all rules in the inner map
  return iterate_file_inner_map_for_path_pair(vfile_inner, buf, &offset, AA_MAY_LINK);
}

SEC("lsm/path_rename")
int BPF_PROG(varmor_path_rename_tail, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, const unsigned int flags) {
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;
  
  struct buffer_offset offset;
  bpf_probe_read(&offset, sizeof(offset), &buf->value[PATH_MAX*3-sizeof(offset)]);

  u32 mnt_ns;
  bpf_probe_read(&mnt_ns, 4, &buf->value[PATH_MAX*3-sizeof(offset)-4]);

  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (vfile_inner == NULL) {
    return 0;
  }

  // Iterate all rules in the inner map
  return iterate_file_inner_map_for_path_pair(vfile_inner, buf, &offset, AA_MAY_RENAME);
}

#endif /* __FILE_H */