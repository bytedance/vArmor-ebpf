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
#define NAME_MAX 256
#define PATH_MAX 4096
#define PATH_DEPTH_MAX 30

typedef unsigned int fmode_t;

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, OUTER_MAP_ENTRIES_MAX);
  __type(key, u32);
  __type(value, u32);
} v_file_outer SEC(".maps");

static u32 *get_file_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_file_outer, &mnt_ns);
}

static struct path_rule *get_file_rule(u32 *vfile_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vfile_inner, &rule_id);
}

static inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

// prepend_path_to_first_block - parse the file path to the first block but ignores chroot'ed root.
static __noinline int prepend_path_to_first_block(struct dentry *dentry, struct vfsmount *vfsmnt, struct buffer *buf, struct buffer_offset *buf_offset) {
  struct mount *mnt = real_mount(vfsmnt);
  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

  char slash = '/';
  char null = '\0';
  int offset = PATH_MAX;

#pragma unroll
  for (int i = 0; i < PATH_DEPTH_MAX; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    d_name = BPF_CORE_READ(dentry, d_name);

    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int ret = bpf_probe_read(
                  &(buf->value[offset & (PATH_MAX - 1)]),
                  d_name.len & (NAME_MAX - 1), 
                  d_name.name);
    if (ret == 0) {
      bpf_probe_read(
          &(buf->value[(offset + d_name.len) & (PATH_MAX - 1)]),
          1,
          &slash);

      // cache the file name to the 3nd block of buffer
      if (buf_offset->first_name == 0) {
        bpf_probe_read(
                  &(buf->value[PATH_MAX*2]),
                  d_name.len & (NAME_MAX - 1),
                  d_name.name);
        bpf_probe_read(&(buf->value[(PATH_MAX*2 + d_name.len) & (PATH_MAX*3 - 1)]), 1, &null);
        buf_offset->first_name = d_name.len;

      }
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  // the path must end with '\0'
  if (offset == PATH_MAX) {
    offset--;
  }
  bpf_probe_read(&(buf->value[PATH_MAX - 1]), 1, &null);

  // the path must start with '/'
  offset--;
  bpf_probe_read(&(buf->value[offset & (PATH_MAX - 1)]), 1, &slash);

  // struct buffer *buf_test = get_file_buffer_test();
  // if (buf_test == 0)
  //   return PATH_MAX;
  // bpf_probe_read_str(buf_test->value, PATH_MAX, &(buf->value[offset & (PATH_MAX - 1)]));
  // DEBUG_PRINT("%s", buf_test->value);

  buf_offset->first_path = offset;
  return 0;
}

// prepend_path_to_second_block - parse the file path to the second block but ignores chroot'ed root.
static __noinline int prepend_path_to_second_block(struct dentry *dentry, struct vfsmount *vfsmnt, struct buffer *buf, struct buffer_offset *buf_offset) {
  struct mount *mnt = real_mount(vfsmnt);
  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

  char slash = '/';
  char null = '\0';
  int offset = PATH_MAX*2;

#pragma unroll
  for (int i = 0; i < PATH_DEPTH_MAX; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    d_name = BPF_CORE_READ(dentry, d_name);

    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int ret = bpf_probe_read(
                  &(buf->value[offset & (PATH_MAX*2 - 1)]),
                  d_name.len & (NAME_MAX - 1), 
                  d_name.name);
    if (ret == 0) {
      bpf_probe_read(
          &(buf->value[(offset + d_name.len) & (PATH_MAX*2 - 1)]),
          1,
          &slash);

      // cache the file name to the 3nd block of buffer
      if (buf_offset->second_name == 0) {
        bpf_probe_read(
                  &(buf->value[(PATH_MAX*2 + NAME_MAX) & (PATH_MAX*3 - 1)]),
                  d_name.len & (NAME_MAX - 1),
                  d_name.name);

        bpf_probe_read(&(buf->value[(PATH_MAX*2 + NAME_MAX + d_name.len) & (PATH_MAX*3 - 1)]), 1, &null);
        buf_offset->second_name = d_name.len;
      }
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  // the path must end with '\0'
  if (offset == PATH_MAX*2) {
    offset--;
  }
  bpf_probe_read(&(buf->value[PATH_MAX*2 - 1]), 1, &null);

  // the path must start with '/'
  offset--;
  bpf_probe_read(&(buf->value[offset & (PATH_MAX*2 - 1)]), 1, &slash);

  buf_offset->second_path = offset;
  return 0;
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

static __noinline bool is_prefix_match(unsigned char *prefix, unsigned char *path) {
  for (int i = 0; i < FILE_PATH_PATTERN_SIZE_MAX; i++) {
    if (prefix[i] == '\0')
      break;

    if (prefix[i] != path[i])
      return false;
  }

  return true;
}

static __noinline bool is_suffix_match(unsigned char *suffix, unsigned char *path, int offset) {
  for (int i = 0; i < FILE_PATH_PATTERN_SIZE_MAX; i++) {
    if (suffix[i] == '\0')
      break;

    if (suffix[i] != path[(offset - i) & (PATH_MAX-1)])
      return false;
  }

  return true;
}

/*
 * file_path_check - do the file permission check against the rule
 * @rule: the deny rule which describes the match pattern and deny permissions
 * @buf:  the buffer that cache the file path, binary path and others
 * @offset: a buffer_offset structure with the offsets of file path, exe path, and file name.
 * 
 * Returns: true if access denied
*/
static __always_inline bool file_path_check(struct path_rule *rule, struct buffer *buf, struct buffer_offset *offset) {
  bool match = true;
  if (rule->flags & GREEDY_MATCH || rule->flags & PRECISE_MATCH) {
    // precise match or greedy match for the globbing "**" with file path
    DEBUG_PRINT("file_path_check() - path match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("file_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[offset->first_path & (PATH_MAX - 1)]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("file_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value, PATH_MAX - 2)) {
        match = true;
      } else {
        match = false;
      }
    }
  } else {
    // non-greedy match for the globbing "*" with file name
    DEBUG_PRINT("file_path_check() - name match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("file_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[PATH_MAX * 2]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("file_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value + PATH_MAX*2, offset->first_name - 1)) {
        match = true;
      } else {
        match = false;
      }
    }
  }

  return match;
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
    DEBUG_PRINT("requested permissions: 0x%x, rule permissions: 0x%x, flags: 0x%x", requested_perms, rule->permissions, rule->flags);

    // Permission check
    if (rule->permissions & requested_perms) {
      if (file_path_check(rule, buf, offset)) {
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

static __noinline bool old_path_check(struct path_rule *rule, struct buffer *buf, struct buffer_offset *offset) {
  bool match = true;
  if (rule->flags & GREEDY_MATCH || rule->flags & PRECISE_MATCH) {
    // precise match or greedy match for the globbing "**" with file path
    DEBUG_PRINT("old_path_check() - file path match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("old_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[offset->first_path & (PATH_MAX - 1)]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("old_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value, PATH_MAX - 2)) {
        match = true;
      } else {
        match = false;
      }
    }
  } else {
    // non-greedy match for the globbing "*" with file name
    DEBUG_PRINT("old_path_check() - file name match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("old_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[PATH_MAX * 2]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("old_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value + PATH_MAX*2, offset->first_name - 1)) {
        match = true;
      } else {
        match = false;
      }
    }
  }

  return match;
}

static __noinline bool new_path_check(struct path_rule *rule, struct buffer *buf, struct buffer_offset *offset) {
  bool match = true;
  if (rule->flags & GREEDY_MATCH || rule->flags & PRECISE_MATCH) {
    // precise match or greedy match for the globbing "**" with file path
    DEBUG_PRINT("new_path_check() - file path match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("new_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[offset->second_path & (PATH_MAX*2 - 1)]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("new_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value + PATH_MAX, PATH_MAX*2 - 2)) {
        match = true;
      } else {
        match = false;
      }
    }
  } else {
    // non-greedy match for the globbing "*" with file name
    DEBUG_PRINT("new_path_check() - file name match");

    if (rule->flags & PREFIX_MATCH) {
      DEBUG_PRINT("new_path_check() - rule prefix: %s", rule->prefix);
      if (is_prefix_match(rule->prefix, &(buf->value[PATH_MAX*2 + NAME_MAX]))) {
        match = true;
      } else {
        match = false;
      }
    }

    if ((rule->flags & SUFFIX_MATCH) && match) {
      DEBUG_PRINT("new_path_check() - rule suffix: %s", rule->suffix);
      if (is_suffix_match(rule->suffix, buf->value + PATH_MAX*2, NAME_MAX + offset->second_name - 1)) {
        match = true;
      } else {
        match = false;
      }
    }
  }

  return match;
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
    DEBUG_PRINT("requested permissions: 0x%x, rule permissions: 0x%x, flags: 0x%x", requested_perms, rule->permissions, rule->flags);

    // Permission check
    if (rule->permissions & AA_MAY_READ) {
      if (old_path_check(rule, buf, offset)) {
        DEBUG_PRINT("");
        DEBUG_PRINT("access denied");
        return -EPERM;
      }
    }

    if (rule->permissions & AA_MAY_WRITE) {
      if (new_path_check(rule, buf, offset)) {
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