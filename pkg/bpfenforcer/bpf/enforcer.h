// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __ENFORCER_H
#define __ENFORCER_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define	EPERM 1
#define OUTER_MAP_ENTRIES_MAX 100

#define FILE_PATH_PATTERN_SIZE_MAX 64
#define BUFFER_MAX 4096*3

#define PRECISE_MATCH 0x00000001
#define GREEDY_MATCH  0x00000002
#define PREFIX_MATCH  0x00000004
#define SUFFIX_MATCH  0x00000008
#define CIDR_MATCH    0x00000020
#define IPV4_MATCH    0x00000040
#define IPV6_MATCH    0x00000080
#define PORT_MATCH    0x00000100

#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })

// #define DEBUG 1
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) \
  bpf_printk(fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...) \
  do { } while (0)
#endif

/*
  We use the buffer to cache file path(or old path), binary path(or new path) and file name etc.
  |---------------------------------------|---------------------------------------|---------------------------------------|
  |                                       |                                       |                                       |
  |                              file path|                                       |file name                              |
  |                                 path-1|                                 path-2|name-1   |name-2                       |
  |exec path                              |                            binary path|exec name|                             |
  |dev path                               |                                       |dev name |                    |fstype  |
  |                                       |                                       |                                       |
  |---------------------------------------|---------------------------------------|---------------------------------------|

  |------------------4096-----------------|------------------4096-----------------|---256---|---256---| |---16---|---16---|
*/
struct buffer {
  unsigned char value[BUFFER_MAX];
};

struct buffer_offset {
  u32 first_path;
  u32 first_name;
  u32 second_path;
  u32 second_name;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct buffer);
  __uint(max_entries, 1);
} v_file_buffer SEC(".maps");

// struct {
//   __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//   __type(key, u32);
//   __type(value, struct buffer);
//   __uint(max_entries, 1);
// } v_file_buffer_test SEC(".maps");

struct path_rule {
  u32 permissions;
  u32 flags;
  unsigned char prefix[FILE_PATH_PATTERN_SIZE_MAX];
  unsigned char suffix[FILE_PATH_PATTERN_SIZE_MAX];
};

static struct buffer *get_buffer() {
    int index = 0;
    return bpf_map_lookup_elem(&v_file_buffer, &index);
}

// static struct buffer *get_file_buffer_test() {
//     int index = 0;
//     return bpf_map_lookup_elem(&v_file_buffer_test, &index);
// }

static u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

static struct user_namespace *get_task_user_ns(struct task_struct *task) {
  return BPF_CORE_READ(task, cred, user_ns);
}

static kernel_cap_t get_task_cap_effective(struct task_struct *task) {
  return BPF_CORE_READ(task, cred, cap_effective);
}

// static __noinline u32 get_task_uts_ns_id(struct task_struct *task) {
//   return BPF_CORE_READ(task, nsproxy, uts_ns, ns).inum;
// }

// static struct file *get_task_exe_file(struct task_struct *task) {
//   return BPF_CORE_READ(task, mm, exe_file);
// }

static int task_in_execve(struct task_struct *task) {
  unsigned long long val = 0;
  unsigned int offset = __builtin_preserve_field_info(task->in_execve, BPF_FIELD_BYTE_OFFSET);
  unsigned int size = __builtin_preserve_field_info(task->in_execve, BPF_FIELD_BYTE_SIZE);
  bpf_probe_read(&val, size, (void *)task + offset);
  val <<= __builtin_preserve_field_info(task->in_execve, BPF_FIELD_LSHIFT_U64);
  val >>= __builtin_preserve_field_info(task->in_execve, BPF_FIELD_RSHIFT_U64);
  return (int)val;
}

#endif