// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "file.h"
#include "perms.h"

char __license[] SEC("license") = "GPL";

// Save the mnt ns id of init task
volatile const u32 init_mnt_ns;

// Tail call map (program array) initialized with program pointers.
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 2);
	__array(values, int());
} file_progs SEC(".maps") = {
	.values =
		{
			[0] = &varmor_path_rename_tail,
		},
};

SEC("lsm/path_rename")
int BPF_PROG(varmor_path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, const unsigned int flags) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has file access control rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (vfile_inner == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;
  
  // Extract the file path of the old dentry provided by LSM Hook
  prepend_path_to_first_block(old_dentry, old_dir->mnt, buf, &offset);

  // Extract the file path of the new dentry provided by LSM Hook
  prepend_path_to_second_block(new_dentry, new_dir->mnt, buf, &offset);

  // Save the offset and the mnt_ns
  bpf_probe_read(&buf->value[PATH_MAX*3-sizeof(offset)], sizeof(offset), &offset);
  bpf_probe_read(&buf->value[PATH_MAX*3-sizeof(offset)-4], 4, &mnt_ns);

  DEBUG_PRINT("================ lsm/path_rename ================");
  DEBUG_PRINT("old path: %s", &(buf->value[offset.first_path & (PATH_MAX-1)]));
  DEBUG_PRINT("offset: %d, length: %d", offset.first_path, PATH_MAX-offset.first_path-1);
  DEBUG_PRINT("file name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);
  DEBUG_PRINT("new path: %s", &(buf->value[offset.second_path & (PATH_MAX*2-1)]));
  DEBUG_PRINT("offset: %d, length: %d", offset.second_path, PATH_MAX*2-offset.second_path-1);
  DEBUG_PRINT("file name: %s, length: %d", &(buf->value[PATH_MAX*2+NAME_MAX]), offset.second_name);

  // Tail call
  bpf_tail_call(ctx, &file_progs, 0);

  return 0;
}
