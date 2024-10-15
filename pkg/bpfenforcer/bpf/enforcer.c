// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "enforcer.h"
#include "capability.h"
#include "file.h"
#include "process.h"
#include "network.h"
#include "ptrace.h"
#include "mount.h"
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
			[0] = &varmor_path_link_tail,
			[1] = &varmor_path_rename_tail,
		},
};

SEC("lsm/capable")
int BPF_PROG(varmor_capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts, int ret) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has file access control rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  struct capability_rule *rule = get_capability_rules(mnt_ns);
  if (rule == 0)
    return ret;

  DEBUG_PRINT("================ lsm/capable ================");
  
  // Permission check
  u64 request_cap_mask = CAP_TO_MASK(cap);

  if (rule->caps & request_cap_mask) {
    struct user_namespace *current_ns = get_task_user_ns(current);
    kernel_cap_t current_cap_effective = get_task_cap_effective(current);
    // We utilize casts to ensure compatibility with kernel 6.3+
    u64 current_effective_mask = *(u64 *)&current_cap_effective;

    DEBUG_PRINT("task(mnt ns: %u) current_effective_mask: 0x%lx, request_cap_mask: 0x%lx", 
            mnt_ns, current_effective_mask, request_cap_mask);

    // Compatible with overlayfs when writing /tmp directory
    if (current_ns == ns && current_effective_mask == 0x1fffeffffff) {
      return ret;
    }

    // Compatible with containerd on cgroup v2 environment
    if (current_ns == ns && current_effective_mask == 0x1ffffffffff) {
      return ret;
    }

    DEBUG_PRINT("task(mnt ns: %u) is not allowed to use capability: 0x%x", mnt_ns, cap);

    // Submit the audit event
    if (rule->mode & AUDIT_MODE) {
      struct audit_event *e;
      e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
      if (e) {
        DEBUG_PRINT("write audit event to ringbuf");
        e->mode = AUDIT_MODE;
        e->type = CAPABILITY_TYPE;
        e->mnt_ns = mnt_ns;
        e->tgid = bpf_get_current_pid_tgid()>>32;
        e->ktime = bpf_ktime_get_boot_ns();
        e->capability = cap;
        bpf_ringbuf_submit(e, 0);
      }
    }

    return -EPERM;
  }

  return ret;
}

SEC("lsm/file_open")
int BPF_PROG(varmor_file_open, struct file *file) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has file access control rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (vfile_inner == NULL)
    return 0;

  // Don't check permission here if called from execve()
  if(task_in_execve(current))
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;
  
  // Extract the file path from the file structure provided by LSM Hook
  struct path f_path = BPF_CORE_READ(file, f_path);
  prepend_path_to_first_block(f_path.dentry, f_path.mnt, buf, &offset);

  DEBUG_PRINT("================ lsm/file_open ================");
  DEBUG_PRINT("path: %s", &(buf->value[offset.first_path & (PATH_MAX-1)]));
  DEBUG_PRINT("offset: %d, length: %d", offset.first_path, PATH_MAX-offset.first_path-1);
  DEBUG_PRINT("file name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);

  u32 requested_perms = map_file_to_perms(file);

  // Iterate all rules in the inner map
  return iterate_file_inner_map_for_file(vfile_inner, buf, &offset, requested_perms, mnt_ns);
}

SEC("lsm/path_symlink")
int BPF_PROG(varmor_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name) {
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

  // Extract the file path from the dentry provided by LSM Hook
  prepend_path_to_first_block(dentry, dir->mnt, buf, &offset);

  DEBUG_PRINT("================ lsm/path_symlink ================");
  DEBUG_PRINT("path: %s", &(buf->value[offset.first_path & (PATH_MAX-1)]));
  DEBUG_PRINT("offset: %d, length: %d", offset.first_path, PATH_MAX-offset.first_path-1);
  DEBUG_PRINT("file name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);

  // Iterate all rules in the inner map
  return iterate_file_inner_map_for_file(vfile_inner, buf, &offset, AA_MAY_WRITE, mnt_ns);
}

SEC("lsm/path_link")
int BPF_PROG(varmor_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry) {
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
  
  // Extract the file path from the old dentry provided by LSM Hook
  prepend_path_to_first_block(old_dentry, new_dir->mnt, buf, &offset);

  // Extract the file path from the new dentry provided by LSM Hook
  prepend_path_to_second_block(new_dentry, new_dir->mnt, buf, &offset);

  // Save the offset and the mnt_ns
  bpf_probe_read(&buf->value[PATH_MAX*3-sizeof(offset)], sizeof(offset), &offset);
  bpf_probe_read(&buf->value[PATH_MAX*3-sizeof(offset)-4], 4, &mnt_ns);

  DEBUG_PRINT("================ lsm/path_link ================");
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
  bpf_tail_call(ctx, &file_progs, 1);

  return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(varmor_bprm_check_security, struct linux_binprm *bprm, int ret) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has bprm access control rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  u32 *vbprm_inner = get_bprm_inner_map(mnt_ns);
  if (vbprm_inner == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;

  // Extract the new executable path from the bprm structure provided by LSM Hook
  prepend_string_to_first_block(bprm->filename, buf, &offset);

  DEBUG_PRINT("================ lsm/bprm_check_security ================");
  DEBUG_PRINT("path: %s", buf->value);
  DEBUG_PRINT("offset: %d, length: %d", offset.first_path, offset.first_path-1);
  DEBUG_PRINT("file name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);

  return iterate_bprm_inner_map_for_executable(vbprm_inner, buf, &offset, mnt_ns);
}

SEC("lsm/socket_connect")
int BPF_PROG(varmor_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
  // Only care about ipv4 and ipv6 for now
	if (address->sa_family != AF_INET && address->sa_family != AF_INET6)
		return 0;

  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has network access control rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  u32 *vnet_inner = get_net_inner_map(mnt_ns);
  if (vnet_inner == NULL)
    return 0;

  DEBUG_PRINT("================ lsm/socket_connect ================");

  DEBUG_PRINT("socket status: 0x%x", sock->state);
  DEBUG_PRINT("socket type: 0x%x", sock->type);
  DEBUG_PRINT("socket flags: 0x%x", sock->flags);

  // Iterate all rules in the inner map
  return iterate_net_inner_map(vnet_inner, address);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(varmor_ptrace_access_check, struct task_struct *child, unsigned int mode) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 current_mnt_ns = get_task_mnt_ns_id(current);
  u32 child_mnt_ns = get_task_mnt_ns_id(child);
  
  // Whether the current task has ptrace access control rule
  u64 *rule = get_ptrace_rule(current_mnt_ns);
  if (rule != 0) {
    DEBUG_PRINT("================ lsm/ptrace_access_check ================");
    if (!ptrace_permission_check(current_mnt_ns, child_mnt_ns, *rule, (mode & PTRACE_MODE_READ) ? AA_PTRACE_READ : AA_PTRACE_TRACE))
      return -EPERM;
  }

  // Whether the child task has ptrace access control rule
  // We allow tasks from the init mnt ns by default
  rule = get_ptrace_rule(child_mnt_ns);
  if (current_mnt_ns != init_mnt_ns && rule != 0) {
    DEBUG_PRINT("================ lsm/ptrace_access_check ================");
    if (!ptrace_permission_check(current_mnt_ns, child_mnt_ns, *rule, (mode & PTRACE_MODE_READ) ? AA_MAY_BE_READ : AA_MAY_BE_TRACED))
      return -EPERM;
  }

  return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(varmor_mount, char *dev_name, struct path *path, char *type, unsigned long flags, void *data) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has mount rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  u32 *vmount_inner = get_mount_inner_map(mnt_ns);
  if (vmount_inner == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;

  // Extract the dev path from the dev_name parameter provided by LSM hook point
  prepend_string_to_first_block(dev_name, buf, &offset);

  // Extract the fstype from the type parameter provided by LSM hook point
  prepend_fstype_to_third_block(type, buf);

  DEBUG_PRINT("================ lsm/sb_mount ================");
  DEBUG_PRINT("dev path: %s", buf->value);
  DEBUG_PRINT("offset: %d, length: %d", offset.first_path, offset.first_path-1);
  DEBUG_PRINT("dev name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);
  DEBUG_PRINT("fstype: %s", &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
  DEBUG_PRINT("flags: 0x%x", flags);

  if (flags & 
      (MS_REMOUNT | MS_BIND | MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE | MS_MOVE | AA_MAY_UMOUNT)) {
    DEBUG_PRINT("force the fstype to 'none'");
    buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX] = 'n';
    buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+1] = 'o';
    buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+2] = 'n';
    buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+3] = 'e';
    buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+4] = '\0';
  }

  // Iterate all rules in the inner map
  return iterate_mount_inner_map(vmount_inner, flags, buf, &offset);
}

SEC("lsm/move_mount")
int BPF_PROG(varmor_move_mount, struct path *from_path, struct path *to_path) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has mount rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  u32 *vmount_inner = get_mount_inner_map(mnt_ns);
  if (vmount_inner == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;
  
  // Extract the source path from the from_path parameter provided by LSM hook point
  prepend_path_to_first_block(from_path->dentry, from_path->mnt, buf, &offset);

  // Mock flags and fstype
  // move_mount() is a part of the new system calls for mounting file systems 
  // since v5.2. See https://lwn.net/Articles/759499/ 
  // We only care about the relocation use case of move_mount() for now, and
  // reuse the rules for mount().
  unsigned long mock_flags = MS_MOVE;
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX] = 'n';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+1] = 'o';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+2] = 'n';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+3] = 'e';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+4] = '\0';

  DEBUG_PRINT("================ lsm/move_mount ================");
  DEBUG_PRINT("from path: %s, length: %d, from path offset: %d", 
      &(buf->value[offset.first_path & (PATH_MAX-1)]), PATH_MAX-offset.first_path-1, offset.first_path);
  DEBUG_PRINT("from name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);
  DEBUG_PRINT("mock fstype: %s", &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
  DEBUG_PRINT("mock flags: 0x%x", mock_flags);

  // Iterate all rules in the inner map
  return iterate_mount_inner_map_extra(vmount_inner, mock_flags, buf, &offset);
}

SEC("lsm/sb_umount")
int BPF_PROG(varmor_umount, struct vfsmount *mnt, int flags) {
  // Retrieve the current task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();

  // Whether the current task has mount rules
  u32 mnt_ns = get_task_mnt_ns_id(current);
  u32 *vmount_inner = get_mount_inner_map(mnt_ns);
  if (vmount_inner == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;

  // Extract the source path from the from_path parameter provided by LSM hook point
  struct mount *m = real_mount(mnt);
  struct dentry *dentry = BPF_CORE_READ(m, mnt).mnt_root;
  prepend_path_to_first_block(dentry, mnt, buf, &offset);

  // Mock flags and fstype
  // Linux mount-flags do not use the value 0x200, so we use it to identify umount
  unsigned long mock_flags = AA_MAY_UMOUNT;
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX] = 'n';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+1] = 'o';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+2] = 'n';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+3] = 'e';
  buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX+4] = '\0';

  DEBUG_PRINT("================ lsm/sb_umount ================");
  DEBUG_PRINT("umount path: %s, length: %d, umount path offset: %d", 
      &(buf->value[offset.first_path & (PATH_MAX-1)]), PATH_MAX-offset.first_path-1, offset.first_path);
  DEBUG_PRINT("umount name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);
  DEBUG_PRINT("mock fstype: %s", &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
  DEBUG_PRINT("mock flags: 0x%x", mock_flags);

  // Iterate all rules in the inner map
  return iterate_mount_inner_map_extra(vmount_inner, mock_flags, buf, &offset);
}
