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
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Whether the current task is confined in a profile
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == 0)
    return ret;

  struct user_namespace *current_ns = get_task_user_ns(current);
  kernel_cap_t current_cap_effective = get_task_cap_effective(current);
  // To achieve compatibility with kernel 6.3+, we make use of type casting.
  u64 current_effective_mask = *(u64 *)&current_cap_effective;

  // When writing to the /tmp directory, overlayfs temporarily overrides the current task's cred to set 
  // the xattr in the trusted namespace using CAP_SYS_ADMIN. Therefore, we need to skip the capability 
  // check to maintain compatibility with it.
  if (current_ns == ns && current_effective_mask == 0x1fffeffffff) {
    return ret;
  }

  // Since v1.4.0, containerd will enable the cgroup namespace by default in the cgroup v2 environment.
  // At this point, using setns/nsenter to enter the container requires CAP_SYS_ADMIN in the container's 
  // user namespace. Therefore, we need to ignore the capability check when current_effective_mask is 
  // 0x1ffffffffff and the current task's user namespace is the same as the ns parameter of capable().
  // This will ensure that pods/exec can run normally.
  if (current_ns == ns && current_effective_mask == 0x1ffffffffff) {
    return ret;
  }

  DEBUG_PRINT("================ lsm/capable ================");
  u64 request_cap_mask = TO_MASK(cap);
  DEBUG_PRINT("task(mnt ns: %u) current_effective_mask: 0x%lx, request_cap_mask: 0x%lx", 
          mnt_ns, current_effective_mask, request_cap_mask);

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = CAPABILITY_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.capability = cap;
      bpf_ringbuf_submit(e, 0);
    }
  } else {
    // Return directly if there is no capability rule for the current task
    struct capability_rule *rule = get_capability_rules(mnt_ns);
    if (rule == NULL)
      return ret;

    // Permission check
    if (rule->caps & request_cap_mask) {
      // Submit the audit event
      if (rule->mode & AUDIT_MODE) {
        struct audit_event *e;
        e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
        if (e) {
          DEBUG_PRINT("write audit event to ringbuf");
          e->action = rule->mode & DENY_MODE ? DENIED_ACTION : AUDIT_ACTION;
          e->type = CAPABILITY_TYPE;
          e->mnt_ns = mnt_ns;
          e->tgid = bpf_get_current_pid_tgid()>>32;
          e->ktime = bpf_ktime_get_boot_ns();
          e->event_u.capability = cap;
          bpf_ringbuf_submit(e, 0);
        }
      }

      if (rule->mode & DENY_MODE) {
        DEBUG_PRINT("task(mnt ns: %u) is not allowed to use capability: 0x%x", mnt_ns, cap);
        return -EPERM;
      }
    }
  }

  return ret;
}

SEC("lsm/file_open")
int BPF_PROG(varmor_file_open, struct file *file) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Don't check permission here if called from execve()
  if(task_in_execve(current))
    return 0;

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Return directly if there are no file rules for the current task
  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (*profile_mode == ENFORCE_MODE && vfile_inner == NULL)
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
  
  if (*profile_mode == COMPLAIN_MODE) {
    // Ignore the behavior when the cred of current task is overridden by overlayfs temporarily
    // Note: 
    // Please remind the users do not execute the 'kubectl exec' command during the behavior modeling.
    // Otherwise, some exceptional behaviors will be recorded.
    kernel_cap_t current_cap_effective = get_task_cap_effective(current);
    u64 current_effective_mask = *(u64 *)&current_cap_effective;
    if (current_effective_mask == 0x1fffeffffff) {
      DEBUG_PRINT("current_effective_mask is 0x1fffeffffff, ignore the behavior");
      return 0;
    }

    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = FILE_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.path.permissions = requested_perms;
      bpf_probe_read_kernel_str(&e->event_u.path.path, PATH_MAX-offset.first_path & (PATH_MAX-1), &(buf->value[offset.first_path & (PATH_MAX-1)]));
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE && vfile_inner != NULL) {
    // Iterate all rules of the inner map
    return iterate_file_inner_map_for_file(vfile_inner, buf, &offset, requested_perms, mnt_ns);
  } else {
    return 0;
  }
}

SEC("lsm/path_symlink")
int BPF_PROG(varmor_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Return directly if there are no file rules for the current task
  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (*profile_mode == ENFORCE_MODE && vfile_inner == NULL)
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

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = FILE_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.path.permissions = AA_MAY_LINK | AA_MAY_WRITE;
      bpf_probe_read_kernel_str(&e->event_u.path.path, PATH_MAX-offset.first_path & (PATH_MAX-1), &(buf->value[offset.first_path & (PATH_MAX-1)]));
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE && vfile_inner != NULL) {
    // Iterate all rules in the inner map
    return iterate_file_inner_map_for_file(vfile_inner, buf, &offset, AA_MAY_LINK | AA_MAY_WRITE, mnt_ns);
  } else {
    return 0;
  }
}

SEC("lsm/path_link")
int BPF_PROG(varmor_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Return directly if there are no file rules for the current task
  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (*profile_mode == ENFORCE_MODE && vfile_inner == NULL)
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
  
  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;

    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event of old path to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = FILE_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.path.permissions = AA_MAY_LINK | AA_MAY_READ;
      bpf_probe_read_kernel_str(&e->event_u.path.path, PATH_MAX-offset.first_path & (PATH_MAX-1), &(buf->value[offset.first_path & (PATH_MAX-1)]));
      bpf_ringbuf_submit(e, 0);
    }

    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event of new path to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = FILE_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.path.permissions = AA_MAY_LINK | AA_MAY_WRITE;
      bpf_probe_read_kernel_str(&e->event_u.path.path, PATH_MAX*2-offset.second_path & (PATH_MAX-1), &(buf->value[offset.second_path & (PATH_MAX*2-1)]));
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE) {
    // Tail call
    bpf_tail_call(ctx, &file_progs, 0);
    return 0;
  } else {
    return 0;
  }
}

SEC("lsm/path_rename")
int BPF_PROG(varmor_path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, const unsigned int flags) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Return directly if there are no file rules for the current task
  u32 *vfile_inner = get_file_inner_map(mnt_ns);
  if (*profile_mode == ENFORCE_MODE && vfile_inner == NULL)
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

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;

    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event of old path to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = FILE_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.path.permissions = AA_MAY_RENAME | AA_MAY_READ;
      bpf_probe_read_kernel_str(&e->event_u.path.path, PATH_MAX-offset.first_path & (PATH_MAX-1), &(buf->value[offset.first_path & (PATH_MAX-1)]));
      bpf_ringbuf_submit(e, 0);
    }

    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event of new path to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = FILE_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.path.permissions = AA_MAY_RENAME | AA_MAY_WRITE;
      bpf_probe_read_kernel_str(&e->event_u.path.path, PATH_MAX*2-offset.second_path & (PATH_MAX-1), &(buf->value[offset.second_path & (PATH_MAX*2-1)]));
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE) {
    // Tail call
    bpf_tail_call(ctx, &file_progs, 1);
    return 0;
  } else {
    return 0;
  }
}

SEC("lsm/bprm_check_security")
int BPF_PROG(varmor_bprm_check_security, struct linux_binprm *bprm, int ret) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Return directly if there are no process rules for the current task
  u32 *vbprm_inner = get_bprm_inner_map(mnt_ns);
  if (*profile_mode == ENFORCE_MODE && vbprm_inner == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;

  // Extract the new executable path from the bprm parameter
  prepend_string_to_first_block(bprm->filename, buf, &offset);

  DEBUG_PRINT("================ lsm/bprm_check_security ================");
  DEBUG_PRINT("path: %s", buf->value);
  DEBUG_PRINT("offset: %d, length: %d", offset.first_path, offset.first_path-1);
  DEBUG_PRINT("file name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = BPRM_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      e->event_u.path.permissions = AA_MAY_EXEC;
      bpf_probe_read_kernel_str(&e->event_u.path.path, offset.first_path & (PATH_MAX-1), &buf->value);
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE && vbprm_inner != NULL) {
    // Iterate all rules of the inner map
    return iterate_bprm_inner_map_for_executable(vbprm_inner, buf, &offset, mnt_ns);
  } else {
    return 0;
  }
}

SEC("lsm/socket_connect")
int BPF_PROG(varmor_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
  // We only care about ipv4 and ipv6 for now
	if (address->sa_family != AF_INET && address->sa_family != AF_INET6)
		return 0;

  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  DEBUG_PRINT("================ lsm/socket_connect ================");
  DEBUG_PRINT("socket status: 0x%x", sock->state);
  DEBUG_PRINT("socket type: 0x%x", sock->type);
  DEBUG_PRINT("socket flags: 0x%x", sock->flags);

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;

    if (address->sa_family == AF_INET) {
      // IPv4
      struct sockaddr_in *addr4 = (struct sockaddr_in *) address;

      DEBUG_PRINT("IPv4 address: 0x%x", addr4->sin_addr.s_addr);
      DEBUG_PRINT("IPv4 port: %d", bpf_ntohs(addr4->sin_port));
      DEBUG_PRINT("write audit event to ringbuf");
      e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
      if (e) {
        e->action = ALLOWED_ACTION;
        e->type = NETWORK_TYPE;
        e->mnt_ns = mnt_ns;
        e->tgid = bpf_get_current_pid_tgid()>>32;
        e->ktime = bpf_ktime_get_boot_ns();
        e->event_u.network.type = CONNETC_TYPE;
        e->event_u.network.addr.sa_family = AF_INET;
        e->event_u.network.addr.sin_addr = addr4->sin_addr.s_addr;
        e->event_u.network.addr.port = bpf_ntohs(addr4->sin_port);
        bpf_ringbuf_submit(e, 0);
      }
    } else if (address->sa_family == AF_INET6) {
      // IPv6
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
      struct in6_addr ip6addr = BPF_CORE_READ(addr6, sin6_addr);

      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[0], ip6addr.in6_u.u6_addr8[1]);
      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[2], ip6addr.in6_u.u6_addr8[3]);
      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[4], ip6addr.in6_u.u6_addr8[5]);
      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[6], ip6addr.in6_u.u6_addr8[7]);
      DEBUG_PRINT("IPv6 port: %d", bpf_ntohs(addr6->sin6_port));
      DEBUG_PRINT("write audit event to ringbuf");
      e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
      if (e) {
        e->action = ALLOWED_ACTION;
        e->type = NETWORK_TYPE;
        e->mnt_ns = mnt_ns;
        e->tgid = bpf_get_current_pid_tgid()>>32;
        e->ktime = bpf_ktime_get_boot_ns();
        e->event_u.network.type = CONNETC_TYPE;
        e->event_u.network.addr.sa_family = AF_INET6;
        bpf_probe_read_kernel(e->event_u.network.addr.sin6_addr, 16, &ip6addr.in6_u.u6_addr8);
        e->event_u.network.addr.port = bpf_ntohs(addr6->sin6_port);
        bpf_ringbuf_submit(e, 0);
      }
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE) {
    // Return directly if there are no network rules for the current task
    u32 *vnet_inner = get_net_inner_map(mnt_ns);
    if (vnet_inner == NULL)
      return 0;

    // Iterate all rules in the inner map
    return iterate_net_inner_map_for_socket_connect(vnet_inner, address, mnt_ns);
  } else {
    return 0;
  }
}

SEC("lsm/socket_create")
int BPF_PROG(varmor_socket_create, int family, int type, int protocol, int kern) {
  // Ignore kernel socket
  if (kern == 1)
    return 0;

  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  DEBUG_PRINT("================ lsm/socket_create ================");
  DEBUG_PRINT("socket family: 0x%x", family);
  DEBUG_PRINT("socket type: 0x%x", type);
  DEBUG_PRINT("socket protocol: 0x%x", protocol);

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
        e->action = ALLOWED_ACTION;
        e->type = NETWORK_TYPE;
        e->mnt_ns = mnt_ns;
        e->tgid = bpf_get_current_pid_tgid()>>32;
        e->ktime = bpf_ktime_get_boot_ns();
        e->event_u.network.type = SOCKET_TYPE;
        e->event_u.network.socket.domain = family;
        e->event_u.network.socket.type = type;
        e->event_u.network.socket.protocol = protocol;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE) {
    // Return directly if there are no network rules for the current task
    u32 *vnet_inner = get_net_inner_map(mnt_ns);
    if (vnet_inner == NULL)
      return 0;

    // Iterate all rules in the inner map
    struct v_socket s = { .domain = family, .type = type, .protocol = protocol};
    return iterate_net_inner_map_for_socket_create(vnet_inner, &s, mnt_ns);
  } else {
    return 0;
  }
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(varmor_ptrace_access_check, struct task_struct *child, unsigned int mode) {
  // Retrieve the mnt ns id of the current task and the child task
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 current_mnt_ns = get_task_mnt_ns_id(current);
  u32 child_mnt_ns = get_task_mnt_ns_id(child);

  // Retrieve the profile mode of the current task and the child task
  u32 *current_profile_mode = get_profile_mode(current_mnt_ns);
  u32 *child_profile_mode = get_profile_mode(child_mnt_ns);

  if (current_profile_mode != NULL) {
    DEBUG_PRINT("================ lsm/ptrace_access_check/current_task ================");
    if (*current_profile_mode == COMPLAIN_MODE) {
      // Record the behavior to the ringbuf
      struct audit_event *e;
      e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
      if (e) {
        DEBUG_PRINT("write audit event to ringbuf");
        e->action = ALLOWED_ACTION;
        e->type = PTRACE_TYPE;
        e->mnt_ns = current_mnt_ns;
        e->tgid = bpf_get_current_pid_tgid()>>32;
        e->ktime = bpf_ktime_get_boot_ns();
        e->event_u.ptrace.permissions = (mode & PTRACE_MODE_READ) ? AA_PTRACE_READ : AA_PTRACE_TRACE;
        e->event_u.ptrace.external = (current_mnt_ns != child_mnt_ns);
        bpf_ringbuf_submit(e, 0);
      }
    } else if (*current_profile_mode == ENFORCE_MODE) {
      // Retrieve the ptrace rule for the current task
      struct ptrace_rule *rule = get_ptrace_rule(current_mnt_ns);
      if (rule != NULL) {
        // Check whether the current task is allowed to trace or read a child task
        if (!ptrace_permission_check(current_mnt_ns, child_mnt_ns, rule, (mode & PTRACE_MODE_READ) ? AA_PTRACE_READ : AA_PTRACE_TRACE)) {
          // Submit the audit event
          if (rule->mode & AUDIT_MODE) {
            struct audit_event *e;
            e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
            if (e) {
              DEBUG_PRINT("write audit event to ringbuf");
              e->action = rule->mode & DENY_MODE ? DENIED_ACTION : AUDIT_ACTION;
              e->type = PTRACE_TYPE;
              e->mnt_ns = current_mnt_ns;
              e->tgid = bpf_get_current_pid_tgid()>>32;
              e->ktime = bpf_ktime_get_boot_ns();
              e->event_u.ptrace.permissions = (mode & PTRACE_MODE_READ) ? AA_PTRACE_READ : AA_PTRACE_TRACE;
              e->event_u.ptrace.external = (current_mnt_ns != child_mnt_ns);
              bpf_ringbuf_submit(e, 0);
            }
          }

          if (rule->mode & DENY_MODE) {
            DEBUG_PRINT("current task(mnt ns: %u) is not allowed to read/trace the task(mnt ns: %u)", current_mnt_ns, child_mnt_ns);
            return -EPERM;
          }
        }
      }
    }
  }

  // By default, we allow the child task to be traced or read by tasks in the init mnt ns
  if (child_profile_mode != NULL && current_mnt_ns != init_mnt_ns) {
    DEBUG_PRINT("================ lsm/ptrace_access_check/child_task ================");
    if (*child_profile_mode == COMPLAIN_MODE) {
      // Record the behavior to the ringbuf
      struct audit_event *e;
      e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
      if (e) {
        DEBUG_PRINT("write audit event to ringbuf");
        e->action = ALLOWED_ACTION;
        e->type = PTRACE_TYPE;
        e->mnt_ns = child_mnt_ns;
        e->tgid = bpf_get_current_pid_tgid()>>32;
        e->ktime = bpf_ktime_get_boot_ns();
        e->event_u.ptrace.permissions = (mode & PTRACE_MODE_READ) ? AA_MAY_BE_READ : AA_MAY_BE_TRACED;
        e->event_u.ptrace.external = (current_mnt_ns != child_mnt_ns);
        bpf_ringbuf_submit(e, 0);
      }
    } else if (*child_profile_mode == ENFORCE_MODE) {
      // Retrieve the ptrace rule for the child task
      struct ptrace_rule *rule = get_ptrace_rule(child_mnt_ns);
      if (rule != NULL) {
        // Check whether the child task is allowed to be traced or read by the current task
        if (!ptrace_permission_check(current_mnt_ns, child_mnt_ns, rule, (mode & PTRACE_MODE_READ) ? AA_MAY_BE_READ : AA_MAY_BE_TRACED)) {
          // Submit the audit event
          if (rule->mode & AUDIT_MODE) {
            struct audit_event *e;
            e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
            if (e) {
              DEBUG_PRINT("write audit event to ringbuf");
              e->action = rule->mode & DENY_MODE ? DENIED_ACTION : AUDIT_ACTION;
              e->type = PTRACE_TYPE;
              e->mnt_ns = child_mnt_ns;
              e->tgid = bpf_get_current_pid_tgid()>>32;
              e->ktime = bpf_ktime_get_boot_ns();
              e->event_u.ptrace.permissions = (mode & PTRACE_MODE_READ) ? AA_MAY_BE_READ : AA_MAY_BE_TRACED;
              e->event_u.ptrace.external = (current_mnt_ns != child_mnt_ns);
              bpf_ringbuf_submit(e, 0);
            }
          }

          if (rule->mode & DENY_MODE) {
            DEBUG_PRINT("current task(mnt ns: %u) is not allowed to readby/traceby the task(mnt ns: %u)", current_mnt_ns, child_mnt_ns);
            return -EPERM;
          }
        }
      }
    }
  }

  return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(varmor_mount, char *dev_name, struct path *path, char *type, unsigned long flags, void *data) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;

  // Extract the dev path from the dev_name parameter
  prepend_string_to_first_block(dev_name, buf, &offset);

  // Extract the fstype from the type parameter
  prepend_fstype_to_third_block(type, buf);

  DEBUG_PRINT("================ lsm/sb_mount ================");
  DEBUG_PRINT("dev path: %s", buf->value);
  DEBUG_PRINT("offset: %d, length: %d", offset.first_path, offset.first_path-1);
  DEBUG_PRINT("dev name: %s, length: %d", &(buf->value[PATH_MAX*2]), offset.first_name);
  DEBUG_PRINT("fstype: %s", &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
  DEBUG_PRINT("flags: 0x%x", flags);

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = MOUNT_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      bpf_probe_read_kernel_str(e->event_u.mount.path, offset.first_path & (PATH_MAX-1), buf->value);
      bpf_probe_read_kernel_str(e->event_u.mount.type, FILE_SYSTEM_TYPE_MAX, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
      e->event_u.mount.flags = flags;
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE) {
    // Return directly if there are no mount rules for the current task
    u32 *vmount_inner = get_mount_inner_map(mnt_ns);
    if (vmount_inner == NULL)
      return 0;

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
    return iterate_mount_inner_map(vmount_inner, flags, buf, &offset, mnt_ns);
  } else {
    return 0;
  }
}

SEC("lsm/move_mount")
int BPF_PROG(varmor_move_mount, struct path *from_path, struct path *to_path) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;
  
  // Extract the source path from the from_path parameter
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

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = MOUNT_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      bpf_probe_read_kernel_str(e->event_u.mount.path, (PATH_MAX-offset.first_path) & (PATH_MAX-1), &(buf->value[offset.first_path & (PATH_MAX-1)]));
      bpf_probe_read_kernel_str(e->event_u.mount.type, FILE_SYSTEM_TYPE_MAX, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
      e->event_u.mount.flags = mock_flags;
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE) {
    // Return directly if there are no mount rules for the current task
    u32 *vmount_inner = get_mount_inner_map(mnt_ns);
    if (vmount_inner == NULL)
      return 0;

    // Iterate all rules in the inner map
    return iterate_mount_inner_map_extra(vmount_inner, mock_flags, buf, &offset, mnt_ns);
  } else {
    return 0;
  }
}

SEC("lsm/sb_umount")
int BPF_PROG(varmor_umount, struct vfsmount *mnt, int flags) {
  // Retrieve the current task and its mnt ns id
  struct task_struct *current = (struct task_struct *)bpf_get_current_task();
  u32 mnt_ns = get_task_mnt_ns_id(current);

  // Return directly if the current task is unconfined
  u32 *profile_mode = get_profile_mode(mnt_ns);
  if (profile_mode == NULL)
    return 0;

  // Prepare buffer
  struct buffer_offset offset = { .first_path = 0, .first_name = 0, .second_path = 0, .second_name = 0 };
  struct buffer *buf = get_buffer();
  if (buf == NULL)
    return 0;

  // Extract the source path from the from_path parameter
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

  if (*profile_mode == COMPLAIN_MODE) {
    // Record the behavior to the ringbuf
    struct audit_event *e;
    e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
    if (e) {
      DEBUG_PRINT("write audit event to ringbuf");
      e->action = ALLOWED_ACTION;
      e->type = MOUNT_TYPE;
      e->mnt_ns = mnt_ns;
      e->tgid = bpf_get_current_pid_tgid()>>32;
      e->ktime = bpf_ktime_get_boot_ns();
      bpf_probe_read_kernel_str(e->event_u.mount.path, (PATH_MAX-offset.first_path) & (PATH_MAX-1), &(buf->value[offset.first_path & (PATH_MAX-1)]));
      bpf_probe_read_kernel_str(e->event_u.mount.type, FILE_SYSTEM_TYPE_MAX, &(buf->value[PATH_MAX*3-FILE_SYSTEM_TYPE_MAX]));
      e->event_u.mount.flags = mock_flags;
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  } else if (*profile_mode == ENFORCE_MODE) {
    // Return directly if there are no mount rules for the current task
    u32 *vmount_inner = get_mount_inner_map(mnt_ns);
    if (vmount_inner == NULL)
      return 0;

    // Iterate all rules in the inner map
    return iterate_mount_inner_map_extra(vmount_inner, mock_flags, buf, &offset, mnt_ns);
  } else {
    return 0;
  }
}
