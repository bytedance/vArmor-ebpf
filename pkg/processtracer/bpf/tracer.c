// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define MAX_FILENAME_LEN 64
#define MAX_ENV_LEN 256
#define MAX_ENV_EXTRACT_LOOP_COUNT 400
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} process_events SEC(".maps");

struct process_event {
    u32 type;
    u32 parent_pid;
    u32 parent_tgid;
    u32 child_pid;
    u32 child_tgid;
    u32 mnt_ns_id;
    unsigned char parent_task[TASK_COMM_LEN];
    unsigned char child_task[TASK_COMM_LEN];
    unsigned char filename[MAX_FILENAME_LEN];
};

const struct process_event *unused __attribute__((unused));

static u32 get_task_mnt_ns_id(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

// https://elixir.bootlin.com/linux/v5.4.196/source/kernel/fork.c#L2388
// https://elixir.bootlin.com/linux/v5.4.196/source/include/trace/events/sched.h#L287
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    // TP_PROTO(struct task_struct *parent, struct task_struct *child)
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    struct process_event event = {};

    event.type = 1;
    BPF_CORE_READ_INTO(&event.parent_pid, parent, pid);
    BPF_CORE_READ_INTO(&event.parent_tgid, parent, tgid);
    BPF_CORE_READ_STR_INTO(&event.parent_task, parent, comm);
    BPF_CORE_READ_INTO(&event.child_pid, child, pid);
    BPF_CORE_READ_INTO(&event.child_tgid, child, tgid);
    BPF_CORE_READ_STR_INTO(&event.child_task, child, comm);
    event.mnt_ns_id = get_task_mnt_ns_id(child);

    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// https://elixir.bootlin.com/linux/v5.4.196/source/fs/exec.c#L1722
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    // TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
    struct task_struct *current = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    struct task_struct *parent = BPF_CORE_READ(current, parent);

    struct process_event event = {};

    event.type = 2;
    BPF_CORE_READ_INTO(&event.parent_pid, parent, pid);
    BPF_CORE_READ_INTO(&event.parent_tgid, parent, tgid);
    BPF_CORE_READ_STR_INTO(&event.parent_task, parent, comm);
    BPF_CORE_READ_INTO(&event.child_pid, current, pid);
    BPF_CORE_READ_INTO(&event.child_tgid, current, tgid);
    BPF_CORE_READ_STR_INTO(&event.child_task, current, comm);
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), BPF_CORE_READ(bprm, filename));
    event.mnt_ns_id = get_task_mnt_ns_id(current);
       
    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
