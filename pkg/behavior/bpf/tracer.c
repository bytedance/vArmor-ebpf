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
} events SEC(".maps");

struct event {
    u32 type;
    u32 parent_pid;
    u32 parent_tgid;
    u32 child_pid;
    u32 child_tgid;
    unsigned char parent_task[TASK_COMM_LEN];
    unsigned char child_task[TASK_COMM_LEN];
    unsigned char filename[MAX_FILENAME_LEN];
    unsigned char env[MAX_ENV_LEN];
    u32 num;
};

const struct event *unused __attribute__((unused));

// https://elixir.bootlin.com/linux/v5.4.196/source/kernel/fork.c#L2388
// https://elixir.bootlin.com/linux/v5.4.196/source/include/trace/events/sched.h#L287
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    // TP_PROTO(struct task_struct *parent, struct task_struct *child)
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    struct event event = {};

    event.type = 1;
    BPF_CORE_READ_INTO(&event.parent_pid, parent, pid);
    BPF_CORE_READ_INTO(&event.parent_tgid, parent, tgid);
    BPF_CORE_READ_STR_INTO(&event.parent_task, parent, comm);
    BPF_CORE_READ_INTO(&event.child_pid, child, pid);
    BPF_CORE_READ_INTO(&event.child_tgid, child, tgid);
    BPF_CORE_READ_STR_INTO(&event.child_task, child, comm);

    u64 env_start = 0;
    u64 env_end = 0;
    int i = 0;
    int len = 0;

    BPF_CORE_READ_INTO(&env_start, parent, mm, env_start);
    BPF_CORE_READ_INTO(&env_end, parent, mm, env_end);
    
    while(i < MAX_ENV_EXTRACT_LOOP_COUNT && env_start < env_end ) {
        len = bpf_probe_read_kernel_str(&event.env, sizeof(event.env), (void *)env_start);
        if ( len <= 0 ) {
            break;
        } else if ( event.env[0] == 'V' && 
                    event.env[1] == 'A' && 
                    event.env[2] == 'R' && 
                    event.env[3] == 'M' && 
                    event.env[4] == 'O' && 
                    event.env[5] == 'R' && 
                    event.env[6] == '=' ) {
            break;
        } else {
            env_start = env_start + len;
            event.env[0] = 0;
            i++;
        }
    }
    
    event.num = i;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

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

    struct event event = {};

    event.type = 2;
    BPF_CORE_READ_INTO(&event.parent_pid, parent, pid);
    BPF_CORE_READ_INTO(&event.parent_tgid, parent, tgid);
    BPF_CORE_READ_STR_INTO(&event.parent_task, parent, comm);
    BPF_CORE_READ_INTO(&event.child_pid, current, pid);
    BPF_CORE_READ_INTO(&event.child_tgid, current, tgid);
    BPF_CORE_READ_STR_INTO(&event.child_task, current, comm);
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), BPF_CORE_READ(bprm, filename));

    u64 env_start = 0;
    u64 env_end = 0;
    int i = 0;
    int len = 0;

    BPF_CORE_READ_INTO(&env_start, current, mm, env_start);
    BPF_CORE_READ_INTO(&env_end, current, mm, env_end);
    
    while(i < MAX_ENV_EXTRACT_LOOP_COUNT && env_start < env_end ) {
        len = bpf_probe_read_user_str(&event.env, sizeof(event.env), (void *)env_start);

        if ( len <= 0 ) {
            break;
        } else if ( event.env[0] == 'V' && 
                    event.env[1] == 'A' && 
                    event.env[2] == 'R' && 
                    event.env[3] == 'M' && 
                    event.env[4] == 'O' && 
                    event.env[5] == 'R' && 
                    event.env[6] == '=' ) {
            break;
        } else {
            env_start = env_start + len;
            event.env[0] = 0;
            i++;
        }
    }

    event.num = i;        
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
