// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 vArmor-ebpf Authors

#ifndef __NETWORK_H
#define __NETWORK_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "enforcer.h"
#include "perms.h"

// Maximum rule count for network access control
#define NET_INNER_MAP_ENTRIES_MAX 50

#define AF_UNIX		1	  /* Unix domain sockets 		*/
#define AF_INET		2	  /* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

struct net_rule {
  u32 mode;
  u32 flags;
  unsigned char address[16];
  unsigned char mask[16];
  u32 port;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, OUTER_MAP_ENTRIES_MAX);
  __type(key, u32);
  __type(value, u32);
} v_net_outer SEC(".maps");

static u32 *get_net_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_net_outer, &mnt_ns);
}

static struct net_rule *get_net_rule(u32 *vnet_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vnet_inner, &rule_id);
}

static __noinline int iterate_net_inner_map(u32 *vnet_inner, struct sockaddr *address, u32 mnt_ns) {
  u32 inner_id, ip, i;
  bool match;

  for(inner_id=0; inner_id<NET_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct net_rule *rule = get_net_rule(vnet_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    match = true;

    if (address->sa_family == AF_INET) {
      // IPv4
      struct sockaddr_in *addr4 = (struct sockaddr_in *) address;
      DEBUG_PRINT("IPv4 address: 0x%x", addr4->sin_addr.s_addr);
      DEBUG_PRINT("IPv4 port: %d", bpf_ntohs(addr4->sin_port));

      if (rule->flags & CIDR_MATCH) {
        for (i = 0; i < 4; i++) {
          ip = (addr4->sin_addr.s_addr >> (8 * i)) & 0xff;
          if ((ip & rule->mask[i]) != rule->address[i]) {
            match = false;
            break;
          }
        }
      } else if (rule->flags & PRECISE_MATCH) {
        for (i = 0; i < 4; i++) {
          ip = (addr4->sin_addr.s_addr >> (8 * i)) & 0xff;
          if (ip != rule->address[i]) {
            match = false;
            break;
          }
        }
      }

      if (match && (rule->flags & PORT_MATCH) && (rule->port != bpf_ntohs(addr4->sin_port))) {
        match = false;
      }
      
      if (match) {
        DEBUG_PRINT("");
        DEBUG_PRINT("access denied");

        // Submit the audit event
        if (rule->mode & AUDIT_MODE) {
          struct audit_event *e;
          e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
          if (e) {
            DEBUG_PRINT("write audit event to ringbuf");
            e->mode = AUDIT_MODE;
            e->type = NETWORK_TYPE;
            e->mnt_ns = mnt_ns;
            e->tgid = bpf_get_current_pid_tgid()>>32;
            e->ktime = bpf_ktime_get_boot_ns();
            e->event_u.egress.sa_family = AF_INET;
            e->event_u.egress.sin_addr = addr4->sin_addr.s_addr;
            e->event_u.egress.port = bpf_ntohs(addr4->sin_port);
            bpf_ringbuf_submit(e, 0);
          }
        }
        return -EPERM;
      }
    } else {
      // IPv6
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) address;
      struct in6_addr ip6addr = BPF_CORE_READ(addr6, sin6_addr);

      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[0], ip6addr.in6_u.u6_addr8[1]);
      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[2], ip6addr.in6_u.u6_addr8[3]);
      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[4], ip6addr.in6_u.u6_addr8[5]);
      DEBUG_PRINT("IPv6 address: %d:%d", ip6addr.in6_u.u6_addr8[6], ip6addr.in6_u.u6_addr8[7]);
      DEBUG_PRINT("IPv6 port: %d", bpf_ntohs(addr6->sin6_port));

      if (rule->flags & CIDR_MATCH) {
        for (i = 0; i < 16; i++) {
          ip = ip6addr.in6_u.u6_addr8[i];
          if ((ip & rule->mask[i]) != rule->address[i]) {
            match = false;
            break;
          }
        }
      } else if (rule->flags & PRECISE_MATCH) {
        for (i = 0; i < 16; i++) {
          ip = ip6addr.in6_u.u6_addr8[i];
          if (ip != rule->address[i]) {
            match = false;
            break;
          }
        }
      }

      if (match && (rule->flags & PORT_MATCH) && (rule->port != bpf_ntohs(addr6->sin6_port))) {
        match = false;
      }

      if (match) {
        DEBUG_PRINT("");
        DEBUG_PRINT("access denied");

        // Submit the audit event
        if (rule->mode & AUDIT_MODE) {
          struct audit_event *e;
          e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
          if (e) {
            DEBUG_PRINT("write audit event to ringbuf");
            e->mode = AUDIT_MODE;
            e->type = NETWORK_TYPE;
            e->mnt_ns = mnt_ns;
            e->tgid = bpf_get_current_pid_tgid()>>32;
            e->ktime = bpf_ktime_get_boot_ns();
            e->event_u.egress.sa_family = AF_INET6;
            bpf_probe_read_kernel(e->event_u.egress.sin6_addr, 16, &ip6addr.in6_u.u6_addr8);
            e->event_u.egress.port = bpf_ntohs(addr6->sin6_port);
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

#endif /* __NETWORK_H */