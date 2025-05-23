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
// Maximum port count for network address rule
#define PORTS_COUNT_MAX 16

#define AF_UNIX		1	  /* Unix domain sockets 		*/
#define AF_INET		2	  /* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

struct net_sockaddr {
  unsigned char address[16];
  unsigned char mask[16];
  u16 port;
  u16 end_port;
  u16 ports[PORTS_COUNT_MAX];
};

struct net_socket {
  u64 domains;
  u64 types;
  u64 protocols;
};

struct net_rule {
  u32 mode;
  u32 flags;
  struct net_socket socket;
  struct net_sockaddr addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, OUTER_MAP_ENTRIES_MAX);
  __type(key, u32);
  __type(value, u32);
} v_net_outer SEC(".maps");

// Pods may be allocated at most 1 value for each of IPv4 and IPv6
struct pod_ip {
  u32 flags;
	unsigned char ipv4[16];
  unsigned char ipv6[16];
};

// The map caches the pod ip of the container.
// It uses the mnt_ns id as the key.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct pod_ip);
	__uint(max_entries, PODS_PER_NODE_MAX);
} v_pod_ip SEC(".maps");

static u32 *get_net_inner_map(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_net_outer, &mnt_ns);
}

static struct net_rule *get_net_rule(u32 *vnet_inner, u32 rule_id) {
  return bpf_map_lookup_elem(vnet_inner, &rule_id);
}

static struct pod_ip *get_pod_ip(u32 mnt_ns) {
  return bpf_map_lookup_elem(&v_pod_ip, &mnt_ns);
}

static __noinline int iterate_net_inner_map_for_socket_connect(u32 *vnet_inner, struct sockaddr *address, u32 mnt_ns) {
  u32 inner_id, ip, i;
  u16 port;
  bool match;

  for(inner_id=0; inner_id<NET_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct net_rule *rule = get_net_rule(vnet_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    if (!(rule->flags & (IPV4_MATCH|IPV6_MATCH|CIDR_MATCH|PRECISE_MATCH|POD_SELF_IP_MATCH|PORT_MATCH|PORT_RANGE_MATCH|PORTS_MATCH))) {
      continue;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    match = true;

    if ((address->sa_family == AF_INET) && (rule->flags & IPV4_MATCH)) {
      // IPv4
      struct sockaddr_in *addr4 = (struct sockaddr_in *) address;
      DEBUG_PRINT("IPv4 address: 0x%x", addr4->sin_addr.s_addr);
      DEBUG_PRINT("IPv4 port: %d", bpf_ntohs(addr4->sin_port));

      if (rule->flags & CIDR_MATCH) {
        for (i = 0; i < 4; i++) {
          ip = (addr4->sin_addr.s_addr >> (8 * i)) & 0xff;
          if ((ip & rule->addr.mask[i]) != rule->addr.address[i]) {
            match = false;
            break;
          }
        }
      } else if (rule->flags & PRECISE_MATCH) {
        for (i = 0; i < 4; i++) {
          ip = (addr4->sin_addr.s_addr >> (8 * i)) & 0xff;
          if (ip != rule->addr.address[i]) {
            match = false;
            break;
          }
        }
      } else if (rule->flags & POD_SELF_IP_MATCH) {
        struct pod_ip *podip = get_pod_ip(mnt_ns);
        if (podip == NULL || !(podip->flags & IPV4_MATCH)) {
          continue;
        }
        for (i = 0; i < 4; i++) {
          ip = (addr4->sin_addr.s_addr >> (8 * i)) & 0xff;
          if (ip != podip->ipv4[i]) {
            match = false;
            break;
          }
        }
      }

      port = bpf_ntohs(addr4->sin_port);
      if (match) {
        if ((rule->flags & PORT_MATCH) && (rule->addr.port != port)) {
          match = false;
        } else if ((rule->flags & PORT_RANGE_MATCH) && (rule->addr.port > port || rule->addr.end_port < port)) {
          match = false;
        } else if (rule->flags & PORTS_MATCH) {
          for (i = 0; i < PORTS_COUNT_MAX; i++) {
            if (rule->addr.ports[i] == port) {
              break;
            }
            if (rule->addr.ports[i] == 0 || i == PORTS_COUNT_MAX-1) {
              match = false;
              break;
            }
          }
        }
      }
      
      if (match) {
        DEBUG_PRINT("");

        // Submit the audit event
        if (rule->mode & AUDIT_MODE) {
          struct audit_event *e;
          e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
          if (e) {
            DEBUG_PRINT("write audit event to ringbuf");
            e->mode = rule->mode;
            e->type = NETWORK_TYPE;
            e->mnt_ns = mnt_ns;
            e->tgid = bpf_get_current_pid_tgid()>>32;
            e->ktime = bpf_ktime_get_boot_ns();
            e->event_u.network.type = CONNETC_TYPE;
            e->event_u.network.addr.sa_family = AF_INET;
            e->event_u.network.addr.sin_addr = addr4->sin_addr.s_addr;
            e->event_u.network.addr.port = port;
            bpf_ringbuf_submit(e, 0);
          }
        }

        if (rule->mode & ENFORCE_MODE) {
          DEBUG_PRINT("access denied");
          return -EPERM;
        }
      }
    } else if ((address->sa_family == AF_INET6) && (rule->flags & IPV6_MATCH)) {
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
          if ((ip & rule->addr.mask[i]) != rule->addr.address[i]) {
            match = false;
            break;
          }
        }
      } else if (rule->flags & PRECISE_MATCH) {
        for (i = 0; i < 16; i++) {
          ip = ip6addr.in6_u.u6_addr8[i];
          if (ip != rule->addr.address[i]) {
            match = false;
            break;
          }
        }
      } else if (rule->flags & POD_SELF_IP_MATCH) {
        struct pod_ip *podip = get_pod_ip(mnt_ns);
        if (podip == NULL || !(podip->flags & IPV6_MATCH)) {
          continue;
        }
        for (i = 0; i < 16; i++) {
          ip = ip6addr.in6_u.u6_addr8[i];
          if (ip != podip->ipv6[i]) {
            match = false;
            break;
          }
        }
      }

      port = bpf_ntohs(addr6->sin6_port);
      if (match) {
        if ((rule->flags & PORT_MATCH) && (rule->addr.port != port)) {
          match = false;
        } else if ((rule->flags & PORT_RANGE_MATCH) && (rule->addr.port > port || rule->addr.end_port < port)) {
          match = false;
        } else if (rule->flags & PORTS_MATCH) {
          for (i = 0; i < PORTS_COUNT_MAX; i++) {
            if (rule->addr.ports[i] == port) {
              break;
            }
            if (rule->addr.ports[i] == 0 || i == PORTS_COUNT_MAX-1) {
              match = false;
              break;
            }
          }
        }
      }

      if (match) {
        DEBUG_PRINT("");

        // Submit the audit event
        if (rule->mode & AUDIT_MODE) {
          struct audit_event *e;
          e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
          if (e) {
            DEBUG_PRINT("write audit event to ringbuf");
            e->mode = rule->mode;
            e->type = NETWORK_TYPE;
            e->mnt_ns = mnt_ns;
            e->tgid = bpf_get_current_pid_tgid()>>32;
            e->ktime = bpf_ktime_get_boot_ns();
            e->event_u.network.type = CONNETC_TYPE;
            e->event_u.network.addr.sa_family = AF_INET6;
            bpf_probe_read_kernel(e->event_u.network.addr.sin6_addr, 16, &ip6addr.in6_u.u6_addr8);
            e->event_u.network.addr.port = port;
            bpf_ringbuf_submit(e, 0);
          }
        }

        if (rule->mode & ENFORCE_MODE) {
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

static __noinline int iterate_net_inner_map_for_socket_create(u32 *vnet_inner, struct v_socket *s, u32 mnt_ns) {
  u32 inner_id;

  for(inner_id=0; inner_id<NET_INNER_MAP_ENTRIES_MAX; inner_id++) {
    // The key of the inner map must start from 0
    struct net_rule *rule = get_net_rule(vnet_inner, inner_id);
    if (rule == NULL) {
      DEBUG_PRINT("");
      DEBUG_PRINT("access allowed");
      return 0;
    }

    if (!(rule->flags & SOCKET_MATCH)) {
      continue;
    }

    DEBUG_PRINT("---- rule id: %d ----", inner_id);
    DEBUG_PRINT("rule domains: 0x%lx, requested domain mask: 0x%lx", rule->socket.domains, TO_MASK(s->domain));
    DEBUG_PRINT("rule types: 0x%lx, requested domain mask: 0x%lx", rule->socket.types, TO_MASK(s->type));
    DEBUG_PRINT("rule protocols: 0x%lx, requested domain mask: 0x%lx", rule->socket.protocols, TO_MASK(s->protocol));

    if (rule->socket.domains && !(rule->socket.domains & TO_MASK(s->domain))) {
      continue;
    }

    if (rule->socket.types && !(rule->socket.types & TO_MASK(s->type))) {
      continue;
    }

    if (rule->socket.protocols && !(rule->socket.protocols & TO_MASK(s->protocol))) {
      continue;
    }

    DEBUG_PRINT("");

    // Submit the audit event
    if (rule->mode & AUDIT_MODE) {
      struct audit_event *e;
      e = bpf_ringbuf_reserve(&v_audit_rb, sizeof(struct audit_event), 0);
      if (e) {
        DEBUG_PRINT("write audit event to ringbuf");
          e->mode = rule->mode;
          e->type = NETWORK_TYPE;
          e->mnt_ns = mnt_ns;
          e->tgid = bpf_get_current_pid_tgid()>>32;
          e->ktime = bpf_ktime_get_boot_ns();
          e->event_u.network.type = SOCKET_TYPE;
          e->event_u.network.socket.domain = s->domain;
          e->event_u.network.socket.type = s->type;
          e->event_u.network.socket.protocol = s->protocol;
          bpf_ringbuf_submit(e, 0);
      }
    }

    if (rule->mode & ENFORCE_MODE) {
      DEBUG_PRINT("access denied");
      return -EPERM;
    }
  }

  DEBUG_PRINT("");
  DEBUG_PRINT("access allowed");
  return 0;
}

#endif /* __NETWORK_H */