/*
 * Soft:        xdp_fw stand for XDP Firewall. It offers a simple layer3
 * 		packet filtering. Operation are really fast since it
 * 		doesnt travel/traverse kernel to apply kernel rules unlike
 * 		netfilter. Initial goal for this module is to provide a packet
 * 		isolation/filtering for Keepalived VRRP framework.
 *
 * Part:        XDP eBPF source code to be loaded into kernel.
 *
 * Author:      Alexandre Cassen, <acassen@keepalived.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2019 Alexandre Cassen, <acassen@gmail.com>
 */

#define KBUILD_MODNAME "xdp_fw"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>

/* linux/if_vlan.h have not exposed this as UAPI, thus mirror some here
 *
 *      struct vlan_hdr - vlan header
 *      @h_vlan_TCI: priority and VLAN ID
 *      @h_vlan_encapsulated_proto: packet type ID or len
 */
struct _vlan_hdr {
	__be16 hvlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct parse_pkt {
	__u16 l3_proto;
	__u16 l3_offset;
};

struct flow_key {
	union {
		__u32 addr;
		__u32 addr6[4];
	};
	__u32 proto;
} __attribute__ ((__aligned__(8)));

struct bpf_map_def SEC("maps") l3_filter = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof (struct flow_key),
	.value_size = sizeof (__u64),	/* Drop counter */
	.max_entries = 32768,
	.map_flags = BPF_F_NO_PREALLOC,
};

#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* Packet filter */
static __always_inline int
filter_packet(void *data, void *data_end, struct parse_pkt *pkt)
{
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct flow_key key = { };
	__u64 *drop_cnt;

	/* Room sanitize */
	if (pkt->l3_proto == ETH_P_IP) {
		iph = data + pkt->l3_offset;
		if (iph + 1 > data_end)
			return XDP_PASS;
		key.proto = ETH_P_IP;
		key.addr6[1] = key.addr6[2] = key.addr6[3] = 0;
		key.addr = iph->daddr;
	} else if (pkt->l3_proto == ETH_P_IPV6) {
		ip6h = data + pkt->l3_offset;
		if (ip6h + 1 > data_end)
			return XDP_PASS;
		key.proto = ETH_P_IPV6;
		__builtin_memcpy(key.addr6, ip6h->daddr.s6_addr32,
				 sizeof (key.addr6));
	} else {
		return XDP_PASS;
	}

	drop_cnt = bpf_map_lookup_elem(&l3_filter, &key);
	if (drop_cnt) {
		*drop_cnt += 1;
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* Ethernet frame parsing and sanitize */
static __always_inline bool
parse_eth_frame(struct ethhdr *eth, void *data_end, struct parse_pkt *pkt)
{
	struct _vlan_hdr *vlan_hdr;
	__u16 eth_type;
	__u8 offset;

	offset = sizeof (*eth);

	/* Make sure packet is large enough for parsing eth */
	if ((void *) eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

	/* Handle outer VLAN tag */
	if (eth_type == bpf_htons(ETH_P_8021Q)
	    || eth_type == bpf_htons(ETH_P_8021AD)) {
		vlan_hdr = (void *) eth + offset;
		offset += sizeof (*vlan_hdr);
		if ((void *) eth + offset > data_end)
			return false;

		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	/* Handle inner (Q-in-Q) VLAN tag */
	if (eth_type == bpf_htons(ETH_P_8021Q)
	    || eth_type == bpf_htons(ETH_P_8021AD)) {
		vlan_hdr = (void *) eth + offset;
		offset += sizeof (*vlan_hdr);
		if ((void *) eth + offset > data_end)
			return false;

		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	pkt->l3_proto = bpf_ntohs(eth_type);
	pkt->l3_offset = offset;
	return true;
}

SEC("xdp_fw")
int
xdp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct parse_pkt pkt = { 0 };

	if (!parse_eth_frame(data, data_end, &pkt))
		return XDP_PASS;

	return filter_packet(data, data_end, &pkt);
}

char _license[] SEC("license") = "GPL";
