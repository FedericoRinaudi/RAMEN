#ifndef __NETWORK_UTILS_H
#define __NETWORK_UTILS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"


#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_RST 0x04

struct flow_info {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

static __always_inline void reverse_flow(struct flow_info *flow) {
    __u32 tmp;
    tmp = flow->saddr;
    flow->saddr = flow->daddr;
    flow->daddr = tmp;
    tmp = (__u32)flow->sport;
    flow->sport = flow->dport;
    flow->dport = (__u16)tmp;
}

static __always_inline __u8 should_skip_packet(struct __sk_buff *skb) {
    // GSO check: if gso_size > 0, packet needs segmentation
    if (skb->gso_size > 0) {
        debug_print("[SKIP] GSO packet: len=%u, gso_segs=%u, gso_size=%u", skb->len, skb->gso_segs, skb->gso_size);
        return 1;
    }
    
    // Oversized packet check (may be GRO aggregated)
    if (skb->len > MAX_PKT_SIZE) {
        debug_print("[SKIP] Oversized: len=%u > %u", skb->len, MAX_PKT_SIZE);
        return 1;
    }
    
    return 0;
}

static __always_inline __u8 extract_ip_header_len(struct __sk_buff *skb, __u8 *ip_header_len) {
    if(skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), ip_header_len, sizeof(__u8)) < 0)
        return TC_ACT_SHOT;
    *ip_header_len = (*ip_header_len & 0x0F) * 4;
    return 1;
}

static __always_inline __u8 extract_tcp_ip_header_lengths_simple(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_header_len) {
    __u8 l4_protocol, result;
    result = extract_ip_header_len(skb, ip_header_len);
    if(result!=1)
        return result;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol), &l4_protocol, 1) < 0)
        return TC_ACT_SHOT;
    if (l4_protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + *ip_header_len + 12, tcp_header_len, 1) < 0)
        return TC_ACT_SHOT;
    *tcp_header_len = (*tcp_header_len >> 4) * 4;
    return 1;
}

static __always_inline __u8 extract_tcp_ip_header_lengths(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_header_len, __u16 *ip_tot_len) {
    __u8 result = extract_tcp_ip_header_lengths_simple(skb, ip_header_len, tcp_header_len);
    if(result != 1)
        return result;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), ip_tot_len, sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    *ip_tot_len = bpf_ntohs(*ip_tot_len);
    return 1;
}

static __always_inline __u8 extract_tcp_flags(struct __sk_buff *skb, __u8 ip_hdr_len, __u8 *tcp_flags) {
    // Load TCP flags (at byte offset 13 of the TCP header)
    __u8 flags;
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + 13, &flags, sizeof(__u8)) < 0)
        return -1;
    
    *tcp_flags = flags;

    return 1;
}

static __always_inline int is_syn(__u8 flags) {
    return (flags & TCP_FLAG_SYN);
}

static __always_inline int is_fin(__u8 flags) {
    return (flags & TCP_FLAG_FIN);
}


static __always_inline int is_rst(__u8 flags) {
    return (flags & TCP_FLAG_RST);
}

static __always_inline int has_ack_flag(__u8 flags) {
    return (flags & TCP_FLAG_ACK);
}

static __always_inline __u8 replace_tcp_flags(struct __sk_buff *skb, __u8 ip_hdr_len, __u8 new_flags) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    
    __u32 flags_offset = tcp_offset + 13; // Offset of flags byte in TCP header
    if (bpf_skb_store_bytes(skb, flags_offset, &new_flags, sizeof(new_flags), 0) < 0)
        return -1;
    
    return 1;
}

static __always_inline void reset_syn(__u8 *flags) {
    *flags &= ~TCP_FLAG_SYN;
}

static __always_inline void reset_fin(__u8 *flags) {
    *flags &= ~TCP_FLAG_FIN;
}

static __always_inline void reset_rst(__u8 *flags) {
    *flags &= ~TCP_FLAG_RST;
}

static __always_inline __u8 extract_seq_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 *seq) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, seq), seq, sizeof(*seq)) < 0)
        return TC_ACT_SHOT;

    *seq = bpf_ntohl(*seq);

    return 1;
}

static __always_inline __u32 extract_ack_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 *ack_seq) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, ack_seq), ack_seq, sizeof(*ack_seq)) < 0)
        return TC_ACT_SHOT;

    *ack_seq = bpf_ntohl(*ack_seq);
    return 1;
}

static __always_inline int replace_seq_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 new_seq) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    
    __u32 new_seq_net = bpf_htonl(new_seq);
    __u32 seq_offset = tcp_offset + offsetof(struct tcphdr, seq);
    if (bpf_skb_store_bytes(skb, seq_offset, &new_seq_net, sizeof(new_seq_net), 0) < 0)
        return TC_ACT_SHOT;
    
    return 1;
}

static __always_inline int replace_ack_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 new_ack) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    
    __u32 new_ack_net = bpf_htonl(new_ack);
    __u32 ack_offset = tcp_offset + offsetof(struct tcphdr, ack_seq);
    if (bpf_skb_store_bytes(skb, ack_offset, &new_ack_net, sizeof(new_ack_net), 0) < 0)
        return -1;
    
    return 1;
}



static __always_inline __s8 extract_src_ip(struct __sk_buff *skb, __u32 *src_ip) {
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), src_ip, sizeof(__u32)) < 0) {
        debug_print("[NETWORK] Failed to extract source IP");
        return -1;
    }
    *src_ip = bpf_ntohl(*src_ip);
    return 1;
}

static __always_inline __s8 extract_dst_ip(struct __sk_buff *skb, __u32 *dst_ip) {
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), dst_ip, sizeof(__u32)) < 0) {
        debug_print("[NETWORK] Failed to extract destination IP");
        return -1;
    }
    *dst_ip = bpf_ntohl(*dst_ip);
    return 1;
}



static __always_inline __s8 extract_src_port(struct __sk_buff *skb, __u8 ip_hdr_len, __u16 *src_port) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, source), src_port, sizeof(__u16)) < 0) {
        debug_print("[NETWORK] Failed to extract source port");
        return -1;
    }
    *src_port = bpf_ntohs(*src_port);
    return 1;
}

static __always_inline __s8 extract_dst_port(struct __sk_buff *skb, __u8 ip_hdr_len, __u16 *dst_port) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, dest), dst_port, sizeof(__u16)) < 0) {
        debug_print("[NETWORK] Failed to extract destination port");
        return -1;
    }
    *dst_port = bpf_ntohs(*dst_port);
    return 1;
}


static __always_inline __u8 extract_flow_info(struct __sk_buff *skb, __u8 ip_hdr_len, struct flow_info *flow) {
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &(flow->saddr), sizeof(__u32)) < 0)
        return TC_ACT_SHOT;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &(flow->daddr), sizeof(__u32)) < 0)
        return TC_ACT_SHOT;
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;

    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, source), &(flow->sport), sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, dest), &(flow->dport), sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    return 1;
}

static __always_inline __s8 extract_server_port_ingress(struct __sk_buff *skb, __u8 ip_hdr_len, __u16 *server_port) {
    #if IS_SERVER == 1
    return extract_dst_port(skb, ip_hdr_len, server_port);
    #else
    return extract_src_port(skb, ip_hdr_len, server_port);
    #endif
}

static __always_inline __s8 extract_server_port_egress(struct __sk_buff *skb, __u8 ip_hdr_len, __u16 *server_port) {
    #if IS_SERVER == 1
    return extract_src_port(skb, ip_hdr_len, server_port);
    #else
    return extract_dst_port(skb, ip_hdr_len, server_port);
    #endif
}

#endif // __NETWORK_UTILS_H
