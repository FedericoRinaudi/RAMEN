#ifndef __CHECKSUM_H
#define __CHECKSUM_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "network_utils.h"

static __always_inline __s8 update_ip_len_and_csum(struct __sk_buff *skb, __u8 ip_header_len, __u16 old_ip_len, __u16 new_ip_len) {
    __be16 new_ip_len_be = bpf_htons(new_ip_len);
    __be16 old_ip_len_be = bpf_htons(old_ip_len); 
    
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len),
                            &new_ip_len_be, sizeof(new_ip_len_be), 0) < 0)
        return -1;

    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                            old_ip_len_be, new_ip_len_be,
                            sizeof(__u16)) < 0)
        return -1;
    
    return 0;
}

static __always_inline __u16 fold_csum(__u32 sum)
{
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)sum;
}

static __always_inline __s8 recompute_tcp_checksum_internal(struct __sk_buff *skb) {

    debug_print("[RECOMPUTE_CSUM] START: len=%u", skb->len);

    __u8 ip_header_len, tcp_header_len;
    __u16 ip_total_len_old;
    __u8 extract_result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &ip_total_len_old);
    if(extract_result != 1)
        return TC_ACT_SHOT;
    __wsum sum = 0;
    __u8 buffer[FRAG_BUFF_MAX_SIZE];
    __u8 tcp_payload_offset = ETH_HLEN + ip_header_len + tcp_header_len;
    __u16 tcp_payload_len = skb->len - tcp_payload_offset; 
    __u32 bytes_remaining = tcp_payload_len;
    __u16 ip_total_len_new = skb->len - ETH_HLEN;

    if (update_ip_len_and_csum(skb, ip_header_len, ip_total_len_old, ip_total_len_new) < 0)
        return -1;


   __u8 chunk;
    for (chunk = 0; chunk < (MAX_PKT_SIZE / FRAG_BUFF_MAX_SIZE) + 1; chunk++) {
  
        if(bytes_remaining < FRAG_BUFF_MAX_SIZE) {
            break;
        }
        
        if (bpf_skb_load_bytes(skb, tcp_payload_offset + (chunk * FRAG_BUFF_MAX_SIZE), buffer, FRAG_BUFF_MAX_SIZE) < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load bytes for chunk %u", chunk);
            return TC_ACT_SHOT;
        }
        
        __s64 csum_result = bpf_csum_diff(NULL, 0, (__be32*)buffer, FRAG_BUFF_MAX_SIZE, sum);
        if (csum_result < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for chunk %u", chunk);
            return TC_ACT_SHOT;
        }

        sum = (__wsum)csum_result;
        bytes_remaining -= FRAG_BUFF_MAX_SIZE;

    }
    if(bytes_remaining > 0) {
        __builtin_memset(buffer, 0, FRAG_BUFF_MAX_SIZE);
        /* Help the verifier understand the bounds */
        bytes_remaining &= 0xFFF;
        if(bytes_remaining > FRAG_BUFF_MAX_SIZE || bytes_remaining == 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Invalid bytes_remaining=%u after padding", bytes_remaining);
            return TC_ACT_SHOT;
        }
        
        if (bpf_skb_load_bytes(skb, tcp_payload_offset + (chunk * FRAG_BUFF_MAX_SIZE), buffer, bytes_remaining) < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load remaining bytes %d", bytes_remaining);
            return TC_ACT_SHOT;
        }

        bytes_remaining += (4 - (bytes_remaining % 4)) % 4;
        
        __s64 csum_result = bpf_csum_diff(NULL, 0, (__be32*)buffer, bytes_remaining, sum);
        if (csum_result < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for remaining bytes %d", bytes_remaining);
            return TC_ACT_SHOT;
        }
        sum = (__wsum)csum_result;

    }


    __u8 tcp_header_off = sizeof(struct ethhdr) + ip_header_len;

    __u16 zero = 0;
    if(bpf_skb_store_bytes(skb, tcp_header_off + offsetof(struct tcphdr, check), &zero, sizeof(zero), 0) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to zero checksum field");
        return TC_ACT_SHOT;
    }

    extract_result = extract_tcp_ip_header_lengths_simple(skb, &ip_header_len, &tcp_header_len);
    if(extract_result != 1)
        return extract_result;
    if(tcp_header_len < 20 || tcp_header_len > 60) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Invalid TCP header length: %u", tcp_header_len);
        return TC_ACT_SHOT;
    }
    
    if (bpf_skb_load_bytes(skb, tcp_header_off, buffer, tcp_header_len) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load TCP header");
        return TC_ACT_SHOT;
    }

    __s64 t = bpf_csum_diff(NULL, 0, (__be32 *)buffer, tcp_header_len, sum);
    if (t < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for TCP header");
        return TC_ACT_SHOT;
    }
    sum = (__wsum)t;
    
    /* add pseudo-header contribution to checksum */
    if (bpf_skb_load_bytes(skb,
            sizeof(struct ethhdr) + offsetof(struct iphdr, saddr),
            buffer, 8) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load IP addresses");
        return -1;
    }
    
    buffer[8] = 0;
    buffer[9] = IPPROTO_TCP;
    /* Pseudo-header needs TOTAL TCP length (header + payload) */
    __u16 tcp_total_len = tcp_header_len + tcp_payload_len;
    __be16 tcp_total_len_be = bpf_htons(tcp_total_len);
    __builtin_memcpy(&buffer[10], &tcp_total_len_be, 2);    
    t = bpf_csum_diff(NULL, 0, (__be32 *)buffer, 12, sum);
    if (t < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for pseudo-header");
        return TC_ACT_SHOT;
    }
    sum = (__wsum)t;

    __u16 folded = fold_csum((__u32)sum);
    __be16 check = (__be16)~folded;
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                        &check, sizeof(check), 0) < 0){
        return TC_ACT_SHOT;
    }

    __u16 checksum;
    extract_result = bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &checksum, sizeof(checksum));
    debug_print("[RECOMPUTE_CSUM] END: len=%u, new_tcp_checksum=0x%04x", skb->len, checksum);

    return TC_ACT_OK;
}

#endif // __CHECKSUM_H
