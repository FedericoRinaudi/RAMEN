#ifndef __FRAGMENTATION_H
#define __FRAGMENTATION_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "network_utils.h"
#include "checksum.h"
#include "skb_mark.h"
#include "client_config.h"

/* Clone fragment to packet - moves fragment data to the beginning of the packet */
static __always_inline __u8 fragmentation_clone_to_packet_internal(struct __sk_buff *skb) {
    /* Extract fragment info from skb->mark */
    __u16 payload_len = skb_mark_get_len(skb);
    if(payload_len == 0) {
        return TC_ACT_SHOT; // Nothing to do
    }

    __u16 old_ip_len, new_ip_len;
    __u8 ip_header_len, tcp_header_len;
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(result != 1)
        return result;

    __u32 new_packet_len = ETH_HLEN + ip_header_len + tcp_header_len + payload_len;
    
    debug_print("[FRAG_CLONE] Clone resized to %u bytes", new_packet_len);
    
    if(bpf_skb_change_tail(skb, new_packet_len, 0) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }

    new_ip_len = new_packet_len - ETH_HLEN;
    
    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }

    __u8 flags;
    if (extract_tcp_flags(skb, ip_header_len, &flags) != 1) {
        debug_print("[FRAG_CLONE] ERROR: Failed to extract TCP flags");
        return TC_ACT_SHOT;
    }
    reset_syn(&flags);
    reset_fin(&flags);
    reset_rst(&flags);
    if (replace_tcp_flags(skb, ip_header_len, flags) != 1) {
        debug_print("[FRAG_CLONE] ERROR: Failed to replace TCP flags");
        return TC_ACT_SHOT;
    }

    /* Clear len and set checksum_flag (packet modified) */
    skb_mark_set_len(skb, 0);
        
    return 1; // Signal to continue with fragmentation
}


static __always_inline __u8 fragment_packet_internal(struct __sk_buff *skb) {
    __u8 ip_header_len, tcp_header_len;
    __u16 old_ip_len, new_ip_len;
    
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(result != 1)
        return result;
    
    __u32 tcp_payload_offset = sizeof(struct ethhdr)
                             + (__u32)ip_header_len
                             + (__u32)tcp_header_len;
    __u16 payload_len = skb->len - tcp_payload_offset;
    
    if(payload_len < 64 || skb_mark_get_redirect_count(skb) > 3) {
        debug_print("[FRAGMENT] Skip: payload too small (%u bytes) or too many redirects (%u)", payload_len, skb_mark_get_redirect_count(skb));
        return 1; // No fragmentation for small payloads or too many redirects
    }

    // Get fragmentation probability for this IP and port
    struct client_config *config = get_client_config_egress(skb, ip_header_len);
    if (!config) {
        return -1;
    }
    
    // Check if we should fragment
    if ((bpf_get_prandom_u32() % 100) > config->frag_probability) {
        debug_print("[FRAGMENT] Skip: probability check (payload=%u bytes)", payload_len);
        return 1; // No fragmentation for small payloads
    }
    
    // fino a qui
    // Calculate new fragment size (minimum 32 bytes)
    u16 frag_payload_len = (bpf_get_prandom_u32() % (payload_len - 32)) + 32; // size of the fragment payload
    payload_len -= frag_payload_len;
    
    debug_print("[FRAGMENT] Fragmenting packet: segment1=%u bytes, segment2=%u bytes", frag_payload_len, payload_len);
    
    // Increment redirect count and store fragment info in mark
    skb_mark_increment_redirect_count(skb);
    skb_mark_set_len(skb, frag_payload_len);
    skb_mark_set_type(skb, SKB_MARK_TYPE_FRAGMENT_CLONE);
    
    if (bpf_clone_redirect(skb, skb->ifindex, 0) < 0) {
        debug_print("[FRAGMENT] ERROR: Failed to clone packet at iteration");
        return TC_ACT_SHOT;
    }

    skb_mark_set_len(skb, 0);  // Clear frag payload, keep other fields
    debug_print("[FRAGMENT] Packet resized to %u bytes", tcp_payload_offset + payload_len);

    __u16 read_start_offset = tcp_payload_offset + frag_payload_len;
    new_ip_len = old_ip_len - frag_payload_len;
    __u16 bytes_left = payload_len;
    __u8 buffer[FRAG_BUFF_MAX_SIZE];
    
    for(__u8 i = 0; i < (MAX_PKT_SIZE / FRAG_BUFF_MAX_SIZE) + 1; i++) {
        __u32 chunk_size = bytes_left;
        if(chunk_size > FRAG_BUFF_MAX_SIZE)
            chunk_size = FRAG_BUFF_MAX_SIZE;

        if(chunk_size == 0)
            break;

        if(bpf_skb_load_bytes(skb, read_start_offset + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to load bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }
        
        if(bpf_skb_store_bytes(skb, tcp_payload_offset + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size, 0) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to store bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }

        bytes_left -= chunk_size;
    }
    
    
    if (bpf_skb_change_tail(skb, tcp_payload_offset + payload_len, 0) < 0) {
        debug_print("[FRAGMENT] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }

    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }

    __u32 old_seq;
    result = extract_seq_num(skb, ip_header_len, &old_seq);
    __u32 new_seq = old_seq + frag_payload_len;

    return replace_seq_num(skb, ip_header_len, new_seq);
}


#endif // __FRAGMENTATION_H
