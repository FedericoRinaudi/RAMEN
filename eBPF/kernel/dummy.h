#ifndef DUMMY_H
#define DUMMY_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "network_utils.h"
#include "checksum.h"
#include "skb_mark.h"
#include "client_config.h"


static __always_inline __s8 is_dummy(struct __sk_buff *skb) {
    __u8 ip_header_len, result;
    result = extract_ip_header_len(skb, &ip_header_len);
    if(result != 1)
        return result;

    struct client_config *config = get_client_config_ingress(skb, ip_header_len);
    if (!config) {
        return -1;
    }
    
    return remove_hmac(skb, skb->len - (HASH_LEN*2), config->dummy_key);
}

static __always_inline __u8 dummy_clone_to_packet_internal(struct __sk_buff *skb) {
    __u16 payload_len = skb_mark_get_len(skb);
    if(payload_len == 0) {
        return TC_ACT_SHOT;
    }
    __u16 old_ip_len, new_ip_len;
    __u8 ip_header_len, tcp_header_len;
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(result != 1)
        return result;

    __u32 new_packet_len = ETH_HLEN + ip_header_len + tcp_header_len + payload_len;
    
    debug_print("[DUMMY] Dummy resized to %u bytes", new_packet_len);
    
    if(bpf_skb_change_tail(skb, new_packet_len, 0) < 0) {
        debug_print("[DUMMY] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }

    for(__u16 i = 0; i < MAX_PKT_SIZE/4; i++) {
        if(i*4 >= payload_len)
            break;
        __u32 random_val = bpf_get_prandom_u32();
        if(bpf_skb_store_bytes(skb, ETH_HLEN + ip_header_len + tcp_header_len + i, &random_val, 4, 0) < 0) {
            debug_print("[DUMMY] ERROR: Failed to store zero byte at offset %u", i);
            return TC_ACT_SHOT;
        }
    }

    struct client_config *config = get_client_config_egress(skb, ip_header_len);
    if (!config) {
        return TC_ACT_SHOT;
    }
    
    __s8 hmac_result = add_hmac(skb, config->dummy_key);
    if (hmac_result < 0) {
        debug_print("[EGRESS] Error in add_hmac, dropping packet");
        return TC_ACT_SHOT;
    }

    new_ip_len = new_packet_len - ETH_HLEN;
    
    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[DUMMY] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }
    
    __u8 flags;
    if (extract_tcp_flags(skb, ip_header_len, &flags) != 1) {
        debug_print("[DUMMY_CLONE] ERROR: Failed to extract TCP flags");
        return TC_ACT_SHOT;
    }
    reset_syn(&flags);
    reset_fin(&flags);
    reset_rst(&flags);
    if (replace_tcp_flags(skb, ip_header_len, flags) != 1) {
        debug_print("[DUMMY_CLONE] ERROR: Failed to replace TCP flags");
        return TC_ACT_SHOT;
    }
        
    return 1;
}

static __always_inline __u8 insert_dummy_packet_internal(struct __sk_buff *skb) {
    __u8 ip_header_len, tcp_header_len, tcp_payload_offset;
    __u8 result = extract_tcp_ip_header_lengths_simple(skb, &ip_header_len, &tcp_header_len);
    if(result != 1)
        return result;
    tcp_payload_offset = sizeof(struct ethhdr)
                             + ip_header_len
                             + tcp_header_len;
    
    if (skb_mark_get_redirect_count(skb) > 8 ) {
        debug_print("[DUMMY] Skip: payload too small or too many redirects (redirects=%u)", skb_mark_get_redirect_count(skb));
        return 1;
    }

    struct client_config *config = get_client_config_egress(skb, ip_header_len);
    if (!config) {
        return -1;
    }
    
    if ((bpf_get_prandom_u32() % 100) > config->dummy_probability) {
        debug_print("[DUMMY] Skip: probability check");
        return 1;
    }
   
    // Calculate dummy packet size (minimum 64 bytes)
    u16 dummy_payload_len = (bpf_get_prandom_u32() % (MAX_PKT_SIZE - tcp_payload_offset - 64)) + 64;
    debug_print("[DUMMY] Inserting dummy packet: dummy_payload=%u bytes", dummy_payload_len);
    skb_mark_increment_redirect_count(skb);
    skb_mark_set_len(skb, dummy_payload_len);
    skb_mark_set_type(skb, SKB_MARK_TYPE_DUMMY_CLONE);
    if (bpf_clone_redirect(skb, skb->ifindex, 0) < 0) {
        debug_print("[DUMMY] ERROR: Failed to clone packet at iteration");
        return TC_ACT_SHOT;
    }
    skb_mark_set_type(skb, SKB_MARK_TYPE_NONE);
    return 1;
}

#endif // DUMMY_H