// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "skb_mark.h"
#include "blake2s.h"
#include "network_utils.h"
#include "checksum.h"
#include "hmac.h"
#include "client_config.h"
#include "padding.h"
#include "fragmentation.h"
#include "seq_num_translation.h"
#include "dummy.h"


enum tail_call_index_eg {
    TAIL_CALL_FRAG_CLONE,
    TAIL_CALL_TCP_DUMMY_CLONE,
    TAIL_CALL_TCP_STATE_INIT_EG,
    TAIL_CALL_FRAGMENT_PACKET,
    TAIL_CALL_INSERT_DUMMY,
    TAIL_CALL_ADD_PADDING,
    TAIL_CALL_MANAGE_TCP_STATE_EG,
    TAIL_CALL_RECOMPUTE_CHECKSUM_EG,
    TAIL_CALL_EGRESS_NUM_ENTRIES
};

enum tail_call_index_in {
    TAIL_CALL_TCP_STATE_INIT_IN,
    TAIL_CALL_DISCARD_DUMMY,
    TAIL_CALL_REMOVE_PADDING,
    TAIL_CALL_MANAGE_TCP_STATE_IN,
    TAIL_CALL_RECOMPUTE_CHECKSUM_IN,
    TAIL_CALL_INGRESS_NUM_ENTRIES
};

// Forward declarations for tail call map
SEC("classifier") int fragmentation_clone_to_packet(struct __sk_buff *skb);
SEC("classifier") int dummy_clone_to_packet(struct __sk_buff *skb);
SEC("classifier") int tcp_state_init_eg(struct __sk_buff *skb);
SEC("classifier") int tcp_state_init_in(struct __sk_buff *skb);
SEC("classifier") int fragment_packet(struct __sk_buff *skb);
SEC("classifier") int insert_dummy_packet(struct __sk_buff *skb);
SEC("classifier") int remove_dummy_packet(struct __sk_buff *skb);
SEC("classifier") int remove_padding(struct __sk_buff *skb);
SEC("classifier") int add_padding(struct __sk_buff *skb);
SEC("classifier") int manage_tcp_state_translations_eg(struct __sk_buff *skb);
SEC("classifier") int manage_tcp_state_translations_in(struct __sk_buff *skb);
SEC("classifier") int recompute_tcp_checksum(struct __sk_buff *skb);

// Tail call program array map
struct {
     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
     __uint(key_size, sizeof(u32));
     __uint(max_entries, TAIL_CALL_EGRESS_NUM_ENTRIES);
     __array(values, u32 (void *));
 } progs_eg SEC(".maps") = {
     .values = {
         [TAIL_CALL_FRAG_CLONE] = (void *)&fragmentation_clone_to_packet,
         [TAIL_CALL_TCP_DUMMY_CLONE] = (void *)&dummy_clone_to_packet,
         [TAIL_CALL_TCP_STATE_INIT_EG] = (void *)&tcp_state_init_eg,
         [TAIL_CALL_FRAGMENT_PACKET] = (void *)&fragment_packet,
         [TAIL_CALL_INSERT_DUMMY] = (void *)&insert_dummy_packet,
         [TAIL_CALL_ADD_PADDING] = (void *)&add_padding,
         [TAIL_CALL_MANAGE_TCP_STATE_EG] = (void *)&manage_tcp_state_translations_eg,
         [TAIL_CALL_RECOMPUTE_CHECKSUM_EG] = (void *)&recompute_tcp_checksum
    },
 };


// Tail call program array map
struct {
     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
     __uint(key_size, sizeof(u32));
     __uint(max_entries, TAIL_CALL_INGRESS_NUM_ENTRIES);
     __array(values, u32 (void *));
 } progs_in SEC(".maps") = {
     .values = {
         [TAIL_CALL_TCP_STATE_INIT_IN] = (void *)&tcp_state_init_in,
         [TAIL_CALL_DISCARD_DUMMY] = (void *)&remove_dummy_packet,
         [TAIL_CALL_REMOVE_PADDING] = (void *)&remove_padding,
         [TAIL_CALL_MANAGE_TCP_STATE_IN] = (void *)&manage_tcp_state_translations_in,
         [TAIL_CALL_RECOMPUTE_CHECKSUM_IN] = (void *)&recompute_tcp_checksum
    },
 };

/* eBPF program sections using modular functions */

SEC("classifier")
int fragmentation_clone_to_packet(struct __sk_buff *skb) {
    __u8 result = fragmentation_clone_to_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] FRAG_CLONE: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_TCP_STATE_INIT_EG);
    return TC_ACT_OK;
}

SEC("classifier")
int dummy_clone_to_packet(struct __sk_buff *skb) {
    __u8 result = dummy_clone_to_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] DUMMY_CLONE: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_MANAGE_TCP_STATE_EG);
    return TC_ACT_OK;
}


SEC("classifier")
int tcp_state_init_eg(struct __sk_buff *skb){
    __u8 result = seq_num_translation_init_egress(skb);
    if(result != 1) {
        debug_print("[EGRESS-EXIT] TCP_STATE_INIT: result=%d", result);
        return result;
    }
    __u8 ip_header_len, tcp_header_len;
    __u8 extract_result = extract_tcp_ip_header_lengths_simple(skb, &ip_header_len, &tcp_header_len);
    if(extract_result != 1)
        return extract_result;
    __u16 tcp_payload_len = skb->len - (ETH_HLEN + ip_header_len + tcp_header_len);
    if(tcp_payload_len < 32) {
        bpf_tail_call(skb, &progs_eg, TAIL_CALL_MANAGE_TCP_STATE_EG);
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_FRAGMENT_PACKET);
    return TC_ACT_OK;
}

SEC("classifier") int tcp_state_init_in(struct __sk_buff *skb){
    __u8 result = seq_num_translation_init_ingress(skb);
    if (result != 1) {
        debug_print("[INGRESS-EXIT] seq_num_translation_init_ingress: result=%d", result);
        return result;
    }
    __u8 ip_header_len, tcp_header_len;
    __u8 extract_result = extract_tcp_ip_header_lengths_simple(skb, &ip_header_len, &tcp_header_len);
    if(extract_result != 1)
        return extract_result;
    __u16 tcp_payload_len = skb->len - (ETH_HLEN + ip_header_len + tcp_header_len);
    if(tcp_payload_len < 64) {
        bpf_tail_call(skb, &progs_in, TAIL_CALL_MANAGE_TCP_STATE_IN);
    }
    bpf_tail_call(skb, &progs_in, TAIL_CALL_DISCARD_DUMMY);
    return TC_ACT_OK;
}

SEC("classifier")
int fragment_packet(struct __sk_buff *skb) {
    __u8 result = fragment_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] FRAGMENT_PACKET: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_INSERT_DUMMY);
    return TC_ACT_OK;
}

SEC("classifier")
int insert_dummy_packet(struct __sk_buff *skb) {
    __u8 result = insert_dummy_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] INSERT_DUMMY_PACKET: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_ADD_PADDING);
    return TC_ACT_OK;
}

SEC("classifier")
int remove_dummy_packet(struct __sk_buff *skb) {
    switch(is_dummy(skb)){
        case -1:
            debug_print("[INGRESS-EXIT] is_dummy: error");
            return TC_ACT_SHOT;
        case 0:
            bpf_tail_call(skb, &progs_in, TAIL_CALL_REMOVE_PADDING);
        case 1:
            skb_mark_set_type(skb, SKB_MARK_TYPE_DUMMY);
            __u8 result = manage_seq_num_ingress(skb); // Update seq num mappings for dummy packets
            if (result != 1) {
                debug_print("[INGRESS-EXIT] manage_seq_num_ingress (dummy): result=%d", result);
                return result;
            }
            debug_print("[INGRESS] Detected dummy packet, dropping");
            return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

SEC("classifier")
int add_padding(struct __sk_buff *skb) {
    __u8 result = add_padding_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] ADD_PADDING: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_MANAGE_TCP_STATE_EG);
    return TC_ACT_OK;
}

SEC("classifier")
int remove_padding(struct __sk_buff *skb){
    if (remove_padding_internal(skb) != 1) {
        debug_print("[INGRESS-EXIT] remove_padding_internal failed: TC_ACT_SHOT");
        return TC_ACT_SHOT;
    }
    bpf_tail_call(skb, &progs_in, TAIL_CALL_MANAGE_TCP_STATE_IN);
    return TC_ACT_OK;
}

SEC("classifier")
int manage_tcp_state_translations_eg(struct __sk_buff *skb){

    __u8 result = manage_seq_num_egress(skb);
    if(result != 1) {
        debug_print("[EGRESS-EXIT] MANAGE_TCP_STATE: result=%d", result);
        return result;
    }
    
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_RECOMPUTE_CHECKSUM_EG);
    
    return TC_ACT_OK;
}


SEC("classifier") int manage_tcp_state_translations_in(struct __sk_buff *skb){
    __u8 result = manage_seq_num_ingress(skb);
    if (result != 1) {
        debug_print("[INGRESS-EXIT] manage_seq_num_ingress: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_in, TAIL_CALL_RECOMPUTE_CHECKSUM_IN);
    
    return TC_ACT_OK;
}

SEC("classifier")
int recompute_tcp_checksum(struct __sk_buff *skb) {
    __u8 result = recompute_tcp_checksum_internal(skb);
    debug_print("END: len=%u", skb->len);
    return result;
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    debug_print("[EGRESS] START: len=%u", skb->len);
    
    if (should_skip_packet(skb)) {
        return TC_ACT_OK;
    }
    
    __u8 ip_header_len;
    if(extract_ip_header_len(skb, &ip_header_len) != 1) {
        return TC_ACT_OK;
    }
    
    struct client_config *config = get_client_config_egress(skb, ip_header_len);
    if (!config) {
        debug_print("[EGRESS] No config for destination IP, passing through");
        return TC_ACT_OK;
    }

    __u16 csum;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &csum, sizeof(csum)) < 0)
        return TC_ACT_SHOT;

    
    debug_print("[EGRESS] Original TCP checksum: 0x%04x", csum);
    
    __u8 result = skb_mark_get_type(skb);
    
    switch(result) {
        case SKB_MARK_TYPE_FRAGMENT_CLONE:
            bpf_tail_call(skb, &progs_eg, TAIL_CALL_FRAG_CLONE);
            break;
        case SKB_MARK_TYPE_DUMMY_CLONE:
            bpf_tail_call(skb, &progs_eg, TAIL_CALL_TCP_DUMMY_CLONE);
            break;
        default:
            bpf_tail_call(skb, &progs_eg, TAIL_CALL_TCP_STATE_INIT_EG);
    }

    return TC_ACT_OK;
}

SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    __u8 ip_header_len;
    
    debug_print("[INGRESS] START: len=%u", skb->len);
    
    if (should_skip_packet(skb)) {
        return TC_ACT_OK;
    }

    if(extract_ip_header_len(skb, &ip_header_len) != 1) {
        return TC_ACT_OK;
    }
    
    struct client_config *config = get_client_config_ingress(skb, ip_header_len);
    if (!config) {
        debug_print("[INGRESS-EXIT] No config for source IP, passing through");
        return TC_ACT_OK;
    }

    bpf_tail_call(skb, &progs_in, TAIL_CALL_TCP_STATE_INIT_IN);
    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "GPL";
