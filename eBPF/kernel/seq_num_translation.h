// SPDX-License-Identifier: GPL-2.0
#ifndef __SEQ_NUM_TRANSLATION_H
#define __SEQ_NUM_TRANSLATION_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "network_utils.h"
#include "checksum.h"
#include "skb_mark.h"

/* Maximum   for flow tracking and seq_num translations */
#define MAX_FLOWS 100000



struct map_key {
    struct flow_info flow;
    __u32 seq;
};

struct map_value {
    __u32 translated_seq;
    __u32 prev_seq;
    __u64 timestamp_ns;
    __u8 is_fin_ack;  // 1 se questo ACK conferma un FIN, 0 altrimenti
};

/* Macro per definire mappe BPF hash */
#define DEFINE_TRANSLATION_HASH_MAP(map_name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(key_size, sizeof(struct map_key)); \
        __uint(value_size, sizeof(struct map_value)); \
        __uint(max_entries, MAX_FLOWS); \
    } map_name SEC(".maps");

/* Macro per definire code BPF per cleanup */
#define DEFINE_CLEANUP_QUEUE(map_name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_QUEUE); \
        __uint(value_size, sizeof(struct map_key)); \
        __uint(max_entries, 4096); \
    } map_name SEC(".maps");

/* Definizione delle mappe hash usando la macro */
DEFINE_TRANSLATION_HASH_MAP(host_to_network_seq_map);
DEFINE_TRANSLATION_HASH_MAP(network_to_host_seq_map);
DEFINE_TRANSLATION_HASH_MAP(host_to_network_ack_map);
DEFINE_TRANSLATION_HASH_MAP(network_to_host_ack_map);

/* Code per segnalare i flussi completati (FIN) da pulire */
DEFINE_CLEANUP_QUEUE(completed_flow_ingress);
DEFINE_CLEANUP_QUEUE(completed_flow_egress);




/* ============================================================================
 * Sequence Number Translation Functions
 * ============================================================================ */

/**
 * Offload cleanup to userspace by pushing a key to the cleanup queue
 */
static __always_inline void offload_cleanup_to_user_space(void* queue_map, struct flow_info *flow, __u32 seq_num) {
    struct map_key key;
    key.flow = *flow;
    key.seq = seq_num;
    
    // Push the key to the queue (BPF_EXIST: only if there's space)
    if (bpf_map_push_elem(queue_map, &key, BPF_EXIST) < 0) {
        debug_print("[SEQ_TRANS] Failed to push key to cleanup queue (queue full?)");
    }
}

/**
 * Initialize flow translation maps for SYN packet
 * Both original and translated seq_num are the same at handshake
 */
static __always_inline __u8 init_translation_map(void* map, struct flow_info *flow, __u32 seq_num) {
    struct map_key key;
    key.flow = *flow;
    key.seq = seq_num;

    struct map_value value;
    value.translated_seq = seq_num;
    value.prev_seq = 0;
    value.timestamp_ns = bpf_ktime_get_ns();
    value.is_fin_ack = 0;
    debug_print("[SEQ_TRANS] Initializing translation map: %u -> %u", seq_num, value.translated_seq);
    if (bpf_map_update_elem(map, &key, &value, BPF_ANY) < 0) {
        debug_print("[SEQ_TRANS] Failed to initialize translation map");
        return TC_ACT_SHOT;
    }

    return 1;
}

/**
 * Lookup seq_num translation for a flow
 * Returns pointer to seq_translation struct, or NULL if not found
 */
static __always_inline struct map_value * lookup_translation_map(void *map, struct flow_info *flow, __u32 seq_num) {
    struct map_key key;
    key.flow = *flow;
    key.seq = seq_num;
    return bpf_map_lookup_elem(map, &key);
}

static __always_inline __u8 seq_num_map_translation_init(struct __sk_buff *skb, void* seq_num_map, void* ack_map, __u64 redirect_flags) { // da chiamare sia in ingress che in egress
    __u8 flag, ip_header_len;
    __u8 result = extract_ip_header_len(skb, &ip_header_len);
    __u32 seq_num;
    struct flow_info flow;
    if(result!=1){
        debug_print("[TCP_STATE_INIT-DROP] extract_ip_header_len failed: result=%d", result);
        return result;
    }
    result = extract_tcp_flags(skb, ip_header_len, &flag);
    if (result != 1) {
        debug_print("[TCP_STATE_INIT-EXIT] extract_tcp_flags failed: result=%d, ip_hdr_len=%u", result, ip_header_len);
        return result;
    }
    result = extract_flow_info(skb, ip_header_len, &flow);
    if (result != 1) {
        debug_print("[TCP_STATE_INIT-EXIT] extract_flow_info failed: result=%d, ip_hdr_len=%u", result, ip_header_len);
        return result;
    }
    result = extract_seq_num(skb, ip_header_len, &seq_num);
    if (result != 1) {
        debug_print("[TCP_STATE_INIT-EXIT] extract_seq_num failed: result=%d, ip_hdr_len=%u", result, ip_header_len);
        return result;
    }
    if(is_syn(flag)){
        seq_num += 1;
        result = init_translation_map(seq_num_map, &flow, seq_num);
        if(result != 1) {
            debug_print("[TCP_STATE_INIT-EXIT] init_translation_map (seq_num) failed: result=%d, seq=%u, flags=%u", result, seq_num, flag);
            return result;
        }
        reverse_flow(&flow);
        result = init_translation_map(ack_map, &flow, seq_num);
        if(result != 1) {
            debug_print("[TCP_STATE_INIT-EXIT] init_translation_map (ack) failed: result=%d, seq=%u, flags=%u", result, seq_num, flag);
            return result;
        }
        return TC_ACT_OK;
    }
    if(lookup_translation_map(seq_num_map, &flow, seq_num)!=NULL){
        return 1;
    }
    debug_print("[TCP_STATE_INIT-EXIT] No SYN and no translation found: seq=%u, flags=%u", seq_num, flag);
    
    return TC_ACT_SHOT;
}

static __always_inline __u8 translate_seq_num(struct __sk_buff *skb, void* seq_num_map, __u32 input_seq_num, struct flow_info *flow, __u32 *output_seq_num, __u8 ip_header_len) {
    struct map_value *translation = lookup_translation_map(seq_num_map, flow, input_seq_num);
    if (!translation) {
        //bpf_printk("[SEQ_TRANS] No translation found for seq_num=%u", input_seq_num);
        debug_print("[SEQ_TRANS] No translation found for seq_num=%u", input_seq_num);
        return TC_ACT_SHOT;
    }

    *output_seq_num = translation->translated_seq;
    debug_print("[SEQ_TRANS] Translating seq_num: %u -> %u", input_seq_num, *output_seq_num);

    int result = replace_seq_num(skb, ip_header_len, *output_seq_num);
    if (result != 1) {
        debug_print("[SEQ_TRANS] Failed to replace seq_num");
        return result;
    }

    return 1;
}

static __always_inline __u8 insert_new_seq(void* seq_num_map, void* ack_map_reverse, struct flow_info *flow, __u32 input_seq_num, __u32 translated_seq, __u16 input_payload_len, __u16 translated_payload_len, __u8 is_fin) {
    struct map_key key;
    key.flow = *flow;
    key.seq = input_seq_num + input_payload_len;

    // Controlla se esiste già un'entry per questa chiave (seq_num)
    // Se sì, preserva la catena usando il prev_seq dell'entry esistente
    struct map_value *existing_seq = bpf_map_lookup_elem(seq_num_map, &key);
    
    struct map_value value;
    value.translated_seq = translated_seq + translated_payload_len;
    value.timestamp_ns = bpf_ktime_get_ns();
    value.is_fin_ack = 0;
    
    if (existing_seq != NULL) {
        // Preserva la catena: il prev della nuova entry diventa il prev della vecchia
        value.prev_seq = existing_seq->prev_seq;
    } else {
        // Nuova entry: prev_seq è il seq corrente
        value.prev_seq = input_seq_num;
    }

    if (bpf_map_update_elem(seq_num_map, &key, &value, BPF_ANY) < 0) {
        debug_print("[SEQ_TRANS] Failed to insert new seq_num");
        return TC_ACT_SHOT;
    }
    debug_print("[SEQ_TRANS] Inserted new seq: key=%u -> translated=%u (input_len=%u, trans_len=%u)", key.seq, value.translated_seq, input_payload_len, translated_payload_len);

    reverse_flow(&(key.flow));
    key.seq = translated_seq + translated_payload_len;

    value.translated_seq = input_seq_num + input_payload_len;
    value.timestamp_ns = bpf_ktime_get_ns();
    value.is_fin_ack = is_fin;  // Marca l'ACK come FIN-ACK se questo è un FIN
    value.prev_seq = 0;  // Non serve più la chain per gli ACK

    if (bpf_map_update_elem(ack_map_reverse, &key, &value, BPF_ANY) < 0) {
        debug_print("[SEQ_TRANS] Failed to insert new ack_num");
        return TC_ACT_SHOT;
    }
    debug_print("[SEQ_TRANS] Inserted new ack: key=%u -> translated=%u (is_fin=%u)", key.seq, value.translated_seq, is_fin);

    return 1;
}

static __always_inline __u8 manage_ack(struct __sk_buff *skb, void* ack_map, void* fin_cleanup_queue, __u32 input_ack_num, struct flow_info flow, __u8 ip_header_len) {
    struct map_value *translation = lookup_translation_map(ack_map, &flow, input_ack_num);
    if (!translation) {
        debug_print("[SEQ_TRANS] No translation found for ack_num=%u", input_ack_num);
        return TC_ACT_SHOT;
    }

    // Se questo ACK conferma un FIN, segnala per pulizia di tutte le mappe
    // Inseriamo il translated_seq con il flow invertito
    if (translation->is_fin_ack == 1) {
        struct flow_info reversed_flow = flow;
        reverse_flow(&reversed_flow);
        offload_cleanup_to_user_space(fin_cleanup_queue, &reversed_flow, translation->translated_seq);
    }

    debug_print("[SEQ_TRANS] Translating ack_num: %u -> %u", input_ack_num, translation->translated_seq);
   // Replace ack_num in packet
    if (replace_ack_num(skb, ip_header_len, translation->translated_seq) < 0) {
        debug_print("[SEQ_TRANS] Failed to replace ack_num");
        return TC_ACT_SHOT;
    }

    return 1;
}

static __always_inline __u8 manage_seq_and_ack(struct __sk_buff *skb, void* seq_num_map, void* ack_map, void* ack_map_reverse, void* fin_cleanup_queue) {

    __u8 ip_header_len, tcp_header_len;
    struct flow_info flow;
    __u16 input_ip_len, input_payload_len, translated_payload_len;
    __u32 input_seq_num, translated_seq_num;
    __u8 tcp_flags;
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &input_ip_len);
    if(result != 1)
        return result;
    result = extract_flow_info(skb, ip_header_len, &flow);
    if(result != 1)
        return result;
    //bpf_printk("IP header length: %u, TCP header length: %u, IP total length: %u", ip_header_len, tcp_header_len, input_ip_len);
    result = extract_seq_num(skb, ip_header_len, &input_seq_num);
    if(result != 1)
        return result;
    result = extract_tcp_flags(skb, ip_header_len, &tcp_flags);
    if(result != 1)
        return result;
    
    input_payload_len = input_ip_len - (ip_header_len + tcp_header_len);
    translated_payload_len = skb->len - (ip_header_len + tcp_header_len + sizeof(struct ethhdr));
    
    // Translate seq_num
    result = translate_seq_num(skb, seq_num_map, input_seq_num, &flow, &translated_seq_num, ip_header_len);
    if (result != 1) {
        return result;
    }
    if(is_fin(tcp_flags)){
        translated_payload_len +=1;
        input_payload_len +=1;
    }

    __u8 mark = skb_mark_get_type(skb);

    if(mark == SKB_MARK_TYPE_DUMMY){
        translated_payload_len = 0;
    } else if (mark == SKB_MARK_TYPE_DUMMY_CLONE){
        input_payload_len = 0;
    }

    __u8 has_fin = is_fin(tcp_flags) ? 1 : 0;
    
    result = insert_new_seq(seq_num_map, ack_map_reverse, &flow, input_seq_num, translated_seq_num, input_payload_len, translated_payload_len, has_fin);
    if (result != 1) {
        return result;
    }
    
    
    if(mark == SKB_MARK_TYPE_DUMMY){
        return 1;
    }

    if (has_ack_flag(tcp_flags) == 0) {
        return 1; // No ACK flag, nothing more to do
    }
    __u32 input_ack_num;
    result = extract_ack_num(skb, ip_header_len, &input_ack_num);
    if (result != 1) {
        return result;
    }
    result = manage_ack(skb, ack_map, fin_cleanup_queue, input_ack_num, flow, ip_header_len);
    if (result != 1) {
        return result;
    }

    return 1;
}

static __always_inline __u8 seq_num_translation_init_ingress(struct __sk_buff *skb) {
    return seq_num_map_translation_init(skb, &network_to_host_seq_map, &host_to_network_ack_map, BPF_F_INGRESS);
}

static __always_inline __u8 seq_num_translation_init_egress(struct __sk_buff *skb) {
    return seq_num_map_translation_init(skb, &host_to_network_seq_map, &network_to_host_ack_map, 0);
}

static __always_inline __u8 manage_seq_num_ingress(struct __sk_buff *skb) {
    return manage_seq_and_ack(skb, &network_to_host_seq_map, &network_to_host_ack_map, &host_to_network_ack_map, &completed_flow_egress);
}

static __always_inline __u8 manage_seq_num_egress(struct __sk_buff *skb) {
    return manage_seq_and_ack(skb, &host_to_network_seq_map, &host_to_network_ack_map, &network_to_host_ack_map, &completed_flow_ingress);
}

#endif /* __SEQ_NUM_TRANSLATION_H */
