#ifndef __CLIENT_CONFIG_H
#define __CLIENT_CONFIG_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "config.h"

/* Structure to hold client configuration including keys and probabilities */
struct client_config {
    __u8 padding_key[32];
    __u8 dummy_key[32];
    __u64 expiration_time;      // Unix timestamp in seconds when config expires
    __u8 padding_probability;   // Current probability (0-100) of applying padding
    __u8 padding_prob_min;      // Minimum probability for padding
    __u8 padding_prob_max;      // Maximum probability for padding
    __u8 dummy_probability;     // Current probability (0-100) of inserting dummy packets
    __u8 dummy_prob_min;        // Minimum probability for dummy packets
    __u8 dummy_prob_max;        // Maximum probability for dummy packets
    __u8 frag_probability;      // Current probability (0-100) of fragmenting packets
    __u8 frag_prob_min;         // Minimum probability for fragmentation
    __u8 frag_prob_max;         // Maximum probability for fragmentation
    __u8 _pad[7];               // Explicit padding for 8-byte alignment of prob_timestamp
    __u64 prob_timestamp;       // ktime_get_ns() of last probability refresh (0 = never)
};

/* Key structure for client config map (IP address + server port) */
struct client_config_key {
    __u32 ip_addr;      // IP address
    __u16 server_port;  // Server port
    __u16 _padding;     // Explicit padding for alignment
};


/* Map for client configurations indexed by IP address and server port */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_config_key);
    __type(value, struct client_config);
    __uint(max_entries, 1024);
} client_config_map SEC(".maps");

/* Get client configuration for given IP address and server port.
 * Refreshes per-type probabilities every 3 seconds by picking a random value
 * in [min, max] for each type. On first call (prob_timestamp == 0) the refresh
 * always triggers because bpf_ktime_get_ns() >> 3000000000. */
static __always_inline struct client_config* get_client_config(__u32 ip_addr, __u16 server_port) {
    struct client_config_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct client_config *config = bpf_map_lookup_elem(&client_config_map, &key);
    if (!config) {
        debug_print("[CLIENT_CONFIG] No config found for IP:port 0x%x:%u", ip_addr, server_port);
        return NULL;
    }

    __u64 now = bpf_ktime_get_ns();
    if (now - config->prob_timestamp > PROB_REFRESH_INTERVAL_NS) {
        __u8 range;

        range = config->padding_prob_max - config->padding_prob_min;
        config->padding_probability = config->padding_prob_min +
            (range > 0 ? (__u8)(bpf_get_prandom_u32() % ((__u32)range + 1)) : 0);

        range = config->dummy_prob_max - config->dummy_prob_min;
        config->dummy_probability = config->dummy_prob_min +
            (range > 0 ? (__u8)(bpf_get_prandom_u32() % ((__u32)range + 1)) : 0);

        range = config->frag_prob_max - config->frag_prob_min;
        config->frag_probability = config->frag_prob_min +
            (range > 0 ? (__u8)(bpf_get_prandom_u32() % ((__u32)range + 1)) : 0);

        config->prob_timestamp = now;
        debug_print("[CLIENT_CONFIG] Refreshed probs: pad=%u dummy=%u frag=%u",
                    config->padding_probability, config->dummy_probability, config->frag_probability);
    }

    return config;
}

/* Get client configuration for ingress packets (extracts src_ip and server port) */
static __always_inline struct client_config* get_client_config_ingress(struct __sk_buff *skb, __u8 ip_header_len) {
    __u32 src_ip;
    if (extract_src_ip(skb, &src_ip) < 0) {
        return NULL;
    }
    
    __u16 server_port;
    if (extract_server_port_ingress(skb, ip_header_len, &server_port) < 0) {
        return NULL;
    }
    
    return get_client_config(src_ip, server_port);
}

/* Get client configuration for egress packets (extracts dst_ip and server port) */
static __always_inline struct client_config* get_client_config_egress(struct __sk_buff *skb, __u8 ip_header_len) {
    __u32 dst_ip;
    if (extract_dst_ip(skb, &dst_ip) < 0) {
        return NULL;
    }
    
    __u16 server_port;
    if (extract_server_port_egress(skb, ip_header_len, &server_port) < 0) {
        return NULL;
    }
    
    return get_client_config(dst_ip, server_port);
}

#endif // __CLIENT_CONFIG_H
