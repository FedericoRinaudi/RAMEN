#ifndef __CONSTS_H
#define __CONSTS_H
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN    14

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

#define SKB_MARK_TYPE_NONE 0
#define SKB_MARK_TYPE_FRAGMENT_CLONE 1
#define SKB_MARK_TYPE_DUMMY_CLONE 2
#define SKB_MARK_TYPE_DUMMY 3
/* BLAKE2s authentication tag size */
#define HASH_LEN 32

#endif