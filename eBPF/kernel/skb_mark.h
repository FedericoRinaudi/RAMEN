#ifndef __SKB_MARK_H
#define __SKB_MARK_H

#include "vmlinux.h"

/*
 * skb->mark encoding (32 bits total):
 *
 * [31-16] len (16 bits)
 * [15-12] unused (4 bits)
 * [11-8]  redirect_count (4 bits)
 * [7-0]   type (8 bits)
 */

#define SKB_MARK_DEFINE_FIELD(NAME, CTYPE, LEN, OFF)                              \
    enum { SKB_MARK_##NAME##_SHIFT = (OFF) };                                     \
    enum { SKB_MARK_##NAME##_LEN   = (LEN) };                                     \
    enum { SKB_MARK_##NAME##_MASK  = ((((__u32)1U << (LEN)) - 1U) << (OFF)) };    \
                                                                                  \
    static __always_inline CTYPE skb_mark_get_##NAME(struct __sk_buff *skb)       \
    {                                                                             \
        return (CTYPE)((skb->mark & SKB_MARK_##NAME##_MASK) >>                    \
                        SKB_MARK_##NAME##_SHIFT);                                 \
    }                                                                             \
                                                                                  \
    static __always_inline void skb_mark_set_##NAME(struct __sk_buff *skb, CTYPE v) \
    {                                                                             \
        volatile __u32 new_mark =                                                 \
            (skb->mark & ~SKB_MARK_##NAME##_MASK) |                               \
            (((__u32)v << SKB_MARK_##NAME##_SHIFT) & SKB_MARK_##NAME##_MASK);     \
        skb->mark = new_mark;                                                     \
    }

/* Field definitions: LEN in bits, OFF = starting bit */

SKB_MARK_DEFINE_FIELD(type,            __u8,  8,  0);
SKB_MARK_DEFINE_FIELD(redirect_count,  __u8,  4,  8);
SKB_MARK_DEFINE_FIELD(len,__u16,16, 16);

static __always_inline void skb_mark_increment_redirect_count(struct __sk_buff *skb)
{
    __u8 current = skb_mark_get_redirect_count(skb);
    skb_mark_set_redirect_count(skb, current + 1);
}

#endif /* __SKB_MARK_H */
