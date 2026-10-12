#ifndef __CONFIG_H
#define __CONFIG_H

/* Debug configuration - DEBUG is passed via -DDEBUG flag at compile time */
#ifndef DEBUG
#define DEBUG 0
#endif

/* Server or Client configuration - IS_SERVER is passed via -DIS_SERVER flag at compile time */
#ifndef IS_SERVER
#define IS_SERVER 0
#endif

#if DEBUG
#define debug_print(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_print(fmt, ...) do {} while (0)
#endif

/* Packet size limits */
#define MAX_PKT_SIZE 1514
#define FRAG_BUFF_MAX_SIZE 300
#define MAX_PADDING_UNITS 20

/* Probability thresholds (0-100) */
#define PROBABILITY_OF_FRAGMENTATION 70
#define PROBABILITY_OF_PADDING 70
#define PROBABILITY_OF_DUMMY 70

/* Interval (nanoseconds) between per-client probability refreshes */
#define PROB_REFRESH_INTERVAL_NS 3000000000ULL

#endif // __CONFIG_H
