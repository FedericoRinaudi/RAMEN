BPF_CLANG ?= clang-15
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_CFLAGS += -D__TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
  BPF_CFLAGS += -D__TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
  BPF_CFLAGS += -D__TARGET_ARCH_arm64
endif

CC ?= gcc
UCFLAGS := -O2 -g -Wall
ULIBS := -lbpf -lelf -lz

all: RAMEN

RAMEN: RAMEN.bpf.o loader

# IS_SERVER can be overridden: make IS_SERVER=1 for server, make IS_SERVER=0 for client
# DEBUG can be overridden: make DEBUG=1 for debug, make DEBUG=0 for release
IS_SERVER ?= 0
DEBUG ?= 0

RAMEN.bpf.o: RAMEN.bpf.c config.h network_utils.h checksum.h hmac.h padding.h fragmentation.h blake2s.h vmlinux.h seq_num_translation.h skb_mark.h client_config.h dummy.h consts.h
	$(BPF_CLANG) $(BPF_CFLAGS) -DIS_SERVER=$(IS_SERVER) -DDEBUG=$(DEBUG) -c $< -o $@

loader: loader.c
	$(CC) $(UCFLAGS) $< -o $@ $(ULIBS)

clean:
	rm -f *.bpf.o loader

.PHONY: all RAMEN clean
