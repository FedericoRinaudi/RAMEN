/*
 * - loader.c: Simplified version that only loads eBPF programs
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <signal.h>

static int ifindex_g;
static struct bpf_object *bpf_obj;

static void cleanup(int sig) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_g,
                        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    bpf_tc_hook_destroy(&hook);
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
    }
    exit(0);
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: sudo %s <interface>\n", prog);
}

int main(int argc, char **argv) {
    struct bpf_program *ing_prog, *eg_prog;

    if (argc != 2) {
        fprintf(stderr, "Error: Interface name is required.\n");
        usage(argv[0]);
        return 1;
    }
    
    const char *ifname = argv[1];

    // Get interface index
    ifindex_g = if_nametoindex(ifname);
    if(ifindex_g == 0) { 
        perror("if_nametoindex"); 
        return 1;
    }
    
    // Build the path to the BPF object file
    char bpf_obj_path[256];
    char *prog_dir = strdup(argv[0]);
    char *dir_path = dirname(prog_dir);
    snprintf(bpf_obj_path, sizeof(bpf_obj_path), "%s/RAMEN.bpf.o", dir_path);
    free(prog_dir);
    
    // Load BPF object
    bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(bpf_obj)) { 
        fprintf(stderr, "Failed to open BPF object file: %s\n", bpf_obj_path);
        return 1; 
    }
    
    if (bpf_object__load(bpf_obj)) { 
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(bpf_obj); 
        return 1; 
    }
    
    // Find programs
    ing_prog = bpf_object__find_program_by_name(bpf_obj, "handle_ingress");
    eg_prog = bpf_object__find_program_by_name(bpf_obj, "handle_egress");
    
    // Create TC hook
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_g, 
                        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) { 
        fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err)); 
        bpf_object__close(bpf_obj); 
        return 1; 
    }
    
    // Attach ingress program
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, ing_opts, .prog_fd = bpf_program__fd(ing_prog), 
                        .flags = BPF_TC_F_REPLACE);
    hook.attach_point = BPF_TC_INGRESS;
    err = bpf_tc_attach(&hook, &ing_opts);
    if (err) { 
        fprintf(stderr, "Failed to attach ingress program: %s\n", strerror(-err)); 
        cleanup(0); 
        return 1; 
    }
    
    // Attach egress program
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, eg_opts, .prog_fd = bpf_program__fd(eg_prog), 
                        .flags = BPF_TC_F_REPLACE);
    hook.attach_point = BPF_TC_EGRESS;
    err = bpf_tc_attach(&hook, &eg_opts);
    if (err) { 
        fprintf(stderr, "Failed to attach egress program: %s\n", strerror(-err)); 
        cleanup(0); 
        return 1; 
    }
    
    // Set up signal handlers
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    printf("Successfully loaded and attached eBPF programs to interface %s\n", ifname);
    printf("Press Ctrl+C to detach and exit\n");
    
    // Keep the program running
    while (1) {
        sleep(30);
    }

    return 0;
}
