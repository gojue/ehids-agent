#ifndef ECAPTURE_COMMON_H
#define ECAPTURE_COMMON_H

#ifdef DEBUG_PRINT
#define debug_bpf_printk(fmt, ...)                     \
    do {                                               \
        char s[] = fmt;                                \
        bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__); \
    } while (0)
#else
#define debug_bpf_printk(fmt, ...)
#endif

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;


#define MAX_PAYLOAD_LEN 150


// These are used by a number of
// different programs to sync eBPF Tail Call
// login between user space and kernel
#define PROG_00 0
#define PROG_01 1
#define PROG_02 2

// Used when replacing text
#define FILENAME_LEN_MAX 50
#define TEXT_LEN_MAX 20

// Simple message structure to get events from eBPF Programs
// in the kernel to user spcae
#define TASK_COMM_LEN 16
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

struct tr_file {
    char filename[FILENAME_LEN_MAX];
    unsigned int filename_len;
};

struct tr_text {
    char text[TEXT_LEN_MAX];
    unsigned int text_len;
};


#endif