struct exec_event {
    __u64 ktime_ns;
    __u32 kind;
    __u32 pid;
    __u32 ppid;
    char comm[16];
    char filename[128];
};

struct open_event {
    __u64 ktime_ns;
    __u32 kind;
    __u32 pid;
    char comm[16];
    char filename[128];
};

#define AF_INET 2
#define AF_INET6 10

#define TCP_EVENT_CONNECT 1
#define TCP_EVENT_ACCEPT 2
#define TCP_EVENT_CLOSE 3

#define EVENT_KIND_EXEC 1
#define EVENT_KIND_OPEN 2

#define HIST_SLOTS 32

#define FILTER_EVENT_CONNECT 1
#define FILTER_EVENT_ACCEPT 2
#define FILTER_EVENT_CLOSE 4
#define FILTER_EVENT_ALL 7

struct filter_config {
    __u32 pid;
    __u32 pid_enabled;
    __u32 comm_enabled;
    __u32 event_mask;
    char comm[16];
};

enum {
    SYSCALL_READ = 0,
    SYSCALL_WRITE = 1,
    SYSCALL_OPENAT = 2,
    SYSCALL_COUNT = 3,
};

struct tcp_event {
    __u64 ktime_ns;
    __u32 pid;
    char comm[16];
    __u8 event_type;
    __u8 family;
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
};
