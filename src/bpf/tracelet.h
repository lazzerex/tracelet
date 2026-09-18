struct exec_event {
    __u64 ktime_ns;
    __u32 pid;
    __u32 ppid;
    char comm[16];
    char filename[128];
};

struct open_event {
    __u64 ktime_ns;
    __u32 pid;
    char comm[16];
    char filename[128];
};
