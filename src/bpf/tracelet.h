struct exec_event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    char filename[128];
};
