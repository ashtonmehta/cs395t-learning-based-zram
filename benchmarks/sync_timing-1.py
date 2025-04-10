#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

prog = """
#include <uapi/linux/ptrace.h>
BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 count = 0, *countp, key = 0;
    
    countp = last.lookup(&key);
    if (countp != NULL) {
        count = *countp;
        bpf_trace_printk("%d\\n", count);
        last.delete(&key);
    }

    // increment the count
    count++;
    last.update(&key, &count);
    return 0;
}
"""
b = BPF(text=prog)

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for sync count... Ctrl-C to end.")
print("%-18s %-16s %-6s %-s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

start = 0
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()