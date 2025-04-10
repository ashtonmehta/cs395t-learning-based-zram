#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

// a hash table to store the start time of
//  each request, indexed by the request pointer
BPF_HASH(start, struct request*);

void trace_start(struct pt_regs *ctx, struct request *req) {
    // stash start timestamp by request pair
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;
    tsp = start.lookup(&req);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_trace_printk("%d %x %d\\n", req->__data_len, req->cmd_flags, delta / 1000);
        start.delete(&req);
    }
}
"""

b = BPF(text=prog)
if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")

if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    # __blk_account_io_done is available before kernel v6.4. 
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion")
elif BPF.get_kprobe_functions(b'blk_account_io_done'):
    # blk_account_io_done is traceable (not inline) before v5.16. 
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")
else:
    b.attach_kprobe(event="blk_mq_end_request", fn_name="trace_completion")

print("Tracing block I/O... Ctrl-C to end.")
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (bytes_s, bflags_s, us_s) = msg.split()
        if int(bflags_s, 16) & REQ_WRITE:
            type_s = b"W"
        elif bytes_s == "0":	# see blk_fill_rwbs() for logic
            type_s = b"M"
        else:
            type_s = b"R"
        ms = float(int(us_s, 10)) / 1000
        printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))   
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()