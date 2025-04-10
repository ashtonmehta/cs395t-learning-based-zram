#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

prog = """
#include <uapi/linux/ptrace.h>

BPF_HASH(count);
int trace_read_compressed_page(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *count = compressed_reads.lookup_or_init(&key, &(u64){0});
    if (count) {
        (*count)++;
    }
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="read_compressed_page", fn_name="trace_read_compressed_page")
print("Tracing for compressed page reads... Ctrl-C to end.")

try:
    while True:
        pass
except KeyboardInterrupt:
    exit()