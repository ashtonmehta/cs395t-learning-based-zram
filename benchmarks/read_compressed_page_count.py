#!/usr/bin/env python
from bcc import BPF
import time

bpf_text = """
#include <uapi/linux/ptrace.h>

/*
 * This line defines a BPF hash table named 'compressed_reads' that
 * maps a u32 key to a u64 value. We will use a singl key (0) to 
 * represent a global counter for the number of compressed page reads.
 * The map is also limited to a single entry.
 */
BPF_HASH(compressed_reads, u32, u64, 1);

int trace_read_compressed_page(struct pt_regs *ctx) {
    // We will use a single key (0) to represent a global counter.
    u32 key = 0;
    u64 zero = 0;
    u64 *count = compressed_reads.lookup(&key);
    if (!count) {
        compressed_reads.update(&key, &zero);
        count = compressed_reads.lookup(&key);
    }
    if (count) {
        (*count)++;
    }
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

# Attach kprobe to zcomp_decompress in zram_drv.c
b.attach_kprobe(event="zcomp_decompress" , fn_name="trace_read_compressed_page")
print("timestamp,compressed_page_reads (cumulative)")
print("Tracking compressed page reads... Press Ctrl-C to exit.")

try:
    while True:
        time.sleep(1)
        count_map = b.get_table("compressed_reads")
        count = 0
        for k, v in count_map.items():
            count = v.value
        print("{},{}".format(time.time(), count))
except KeyboardInterrupt:
    exit()