#!/usr/bin/env python

from bcc import BPF
from time import sleep
import mysql.connector
from mysql.connector import Error

db_config = {
    'host': 'localhost',
    'user': 'grafana',
    'password': 'bmscecollege',
    'database': 'grafanadb'
}

def insert_data_to_mysql(data):
    try:
        conn = mysql.connector.connect(**db_config)
        if conn.is_connected():
            cursor = conn.cursor()
            insert_query = """
            INSERT INTO Paging_Operations (pid, page_faults, refaults, swap_ins, swap_outs)
            VALUES (%s, %s, %s, %s, %s)
            """
            for pid, stats in data.items():
                cursor.execute(insert_query, (pid, stats["page_faults"], stats["refaults"], stats["swap_ins"], stats["swap_outs"]))
            conn.commit()
            cursor.close()
            conn.close()
    except Error as e:
        print(f"Error: {e}")
# Combined BPF program
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// For tracing page faults
BPF_HISTOGRAM(page_fault_count, u32);

// For tracing page re-faults
BPF_HASH(page_refaults, u32, u64);

// For tracing swap in/out
struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(swapin_addrs, struct key_t, u64);
BPF_HASH(swapout_addrs, struct key_t, u64);

int trace_page_fault(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    page_fault_count.increment(pid);
    return 0;
}

int trace_page_reclaimed(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = page_refaults.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        u64 zero = 0;
        page_refaults.update(&pid, &zero);
    }
    return 0;
}

int kprobe__swap_readpage(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = pid};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    u64 *count, zero = 0;
    count = swapin_addrs.lookup_or_init(&key, &zero);
    (*count)++;
    return 0;
}

int kprobe__swap_writepage(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = pid};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    u64 *count, zero = 0;
    count = swapout_addrs.lookup_or_init(&key, &zero);
    (*count)++;
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)
b.attach_kprobe(event="handle_mm_fault", fn_name="trace_page_fault")
b.attach_kprobe(event="swap_readpage", fn_name="kprobe__swap_readpage")
b.attach_kprobe(event="swap_writepage", fn_name="kprobe__swap_writepage")

print("Tracing page faults, re-faulted (reclaimed) pages, and swap in/out events... Ctrl+C to exit")

# Main loop
try:
    while True:
        # Aggregate data
        aggregated_data = {}
        page_fault_count = b["page_fault_count"]
        page_refaults = b["page_refaults"]
        swapin_addrs = b["swapin_addrs"]
        swapout_addrs = b["swapout_addrs"]

        for pid, count in page_fault_count.items():
            pid_value = pid.value
            if pid_value not in aggregated_data:
                aggregated_data[pid_value] = {"page_faults": 0, "refaults": 0, "swap_ins": 0, "swap_outs": 0}
            aggregated_data[pid_value]["page_faults"] = count.value
        
        for pid, count in page_refaults.items():
            if pid not in aggregated_data:
                aggregated_data[pid] = {"page_faults": 0, "refaults": 0, "swap_ins": 0, "swap_outs": 0}
            aggregated_data[pid]["refaults"] = count.value

        for key, count in swapin_addrs.items():
            pid_value = key.pid
            if pid_value not in aggregated_data:
                aggregated_data[pid_value] = {"page_faults": 0, "refaults": 0, "swap_ins": 0, "swap_outs": 0}
            aggregated_data[pid_value]["swap_ins"] = count.value
        
        for key, count in swapout_addrs.items():
            pid_value = key.pid
            if pid_value not in aggregated_data:
                aggregated_data[pid_value] = {"page_faults": 0, "refaults": 0, "swap_ins": 0, "swap_outs": 0}
            aggregated_data[pid_value]["swap_outs"] = count.value
        
        # Print aggregated data
        print("\n%-6s %-12s %-8s %-9s %-9s" % ("PID", "Page Faults", "Re-faults", "Swap Ins", "Swap Outs"))
        for pid, data in aggregated_data.items():
            print("%-6d %-12d %-8d %-9d %-9d" % (pid, data["page_faults"], data["refaults"], data["swap_ins"], data["swap_outs"]))
        
        insert_data_to_mysql(aggregated_data)

        page_fault_count.clear()
        page_refaults.clear()
        swapin_addrs.clear()
        swapout_addrs.clear()

        sleep(10)
except KeyboardInterrupt:
    print("Detaching...")
    exit()

