#!/usr/bin/python
import time
from bcc import BPF
import mysql.connector
from mysql.connector import Error

# MySQL configuration
db_config = {
    'host': 'localhost',
    'user': 'grafana',
    'password': 'bmscecollege',
    'database': 'grafanadb'
}

def insert_into_mysql(timestamp, pid, action, count):
    conn = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        insert_query = """
        INSERT INTO User_Space_Memory_Alloc_And_Dealloc (timestamp, pid, action, count)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (timestamp, pid, action, count))
        conn.commit()
    except Error as e:
        print(f"Error: {e}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(allocs, u64, u64);
BPF_HASH(frees, u64, u64);

int trace_alloc(struct pt_regs *ctx) {
    u64 addr = PT_REGS_RC(ctx);
    u64 *count = allocs.lookup(&addr);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        allocs.update(&addr, &one);
    }
    return 0;
}

int trace_free(struct pt_regs *ctx) {
    u64 addr = PT_REGS_PARM1(ctx);
    u64 *count = frees.lookup(&addr);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        frees.update(&addr, &one);
    }
    return 0;
}
"""

# Load the eBPF program
b = BPF(text=bpf_text)

# Attach eBPF program to malloc and free functions
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libc.so.6", sym="malloc", fn_name="trace_alloc")
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libc.so.6", sym="free", fn_name="trace_free")

print("Tracing memory allocations and deallocations...")

# Data structures for tracking allocations and deallocations
allocs = b.get_table("allocs")
frees = b.get_table("frees")

def format_timestamp(timestamp):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

try:
    while True:
        current_time = time.time()
        formatted_time = format_timestamp(current_time)
        for addr, count in allocs.items():
            address = int.from_bytes(addr, byteorder='little')
            alloc_count = count.value
            insert_into_mysql(formatted_time, address >> 32, 'Allocation', alloc_count)
        
        for addr, count in frees.items():
            address = int.from_bytes(addr, byteorder='little')
            free_count = count.value
            insert_into_mysql(formatted_time, address >> 32, 'Deallocation', free_count)
        
        allocs.clear()
        frees.clear()

except KeyboardInterrupt:
    print("Tracing stopped.")

