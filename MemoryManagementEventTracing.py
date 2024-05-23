#!/usr/bin/env python

import subprocess
from bcc import BPF
import psutil
import time

import mysql.connector
from mysql.connector import Error

def insert_into_mysql(event_type, pid=None, process_name=None, total_memory_gb=None, available_memory_gb=None, used_memory_gb=None, memory_percent_used=None, total_swap_gb=None, used_swap_gb=None, swap_percent_used=None):
    try:
        conn = mysql.connector.connect(
            host='localhost',
            database='grafanadb',
            user='grafana',
            password='bmscecollege'
        )
        cursor = conn.cursor()
        insert_query = """
        INSERT INTO Memory_Management_Event_Tracing (event_type, pid, process_name, total_memory_gb, available_memory_gb, used_memory_gb, memory_percent_used, total_swap_gb, used_swap_gb, swap_percent_used)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (event_type, pid, process_name, total_memory_gb, available_memory_gb, used_memory_gb, memory_percent_used, total_swap_gb, used_swap_gb, swap_percent_used))
        conn.commit()
    except Error as e:
        print(f"Database error: {e}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


# Keep the OOM kill event part of your BPF program
bpf_prog = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

struct data_t {
    u32 fpid;
    char fcomm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(oom_events);

void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message) {
    struct task_struct *p = oc->chosen;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.fpid = pid;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    oom_events.perf_submit(ctx, &data, sizeof(data));
}
"""

# Load BPF program
b = BPF(text=bpf_prog)

# Define processing function for OOM events
def print_oom_event(cpu, data, size):
    event = b["oom_events"].event(data)
    print(f"OOM Kill: PID {event.fpid} ({event.fcomm.decode('utf-8', 'replace')})")
    # Insert OOM event data into MySQL
    insert_into_mysql(event_type="OOM Kill", pid=event.fpid, process_name=event.fcomm.decode('utf-8', 'replace'))


# Attach perf buffer for OOM events
b["oom_events"].open_perf_buffer(print_oom_event)

def monitor_system_memory():
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    print(f"Memory - Total: {memory.total / (1024**3):.2f} GB, Available: {memory.available / (1024**3):.2f} GB, Used: {memory.used / (1024**3):.2f} GB ({memory.percent}%)")
    print(f"Swap - Total: {swap.total / (1024**3):.2f} GB, Used: {swap.used / (1024**3):.2f} GB ({swap.percent}%)")
    # Insert memory and swap usage data into MySQL
    insert_into_mysql(
        event_type="Memory/Swap Usage",
        total_memory_gb=memory.total / (1024**3),
        available_memory_gb=memory.available / (1024**3),
        used_memory_gb=memory.used / (1024**3),
        memory_percent_used=memory.percent,
        total_swap_gb=swap.total / (1024**3),
        used_swap_gb=swap.used / (1024**3),
        swap_percent_used=swap.percent
    )

print("Monitoring OOM kills and system memory/swap usage... Press CTRL+C to stop.")

try:
    while True:
        # OOM kill events
        b.perf_buffer_poll(timeout=1000)  # timeout is in milliseconds
        
        # Monitor system memory and swap usage
        monitor_system_memory()
        
        # Sleep for a bit to avoid spamming output too quickly
        time.sleep(5)

except KeyboardInterrupt:
    print("\nExiting...")
