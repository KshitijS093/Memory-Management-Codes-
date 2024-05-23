from bcc import BPF
import time

import mysql.connector
from mysql.connector import Error

db_config = {
    'host': 'localhost',
    'user': 'grafana',
    'password': 'bmscecollege',
    'database': 'grafanadb'
}

def insert_into_mysql(data, read_mb_s, write_mb_s):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        insert_query = """
        INSERT INTO Swap_IO_Overhead (pid, command, read_bytes, write_bytes, read_mb_s, write_mb_s)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        for item in data:
            cursor.execute(insert_query, item + (read_mb_s, write_mb_s))
        conn.commit()
    except Error as e:
        print(f"Error: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# Interval for calculating rates, in seconds
INTERVAL = 1

# BPF program
bpf_program = """
#include <linux/blk-mq.h>

struct cmd_struct {
    char comm[16];
};

BPF_HASH(pid_cmd, u32, struct cmd_struct);
BPF_HASH(read_bytes, u32, u64);
BPF_HASH(write_bytes, u32, u64);

TRACEPOINT_PROBE(block, block_rq_issue) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct cmd_struct val = {};
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    pid_cmd.update(&pid, &val);

    u64 *rb, *wb, zero = 0;
    if (args->rwbs[0] == 'R') {
        rb = read_bytes.lookup_or_init(&pid, &zero);
        if (rb) {
            *rb += args->bytes;
        }
    } else if (args->rwbs[0] == 'W') {
        wb = write_bytes.lookup_or_init(&pid, &zero);
        if (wb) {
            *wb += args->bytes;
        }
    }
    return 0;
}
"""

# Load and attach BPF program
b = BPF(text=bpf_program)

print("Monitoring Disk I/O for all processes")
print("PID\tCMD\t\tREAD_BYTES\tWRITE_BYTES")

def print_stats(interval):
    read_bytes = b.get_table("read_bytes")
    write_bytes = b.get_table("write_bytes")
    pid_cmd = b.get_table("pid_cmd")

    total_read_bytes = 0
    total_write_bytes = 0
    data_for_mysql = []

    for pid, cmd in pid_cmd.items():
        read_b = read_bytes[pid].value if pid in read_bytes else 0
        write_b = write_bytes[pid].value if pid in write_bytes else 0
        cmd_str = bytearray(cmd.comm).decode(errors='ignore').rstrip('\x00')
        data_for_mysql.append((pid.value, cmd_str, read_b, write_b))

        total_read_bytes += read_b
        total_write_bytes += write_b

    total_read_mb = total_read_bytes / 1024 / 1024
    total_write_mb = total_write_bytes / 1024 / 1024

    read_mb_s = total_read_mb / interval
    write_mb_s = total_write_mb / interval

    insert_into_mysql(data_for_mysql, read_mb_s, write_mb_s)

    read_bytes.clear()
    write_bytes.clear()
    pid_cmd.clear()

# Loop printing output every interval
try:
    while True:
        print_stats(INTERVAL)
        time.sleep(INTERVAL)  # Use the INTERVAL variable
except KeyboardInterrupt:
    print("Exiting...")

