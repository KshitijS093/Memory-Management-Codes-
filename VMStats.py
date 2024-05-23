import subprocess
import mysql.connector
from mysql.connector import Error
import signal

exit_flag = False

# Signal handler for SIGINT
def signal_handler(sig, frame):
    global exit_flag
    exit_flag = True
    print("\nReceived Ctrl+C! Setting exit flag...")

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

db_config = {
    'host': 'localhost',
    'database': 'grafanadb',
    'user': 'grafana',
    'password': 'bmscecollege'
}

def insert_into_mysql(pid, rss, pss, process_name, total_memory, used_memory, free_memory, available_memory):
    if exit_flag:
        print("Exiting due to Ctrl+C")
        return
    conn = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        insert_query = """
        INSERT INTO VMStats (pid, rss, pss, process_name, total_memory, used_memory, free_memory, available_memory)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (pid, rss, pss, process_name, total_memory, used_memory, free_memory, available_memory))
        conn.commit()
    except Error as e:
        print(f"Database error: {e}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

def get_memory_stats():
    free_output = subprocess.check_output(['free', '-h']).decode('utf-8')
    smem_output = subprocess.check_output(['smem', '-c', 'pid rss pss name']).decode('utf-8')
    return free_output, smem_output

def print_memory_stats(free_output, smem_output):
    lines = free_output.split('\n')
    memory_line = lines[1].split()
    total_memory, used_memory, free_memory, available_memory = memory_line[1], memory_line[2], memory_line[3], memory_line[6]
    
    print("Overall Memory Statistics:\n")
    print(free_output)
    print("Process Memory Usage (RSS, PSS):\n")
    print("PID\tRSS\tPSS\tNAME")
    
    for line in smem_output.splitlines()[1:]:
        if exit_flag:
            print("Exiting due to Ctrl+C")
            break
        pid, rss, pss, process_name = line.split()[:4]
        print(f"{pid}\t{rss}\t{pss}\t{process_name}")
        insert_into_mysql(pid if pid.isdigit() else None, rss, pss, process_name, total_memory, used_memory, free_memory, available_memory)

if __name__ == "__main__":
    try:
        free_output, smem_output = get_memory_stats()
        print_memory_stats(free_output, smem_output)
    except KeyboardInterrupt:
        print("\nUser interrupted the script. Exiting...")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

