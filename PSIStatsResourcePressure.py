import subprocess
import mysql.connector
from mysql.connector import Error

# Add your MySQL database connection details
db_config = {
    'host': 'localhost',
    'database': 'grafanadb',
    'user': 'grafana',
    'password': 'bmscecollege'
}


def insert_into_mysql(stat_type, metrics):
    conn = None
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        insert_query = """
        INSERT INTO PSI_Stats_Resource_Pressure 
        (stat_type, avg10, avg60, avg300, total)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            stat_type, 
            metrics.get('avg10', 0),
            metrics.get('avg60', 0),
            metrics.get('avg300', 0),
            metrics.get('total', 0)
        ))
        conn.commit()
    except Error as e:
        print(f"Database error: {e}")
    finally:
        if conn and conn.is_connected():
            # The following lines are properly indented within the finally block
            cursor.close()
            conn.close()

def parse_pressure_stats(output):
    """Parse the pressure stats output to extract all average values and total."""
    metrics = {'avg10': 0.0, 'avg60': 0.0, 'avg300': 0.0, 'total': 0}
    for line in output.splitlines():
        for metric in metrics.keys():
            # Find the part of the line that contains the current metric
            part = next((p for p in line.split() if p.startswith(metric + '=')), None)
            if part:
                value = part.split('=')[1]
                # Attempt to convert the value to the appropriate type (float for averages, int for total)
                if metric == 'total':
                    metrics[metric] = int(value)
                else:
                    metrics[metric] = float(value)
    return metrics


def get_pressure_stat(stat_type):
    try:
        file_path = f'/proc/pressure/{stat_type}'
        result = subprocess.run(['cat', file_path], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{stat_type.capitalize()} Pressure Stats:\n{result.stdout.strip()}")
            metrics = parse_pressure_stats(result.stdout)
            # Adjusted to pass the entire metrics dictionary
            insert_into_mysql(stat_type, metrics)
        else:
            print(f"Failed to fetch {stat_type} pressure stats.")
    except Exception as e:
        print(f"Error fetching {stat_type} pressure stats: {e}")


if __name__ == "__main__":
    print("Gathering CPU and Memory pressure stats and inserting into MySQL...")
    get_pressure_stat('cpu')
    get_pressure_stat('memory')

