import schedule
import time
import subprocess
from datetime import datetime

def run_scan():
    print(f"[{datetime.now()}] Starting scheduled scan")
    subprocess.run(["python", "cli.py", "scan", "192.168.1.0/24"])
    subprocess.run(["python", "cli.py", "scan-vuln"])
    print(f"[{datetime.now()}] Scan completed")

# Schedule daily at 2 AM
schedule.every().day.at("02:00").do(run_scan)

# Schedule weekly vulnerability scan
schedule.every().wednesday.at("03:00").do(
    lambda: subprocess.run(["python", "cli.py", "scan-vuln"])
)

while True:
    schedule.run_pending()
    time.sleep(60)