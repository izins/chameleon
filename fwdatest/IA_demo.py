#%%
import psutil

data = []

for conn in psutil.net_connections(kind="inet"):
    if not conn.raddr:
        continue

    try:
        pid = conn.pid
        if pid is None:
            continue

        p = psutil.Process(pid)

        record = {
            "local_ip": conn.laddr.ip,
            "local_port": conn.laddr.port,
            "remote_ip": conn.raddr.ip,
            "remote_port": conn.raddr.port,
            "status": conn.status,
            "pid": pid,
            "process_name": p.name(),
            "process_path": p.exe(),
            "username": p.username(),
            "cpu_percent": p.cpu_percent(interval=0.1),
            "memory_mb": p.memory_info().rss / 1024 / 1024
        }

        data.append(record)

        print(record)

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue



#%%
from datetime import datetime
import random
import json
import os

# helper data
processes = [
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "SYSTEM"),
    ("explorer.exe", "C:\\Windows\\explorer.exe", "user"),
    ("python.exe", "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\python.exe", "user"),
    ("discord.exe", "C:\\Users\\user\\AppData\\Local\\Discord\\app.exe", "user"),
    ("unknown.exe", "C:\\Temp\\unknown.exe", "user"),
]

statuses = ["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"]

def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"

def is_suspicious(proc_name, remote_ip, port):
    # simple heuristic labeling
    if proc_name == "unknown.exe":
        return 1
    if port in [4444, 5555, 1337]:
        return 1
    if remote_ip.startswith("10.") and proc_name == "svchost.exe":
        return 0
    if random.random() < 0.05:
        return 1
    return 0

data = []

for i in range(2000):
    proc_name, path, user = random.choice(processes)
    pid = random.randint(1000, 50000)

    record = {
        "local_ip": "192.168.1.10",
        "local_port": random.randint(1024, 65535),
        "remote_ip": random_ip(),
        "remote_port": random.randint(1, 65535),
        "status": random.choice(statuses),
        "pid": pid,
        "process_name": proc_name,
        "process_path": path,
        "username": user,
        "cpu_percent": round(random.uniform(0, 30), 2),
        "memory_mb": round(random.uniform(5, 500), 2),
        "timestamp": datetime.utcnow().isoformat(),
    }

    label = is_suspicious(proc_name, record["remote_ip"], record["remote_port"])
    record["label"] = "suspicious" if label == 1 else "normal"

    data.append(record)


file_path = r"C:\Users\PC\Desktop\cyber_ia\fused_network_process_logs.json"
os.makedirs(os.path.dirname(file_path), exist_ok=True)

with open(file_path, "w") as f:
    json.dump(data, f, indent=2)

f