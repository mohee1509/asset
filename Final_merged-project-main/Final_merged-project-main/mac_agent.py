import getpass
import os
import platform
import shutil
import socket
import subprocess
import threading
import time

import psutil
import requests

SERVER_URL = "http://192.168.1.18:8000" # Make sure this IP is correct
AGENT_ID = socket.gethostname()
HOSTNAME = socket.gethostname()

# --- NEW FUNCTION TO DETECT VM ---
def get_machine_type():
    """Detects if the machine is physical or virtual on macOS."""
    try:
        # Check system profiler for model identifier
        model_info = subprocess.check_output(
            ["sysctl", "-n", "hw.model"], 
            stderr=subprocess.DEVNULL
        ).decode().lower()
        if "vmware" in model_info or "virtualbox" in model_info:
            return "Virtual"

        # Another check using ioreg
        ioreg_info = subprocess.check_output(
            ["ioreg", "-l"], 
            stderr=subprocess.DEVNULL
        ).decode().lower()
        if '"manufacturer" = <"vmware,inc.">' in ioreg_info or '"manufacturer" = <"innotek gmbh">' in ioreg_info:
             return "Virtual"
    except Exception:
        pass # Ignore errors if commands fail
    return "Physical"

def get_installed_software():
    software = []
    try:
        if platform.system() == "Darwin":  # macOS
            # Get installed applications
            try:
                output = subprocess.check_output(
                    ["system_profiler", "SPApplicationsDataType"],
                    universal_newlines=True,
                    stderr=subprocess.DEVNULL
                )
                app_name = None
                for line in output.splitlines():
                    line = line.strip()
                    if line.endswith(":") and not line.startswith(" "):
                        app_name = line[:-1]
                    elif line.startswith("Version:") and app_name:
                        version = line.split(":", 1)[1].strip()
                        software.append(f"{app_name} {version}")
                        app_name = None
            except Exception as e:
                software.append(f"Error reading applications: {e}")
    except Exception as e:
        software.append(f"Error: {str(e)}")
    return software

def get_open_ports():
    ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_LISTEN:
                ports.append({
                    "port": conn.laddr.port,
                    "ip": conn.laddr.ip,
                    "process": psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                })
    except Exception as e:
        ports.append({"error": str(e)})
    return ports

def get_vmware_vms():
    vms_info = []
    vmrun_path = shutil.which("vmrun")
    if not vmrun_path:
        possible_paths = [
            "/Applications/VMware Fusion.app/Contents/Library/vmrun"
        ]
        for p in possible_paths:
            if os.path.exists(p):
                vmrun_path = p
                break
    if not vmrun_path:
        return []

    try:
        output = subprocess.check_output([vmrun_path, "list"], universal_newlines=True)
        lines = output.splitlines()
        if len(lines) > 1:
            for vmx_path in lines[1:]:
                vmx_path = vmx_path.strip()
                guest_os = "Unknown"
                if os.path.exists(vmx_path):
                    try:
                        with open(vmx_path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                if line.strip().startswith("guestOS"):
                                    guest_os = line.split("=")[1].strip().strip('"')
                                    break
                    except Exception:
                        pass
                vms_info.append({"vmx_path": vmx_path, "guest_os": guest_os})
    except Exception as e:
        vms_info.append({"error": str(e)})

    return vms_info

def collect_info():
    try:
        ip_list = [
            ni.address
            for ni_list in psutil.net_if_addrs().values()
            for ni in ni_list
            if ni.family.name == 'AF_INET'
        ]
    except Exception:
        ip_list = []

    uptime_seconds = int(time.time() - psutil.boot_time())

    data = {
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "username": getpass.getuser(),
        "os": platform.system(),
        "os_version": platform.mac_ver()[0] if platform.system() == "Darwin" else platform.version(),
        "cpu": platform.processor(),
        "memory_gb": round(psutil.virtual_memory().total / 1e9, 2),
        "disk_gb": round(psutil.disk_usage('/').total / 1e9, 2),
        "uptime_seconds": uptime_seconds,
        "open_ports": get_open_ports(),
        "software": get_installed_software(),
        "ip_addresses": ip_list,
        "vmware_vms": get_vmware_vms(),
        "collected_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    print("[DEBUG] Collected asset data:", data)
    return data

# --- UPDATED HEARTBEAT FUNCTION ---
def send_heartbeat():
    while True:
        try:
            # Get machine type for every heartbeat
            machine_type = get_machine_type()
            
            # This payload now matches what the server expects
            payload = {
                "hostname": HOSTNAME,
                "os_name": "mac", # Hardcoded for the Mac agent
                "machine_type": machine_type
            }

            r = requests.post(f"{SERVER_URL}/agent_heartbeat", json=payload, timeout=5)
            print(f"[{time.strftime('%H:%M:%S')}] Heartbeat: {r.status_code} (Type: {machine_type})")
        except Exception as e:
            print(f"Heartbeat error: {e}")
        time.sleep(5)

def send_assets():
    while True:
        try:
            data = collect_info()
            r = requests.post(f"{SERVER_URL}/agent_assets", json=data, timeout=10)
            print(f"[{time.strftime('%H:%M:%S')}] Asset report: {r.status_code}")
            print("[DEBUG] Server response:", r.text)
        except Exception as e:
            print(f"Asset report error: {e}")
        time.sleep(3600)  # every hour

if __name__ == "__main__":
    threading.Thread(target=send_heartbeat, daemon=True).start()
    threading.Thread(target=send_assets, daemon=True).start()
    while True:
        time.sleep(1)