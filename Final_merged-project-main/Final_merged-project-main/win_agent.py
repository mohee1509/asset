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

SERVER_URL = "http://192.168.1.11:8000" # Make sure this IP is correct
AGENT_ID = socket.gethostname()
HOSTNAME = socket.gethostname()

# --- NEW FUNCTION TO DETECT VM ---

# --- NEW, MORE ACCURATE FUNCTION TO DETECT VM ---
def get_machine_type():
    """
    Detects if the machine is physical or virtual on Windows by checking the hardware model.
    """
    try:
        # WMIC is a reliable way to get hardware info
        model_info = subprocess.check_output(
            "wmic csproduct get vendor,name", 
            shell=True, 
            stderr=subprocess.DEVNULL
        ).decode().lower()
        
        # Virtual machine vendors and models often contain these strings
        vm_indicators = ["vmware", "virtualbox", "qemu", "virtual", "innotek gmbh"]

        if any(indicator in model_info for indicator in vm_indicators):
            return "Virtual"
            
    except Exception as e:
        print(f"Could not run WMIC for VM check: {e}")
        # If WMIC fails, we can fall back to the systeminfo check as a secondary method
        try:
            sys_info = subprocess.check_output("systeminfo", shell=True, stderr=subprocess.DEVNULL).decode().lower()
            if "hyper-v" in sys_info:
                return "Virtual"
        except Exception:
            pass # Ignore errors on the fallback

    # If no VM indicators are found, it's very likely physical
    return "Physical"    

def get_installed_software():
    software = []
    try:
        if platform.system() == "Windows":
            powershell_script = r"""
$paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($path in $paths) {
    try {
        Get-ChildItem $path | ForEach-Object {
            try {
                $item = Get-ItemProperty $_.PSPath
                if ($item.DisplayName -and $item.DisplayVersion) {
                    Write-Output "$($item.DisplayName) $($item.DisplayVersion)"
                }
            } catch {
                continue
            }
        }
    } catch {
        Write-Output "Could not access path: $path"
    }
}
"""
            output = subprocess.check_output(
                ["powershell", "-Command", powershell_script],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            for line in output.splitlines():
                if line.strip():
                    software.append(line.strip())
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
            r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
            r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
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
        "os_version": platform.version(),
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

    print("[DEBUG] Collected asset data:", data)  # DEBUG LOG
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
                "os_name": "windows",  # Hardcoded for the Windows agent
                "machine_type": machine_type
            }
            
            r = requests.post(f"{SERVER_URL}/agent_heartbeat", json=payload, timeout=5)
            print(f"[{time.strftime('%H:%M:%S')}] Heartbeat: {r.status_code} (Type: {machine_type})")
        except Exception as e:
            print(f"Heartbeat error: {e}")
        time.sleep(5) # The server's active threshold is 10s, so 5s is good

def send_assets():
    while True:
        try:
            data = collect_info()
            r = requests.post(f"{SERVER_URL}/agent_assets", json=data, timeout=10)
            print(f"[{time.strftime('%H:%M:%S')}] Asset report: {r.status_code}")
            print("[DEBUG] Server response:", r.text)
        except Exception as e:
            print(f"Asset report error: {e}")
        time.sleep(3600)  # send every hour

if __name__ == "__main__":
    threading.Thread(target=send_heartbeat, daemon=True).start()
    threading.Thread(target=send_assets, daemon=True).start()
    while True:
        time.sleep(1)