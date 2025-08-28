# app.py
import hashlib
import os
import secrets
import socket
import subprocess
from datetime import datetime, timedelta
from typing import Optional

import psycopg2
import requests
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)
from psycopg2.extras import Json, RealDictCursor

# --------------------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Make sure folders exist
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

HEARTBEAT_LOG_FILE = os.path.join(LOGS_DIR, "heartbeats.log")

# Agents to poll for asset reports (these are the client agents' /report endpoints)
agent_ips = [
    "http://192.168.1.20:9000/report",
    # Add more agent report URLs here
]

# Downloads allowed (used by /get_link and /downloads/<file>)
ALLOWED = {
    "windows": "agent_api.exe",
    "ubuntu": "ubuntu_agent.sh",
    "mac": "mac_agent.pkg",
}

# Simple demo credentials
USER_CREDENTIALS = {
    "admin": "password123"
}

TOKENS = {}

# PostgreSQL connection config
DB_CONFIG = {
    "dbname": "assetdb",
    "user": "postgres",
    "password": "mohee78692",
    "host": "localhost",
    "port": 5432,
}

# Active status threshold for heartbeats
ACTIVE_THRESHOLD_SECONDS = 10

# --------------------------------------------------------------------------------------
# DB HELPERS
# --------------------------------------------------------------------------------------
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    """Create required tables if they don't exist."""
    conn = get_db_connection()
    cur = conn.cursor()

    # downloads table (one row per IP, updated on new download)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS downloads (
            id SERIAL PRIMARY KEY,
            download_time TIMESTAMP NOT NULL DEFAULT NOW(),
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            os_name TEXT
        );
    """)

    # assets table (one row per hostname; latest details kept)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            hostname TEXT PRIMARY KEY,
            username TEXT,
            os TEXT,
            os_version TEXT,
            cpu TEXT,
            memory_gb DOUBLE PRECISION,
            disk_gb DOUBLE PRECISION,
            uptime_seconds BIGINT,
            ip_addresses TEXT,
            open_ports JSONB,
            software TEXT,
            vmware_vms JSONB,
            ip_reporter TEXT,
            collected_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    conn.commit()
    cur.close()
    conn.close()

   
# --------------------------------------------------------------------------------------
# UTILS
# --------------------------------------------------------------------------------------
def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# THIS IS THE NEW, CORRECTED CODE
# THIS IS THE NEW, CORRECTED CODE
def log_download(os_name: str, ip: str):
    """Insert or update the download log for a given IP and OS combination."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        hostname = "Unknown"

    conn = get_db_connection()
    cur = conn.cursor()
    # This query now updates the timestamp on a conflict of BOTH ip_address AND os_name
    cur.execute("""
        INSERT INTO downloads (download_time, ip_address, hostname, os_name)
        VALUES (NOW(), %s, %s, %s)
        ON CONFLICT (ip_address, os_name)
        DO UPDATE SET
            download_time = EXCLUDED.download_time,
            hostname = EXCLUDED.hostname
    """, (ip, hostname, os_name))
    conn.commit()
    cur.close()
    conn.close()

def flatten_agent_payload(data: dict) -> dict:
    """Normalize the agent JSON into the schema we store in `assets`."""
    return {
        "hostname": data.get("hostname", ""),
        "username": data.get("username", ""),
        "os": data.get("os", ""),
        "os_version": data.get("os_version", ""),
        "cpu": data.get("cpu", ""),
        "memory_gb": data.get("memory_gb") or data.get("ram") or data.get("memory"),
        "disk_gb": data.get("disk_gb") or data.get("hdd") or data.get("disk"),
        "uptime_seconds": data.get("uptime_seconds", 0),
        "ip_addresses": ", ".join(data.get("ip_addresses", [])),
        "software": ", ".join(data.get("software", [])),
        "open_ports_json": data.get("open_ports", []),
        "vmware_vms_json": data.get("vmware_vms", []),
    }

def upsert_asset_record(flat: dict, reporter_ip: Optional[str] = None):
    """Insert/update latest info for a hostname into `assets`."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO assets (
            hostname, username, os, os_version, cpu,
            memory_gb, disk_gb, uptime_seconds, ip_addresses,
            open_ports, software, vmware_vms, ip_reporter, collected_at
        )
        VALUES (
            %(hostname)s, %(username)s, %(os)s, %(os_version)s, %(cpu)s,
            %(memory_gb)s, %(disk_gb)s, %(uptime_seconds)s, %(ip_addresses)s,
            %(open_ports)s, %(software)s, %(vmware_vms)s, %(ip_reporter)s, NOW()
        )
        ON CONFLICT (hostname) DO UPDATE SET
            username = EXCLUDED.username,
            os = EXCLUDED.os,
            os_version = EXCLUDED.os_version,
            cpu = EXCLUDED.cpu,
            memory_gb = EXCLUDED.memory_gb,
            disk_gb = EXCLUDED.disk_gb,
            uptime_seconds = EXCLUDED.uptime_seconds,
            ip_addresses = EXCLUDED.ip_addresses,
            open_ports = EXCLUDED.open_ports,
            software = EXCLUDED.software,
            vmware_vms = EXCLUDED.vmware_vms,
            ip_reporter = EXCLUDED.ip_reporter,
            collected_at = NOW();
    """, {
        "hostname": flat.get("hostname"),
        "username": flat.get("username"),
        "os": flat.get("os"),
        "os_version": flat.get("os_version"),
        "cpu": flat.get("cpu"),
        "memory_gb": flat.get("memory_gb"),
        "disk_gb": flat.get("disk_gb"),
        "uptime_seconds": flat.get("uptime_seconds"),
        "ip_addresses": flat.get("ip_addresses"),
        "open_ports": Json(flat.get("open_ports_json", [])),
        "software": flat.get("software"),
        "vmware_vms": Json(flat.get("vmware_vms_json", [])),
        "ip_reporter": reporter_ip,
    })
    conn.commit()
    cur.close()
    conn.close()

# --------------------------------------------------------------------------------------
# AUTH & BASIC PAGES
# --------------------------------------------------------------------------------------
@app.route("/")
def home():
    if "user" in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if USER_CREDENTIALS.get(username) == password:
        session["user"] = username
        return redirect("/dashboard")
    return render_template("login.html", error="Invalid credentials")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT hostname, username, os, os_version, cpu, memory_gb, disk_gb,
               uptime_seconds, ip_addresses, collected_at
        FROM assets
        ORDER BY hostname ASC;
    """)
    assets = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("dashboard.html", assets=assets)

# --------------------------------------------------------------------------------------
# DOWNLOAD LINKS + CHECKSUM
# --------------------------------------------------------------------------------------
@app.route("/get_link/<os_name>")
def get_link(os_name):
    if "user" not in session:
        abort(403)
    if os_name not in ALLOWED:
        abort(404)

    filename = ALLOWED[os_name]
    path = os.path.join(FILES_DIR, filename)
    if not os.path.exists(path):
        abort(404)

    token = secrets.token_hex(8)
    TOKENS[token] = filename

    download_url = url_for("download_file", filename=filename, token=token, _external=True)
    checksum = sha256_of_file(path)
    return jsonify({"url": download_url, "sha256": checksum})

@app.route("/downloads/<path:filename>")
def download_file(filename):
    token = request.args.get("token")
    if not token or TOKENS.get(token) != filename:
        abort(403, "Invalid or missing token")

    os_name = next((os for os, file in ALLOWED.items() if file == filename), "unknown")
    ip_address = request.remote_addr
    log_download(os_name, ip_address)

    TOKENS.pop(token, None)
    return send_from_directory(FILES_DIR, filename, as_attachment=True)

# --------------------------------------------------------------------------------------
# HEARTBEAT ENDPOINT
# --------------------------------------------------------------------------------------
# THIS IS THE NEW, CORRECTED HEARTBEAT ROUTE
# In app.py

@app.route("/agent_heartbeat", methods=["POST"])
def agent_heartbeat():
    ip_address = request.remote_addr
    data = request.get_json() or {}
    hostname = data.get("hostname", "Unknown")
    machine_type = data.get("machine_type", "Unknown")
    os_name = data.get("os_name")

    # Log to file with the new os_name field
    now = datetime.now().isoformat()
    with open(HEARTBEAT_LOG_FILE, "a") as f:
        # We now write 5 fields to the log for better tracking
        f.write(f"{now} | {ip_address} | {hostname} | {os_name} | {machine_type}\n")

    # Update the database
    if os_name:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE downloads
                SET machine_type = %s
                WHERE ip_address = %s AND os_name = %s
            """, (machine_type, ip_address, os_name))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"DB Update Error on heartbeat: {e}")

    return jsonify({"status": "heartbeat received"})

# --------------------------------------------------------------------------------------
# SERVER DASHBOARD (DOWNLOADS + HEARTBEATS)
# --------------------------------------------------------------------------------------
# In app.py

@app.route("/server_dashboard")
def server_dashboard():
    if "user" not in session:
        return redirect("/")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT download_time AS datetime,
               ip_address AS ip,
               hostname,
               os_name,
               machine_type
        FROM downloads
        ORDER BY download_time DESC;
    """)
    logs = cur.fetchall()
    conn.close()

    unique_ips = {log["ip"] for log in logs}
    latest_download_time = logs[0]["datetime"] if logs else None

    # Read heartbeats from file
    heartbeats = {} # This will now use a (ip, os_name) tuple as the key
    if os.path.exists(HEARTBEAT_LOG_FILE):
        with open(HEARTBEAT_LOG_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(" | ")
                # Check for our new 5-part log format
                if len(parts) == 5:
                    hb_time_str, ip, hostname, os_name, _ = parts
                    try:
                        hb_time = datetime.fromisoformat(hb_time_str)
                        # Create a unique key for each agent
                        agent_key = (ip, os_name)
                        # Store the latest heartbeat for that specific agent
                        if agent_key not in heartbeats or hb_time > heartbeats[agent_key]["time"]:
                            heartbeats[agent_key] = {"time": hb_time, "hostname": hostname}
                    except (ValueError, IndexError):
                        continue

    # Determine active/inactive status for each log entry individually
    now = datetime.now()
    active_threshold = timedelta(seconds=ACTIVE_THRESHOLD_SECONDS)

    for log in logs:
        # Create the key for the current log entry
        agent_key = (log["ip"], log["os_name"])
        last_hb = heartbeats.get(agent_key) # Look up the specific agent's heartbeat

        if last_hb:
            log["hostname"] = last_hb["hostname"]  # Use the correct hostname from the specific heartbeat
            diff = (now - last_hb["time"]).total_seconds()
            log["status"] = "Active" if diff <= active_threshold.total_seconds() else "Inactive"
        else:
            log["status"] = "Agent never started"

    return render_template(
        "server_dashboard.html",
        logs=logs,
        unique_ips=len(unique_ips),
        latest_download_time=latest_download_time.strftime('%Y-%m-%d %H:%M:%S') if latest_download_time else "N/A"
    )

# --------------------------------------------------------------------------------------
# ASSET GATHERING (POLL AGENTS + STORE IN POSTGRES)
# --------------------------------------------------------------------------------------
def poll_agent_report(report_url: str) -> Optional[dict]:
    try:
        r = requests.get(report_url, timeout=15)
        if r.status_code == 200:
            return r.json()
        print(f"[ERROR] Agent {report_url} returned status {r.status_code}")
    except Exception as e:
        print(f"[ERROR] Could not contact {report_url}: {e}")
    return None

@app.route("/gather_assets", methods=["POST"])
def gather_assets():
    if "user" not in session:
        return redirect("/")

    count_ok = 0
    for url in agent_ips:
        payload = poll_agent_report(url)
        print(f"Polled {url}, got:", payload)  # DEBUG

        if not payload:
            continue
        flat = flatten_agent_payload(payload)
        print("Flattened asset data:", flat)  # DEBUG

        payload = poll_agent_report(url)
        if not payload:
            continue
        flat = flatten_agent_payload(payload)

        # Reporter IP (the IP part of the URL host, handy to store)
        try:
            reporter_ip = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        except Exception:
            reporter_ip = None

        upsert_asset_record(flat, reporter_ip=reporter_ip)
        count_ok += 1

    # reload dashboard with fresh data
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT hostname, username, os, os_version, cpu, memory_gb, disk_gb,
               uptime_seconds, ip_addresses, collected_at
        FROM assets
        ORDER BY hostname ASC;
    """)
    assets = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        assets=assets,
        message=f"Assets gathered from {count_ok} agent(s)."
    )

# --------------------------------------------------------------------------------------
# NMAP SCAN (OPTIONAL)
# --------------------------------------------------------------------------------------
@app.route("/nmap_scan", methods=["POST"])
def nmap_scan():
    if "user" not in session:
        return redirect("/")

    subnet = request.form.get("subnet", "192.168.1.0/24")
    try:
        # -sn is the modern equivalent of -sP (ping scan)
        result = subprocess.check_output(["nmap", "-sn", subnet], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError as e:
        result = f"Error: {e.output.decode()}"

    # reload dashboard along with scan result
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT hostname, username, os, os_version, cpu, memory_gb, disk_gb,
               uptime_seconds, ip_addresses, collected_at
        FROM assets
        ORDER BY hostname ASC;
    """)
    assets = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("dashboard.html", assets=assets, scan_result=result)
@app.route("/agent_assets", methods=["POST"])
def agent_assets():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    flat = flatten_agent_payload(data)
    upsert_asset_record(flat, reporter_ip=request.remote_addr)
    print(f"[INFO] Asset data stored for {flat.get('hostname')}")
    return jsonify({"status": "asset stored"}), 200



# --------------------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------------------
if __name__ == "__main__":
    # Ensure DB is reachable and initialize tables
    try:
        conn = get_db_connection()
        conn.close()
        print("✅ Connected to PostgreSQL server!")
    except Exception as e:
        print("❌ Connection failed:", e)

    init_db()
    app.run(host="0.0.0.0", port=8000, debug=True)
