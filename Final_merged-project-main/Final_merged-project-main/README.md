# 🖥️ Agent Download Dashboard

A Flask-based web application for managing and monitoring agent downloads across multiple operating systems.  
It provides an admin dashboard showing download logs, client hostnames, OS type, and live heartbeat status.

---

## 🚀 Features
- **Multi-OS Downloads** – Windows, Ubuntu, and Mac agent installers.
- **Hostname Logging** – Reverse DNS lookup to record client machine names.
- **Download Tracking** – Logs date/time, IP, hostname, and OS.
- **Heartbeat Monitoring** – Tracks if agents are currently active.
- **Admin Dashboard** – Displays:
  - Total downloads
  - Unique IP count
  - Latest download timestamp
  - Download history with OS badges and active/inactive status
- **Auto Refresh** – Configurable refresh rate for the dashboard.
- **Secure Access** – Basic admin login system.

---

## 📂 Project Structure
Agent-Download-Dashboard/
│
├── app.py # Main Flask application
├── files/ # Agent installer files
├── logs/
│ ├── downloads.log # Download history
│ ├── heartbeats.log # Agent heartbeat pings
├── templates/
│ ├── login.html
│ ├── dashboard.html
│ ├── server_dashboard.html
└── static/ # (Optional) CSS/JS assets

yaml
Copy code

---

## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/your-username/agent-download-dashboard.git
cd agent-download-dashboard
2️⃣ Create a virtual environment
bash
Copy code
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
3️⃣ Install dependencies
bash
Copy code
pip install flask
4️⃣ Add agent files
Place your agent installers in the files/ folder and name them according to ALLOWED in app.py:

python
Copy code
ALLOWED = {
    "windows": "agent_api.exe",
    "ubuntu": "ubuntu_agent.sh",
    "mac": "mac_agent.pkg"
}
▶️ Running the App
bash
Copy code
python app.py
The app will start on:

arduino
Copy code
http://localhost:8000
🔑 Default Login
plaintext
Copy code
Username: admin
Password: password123
(Change in USER_CREDENTIALS inside app.py)

📜 Log Format
downloads.log
pgsql
Copy code
2025-08-12T14:29:38.858712 | 192.168.1.9 | LAPTOP-HLLIF94A.domain.name | windows
Format:

lua
Copy code
datetime | ip_address | hostname | os
heartbeats.log
makefile
Copy code
2025-08-12T14:30:00.590042 | 192.168.1.9
Format:

nginx
Copy code
datetime | ip_address
🌟 Customization
Auto Refresh Rate
Edit server_dashboard.html:

html
Copy code
<meta http-equiv="refresh" content="60" />
(Value is in seconds)

OS Logos
Replace emoji placeholders with SVG/PNG logos in dashboard.html.

🛡️ Security Note
This is a basic prototype and does not include advanced authentication, encryption, or role-based access control.
Do not use in production without securing it.

