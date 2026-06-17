# ForensicLogX — Ubuntu Agent Deployment & Setup Guide

This guide provides the complete setup commands and configurations required to deploy the ForensicLogX Agent on the Ubuntu Server running DVWA.

---

## 1. Prerequisites & Required Packages

The agent is designed to run with **zero external Python package dependencies** (utilizing standard library modules `threading`, `sqlite3`, `socket`, `urllib.request`, and `/proc` system stats). This ensures high reliability and quick setup.

Make sure Python 3 is installed on the target Ubuntu system:
```bash
sudo apt update
sudo apt install -y python3 python3-pip
```

---

## 2. File & Log Permissions

To allow the agent to read administrative logs (like `/var/log/auth.log` or `/var/log/syslog`) and web logs, the agent service runs as the `root` user or a user in the `adm` group.

Verify that the target log files exist and have appropriate read permissions:
```bash
# Ensure log files exist
sudo touch /var/log/apache2/access.log /var/log/apache2/error.log
sudo touch /var/log/modsec_audit.log
sudo touch /var/log/auth.log /var/log/syslog

# Ensure proper ownership and permissions
sudo chmod 640 /var/log/apache2/access.log /var/log/apache2/error.log
sudo chmod 640 /var/log/modsec_audit.log
sudo chmod 640 /var/log/auth.log /var/log/syslog
```

---

## 3. Deployment Directory Setup

1. Create a directory for the agent on the DVWA server (e.g., `/opt/web-analyzer-agent`):
   ```bash
   sudo mkdir -p /opt/web-analyzer-agent
   ```
2. Copy [agent.py](file:///e:/ForensicLogX/agent.py) and [agent.conf](file:///e:/ForensicLogX/agent.conf) from this analyzer project workspace to the target directory `/opt/web-analyzer-agent/`.
3. Configure the backend ForensicLogX server IP address in `/opt/web-analyzer-agent/agent.conf`:
   ```ini
   [server]
   server_url=http://<YOUR_ANALYZER_IP>:5000
   ```

---

## 4. Systemd Service Setup

To run the agent in the background as a continuous Linux systemd service that automatically starts on boot and restarts on failures:

1. Create the systemd service file:
   ```bash
   sudo nano /etc/systemd/system/web-analyzer-agent.service
   ```
2. Paste the following configuration:
   ```ini
   [Unit]
   Description=ForensicLogX Web Analyzer Agent
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/web-analyzer-agent
   ExecStart=/usr/bin/python3 agent.py
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
3. Reload systemd, enable the service to run on boot, and start it:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable web-analyzer-agent
   sudo systemctl start web-analyzer-agent
   ```

### 5. Managing the Service

Use the standard systemctl commands to manage the agent:
```bash
# Start the agent
sudo systemctl start web-analyzer-agent

# Stop the agent
sudo systemctl stop web-analyzer-agent

# Restart the agent
sudo systemctl restart web-analyzer-agent

# Check service status and logs
sudo systemctl status web-analyzer-agent
```

---

## 6. Verification and Troubleshooting

### Verify logs are being read & sent:
Check the systemd logs to confirm active log tailing:
```bash
sudo journalctl -u web-analyzer-agent.service -f -n 50
```
A successful connection and forwarding output will look like this:
```text
[AGENT] Loading configuration from agent.conf
[AGENT] Sender pipeline thread active.
[AGENT] Heartbeat reporter thread active.
[AGENT] Started tailing thread for /var/log/apache2/access.log (apache_access)
[AGENT] Started tailing thread for /var/log/modsec_audit.log (modsec_audit)
...
[AGENT] Forwarded 5 logs to analyzer.
```

### Verify database records:
Check that logs are populating the central analyzer's database:
```bash
sqlite3 dataset/crs_rules.db "SELECT * FROM raw_logs ORDER BY id DESC LIMIT 5;"
```
