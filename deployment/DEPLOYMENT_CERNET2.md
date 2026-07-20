# CERNET2 Measurement Node Deployment Guide

This guide explains how to deploy the IPv6 AI infrastructure scanner on a CERNET2-connected server.

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Disk | 100 GB | 500 GB SSD |
| Network | IPv6 | Dual-stack IPv4/IPv6 |
| Bandwidth | 100 Mbps | 1 Gbps |

### Software Requirements

- Linux (Ubuntu 20.04+ or CentOS 8+)
- Python 3.9+
- masscan 1.3.9+
- SQLite 3
- Root/sudo access

### Network Requirements

- CERNET2 IPv6 connectivity
- Outbound TCP/UDP to ports: 11434, 7000, 50051, 8000, 7860, 8501, 8888, 18789, 18798, 28789, 56767
- Sufficient bandwidth for scanning (recommended: dedicated 100 Mbps)

## Installation

### 1. System Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip masscan sqlite3 git

# Install Python packages
pip3 install -r requirements.txt
```

### 2. Directory Structure

```bash
# Create directory structure
sudo mkdir -p /opt/ai-scanner/{logs,data,results}
sudo chown -R $USER:$USER /opt/ai-scanner

# Link repository
ln -s /path/to/repo /opt/ai-scanner/repo
```

### 3. Configure masscan

```bash
# Copy configuration
sudo cp /opt/ai-scanner/repo/deployment/scan_config.conf /etc/masscan/

# Edit configuration
sudo nano /etc/masscan/masscan.conf
```

Recommended configuration (`/etc/masscan/masscan.conf`):

```
# Interface
interface = ens192

# Rate
rate = 22000

# IPv6 mode
#adapter-ip = 2402:e740::666
#adapter-port = 0
#adapter-mac = 00:11:22:33:44:55

# Ports to scan
ports = 11434,7000,50051,8000,7860,8501,8888,18789,18798,28789,56767

# Output
output-format = json
output-filename = /opt/ai-scanner/results/scan_%date%.json

# Performance
wait = 5
retries = 3

# Logging
verbose = 0
```

### 4. Test Connectivity

```bash
# Test IPv6 connectivity
ping6 -c 3 2402:e740::1

# Test masscan
sudo masscan -p 80 -6 2402:e740::1 --rate 1000
```

## Deployment

### Automated Scanning

#### Daily Scan Script

Create `/opt/ai-scanner/daily_scan.sh`:

```bash
#!/bin/bash

# Configuration
LOG_DIR="/opt/ai-scanner/logs"
DATA_DIR="/opt/ai-scanner/data"
RESULTS_DIR="/opt/ai-scanner/results"
DATE=$(date +%Y%m%d)

# Create log file
LOG_FILE="$LOG_DIR/scan_$DATE.log"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

log "Starting daily scan"

# Run masscan
sudo masscan \
    --conf /etc/masscan/masscan.conf \
    --rate 22000 \
    -oJ "$RESULTS_DIR/scan_$DATE.json" \
    2>> $LOG_FILE

# Process results
python3 /opt/ai-scanner/repo/analysis_scripts/process_results.py \
    --input "$RESULTS_DIR/scan_$DATE.json" \
    --output "$DATA_DIR/processed_$DATE.db"

# Update honeypot detection
python3 /opt/ai-scanner/repo/analysis_scripts/honeypot_detector.py \
    --data "$DATA_DIR/processed_$DATE.db" \
    --output "$DATA_DIR/honeypot_$DATE.json"

# Update trends
python3 /opt/ai-scanner/repo/analysis_scripts/trend_analyzer.py \
    --database "$DATA_DIR/"*.db \
    --output "$DATA_DIR/trends.json"

log "Daily scan complete"
```

Make executable:

```bash
chmod +x /opt/ai-scanner/daily_scan.sh
```

#### Cron Job

Add to crontab (`sudo crontab -e`):

```cron
# Daily scan at 2 AM
0 2 * * * /opt/ai-scanner/daily_scan.sh >> /opt/ai-scanner/logs/cron.log 2>&1

# Weekly report every Monday at 8 AM
0 8 * * 1 /opt/ai-scanner/repo/analysis_scripts/weekly_report.py >> /opt/ai-scanner/logs/weekly.log 2>&1
```

### Manual Scanning

```bash
# Scan specific prefix
sudo masscan -p 11434,50051,8000 -6 2402:e740::/48 --rate 22000 -oJ results.json

# Scan with custom configuration
sudo masscan --conf /path/to/config.conf 2402:e740::/32 -oJ output.json
```

## Monitoring

### Check Scan Status

```bash
# Check running scans
ps aux | grep masscan

# Check masscan status
sudo cat /var/lib/masscan/status.json
```

### View Logs

```bash
# Recent logs
tail -f /opt/ai-scanner/logs/scan_*.log

# Error logs
grep ERROR /opt/ai-scanner/logs/*.log
```

### Database Queries

```bash
# View recent discoveries
sqlite3 /opt/ai-scanner/data/processed.db "SELECT * FROM hosts ORDER BY timestamp DESC LIMIT 10"

# Count by service
sqlite3 /opt/ai-scanner/data/processed.db "SELECT service, COUNT(*) FROM hosts GROUP BY service"

# View trends
sqlite3 /opt/ai-scanner/data/processed.db "SELECT * FROM trends ORDER BY timestamp DESC"
```

## Troubleshooting

### masscan Permission Denied

```bash
# Check capabilities
getcap /usr/sbin/masscan

# Set capabilities (if needed)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/masscan
```

### Slow Scanning

```bash
# Check network latency
ping6 -c 10 target_ipv6

# Adjust rate
sudo masscan --rate 10000 ...

# Check system load
top
```

### Out of Memory

```bash
# Increase swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Security Considerations

### Firewall Rules

```bash
# Allow outbound scan traffic
sudo iptables -A OUTPUT -p tcp -m multiport --dports 11434,7000,50051,8000,7860,8501,8888,18789,18798,28789,56767 -j ACCEPT

# Rate limit (optional)
sudo iptables -A OUTPUT -p tcp -m multiport --dports 11434,7000,50051 -m limit --limit 100/s -j ACCEPT
```

### Authentication

- Secure SSH access with key-based authentication
- Use sudo for privileged operations only
- Enable audit logging

## Support

For issues, please open a GitHub issue or contact the research team.
