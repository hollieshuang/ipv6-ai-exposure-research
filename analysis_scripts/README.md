# IPv6 AI Infrastructure Scanner

A comprehensive IPv6 AI service scanner using masscan and protocol-specific probing.

## Features

- Masscan-based IPv6 port scanning
- Ollama service detection and probing
- gRPC service detection
- Honeypot detection using entropy analysis
- SQLite database for results storage

## Installation

```bash
pip install -r requirements.txt

# Install masscan (required)
# Ubuntu/Debian:
sudo apt-get install masscan

# macOS:
brew install masscan

# Build from source:
git clone https://github.com/robertdavidgraham/masscan.git
cd masscan
make
sudo make install
```

## Quick Start

### Basic Scan

```bash
python masscan_ipv6_ai_scan.py \
  --target 2402:e740::/48 \
  --rate 22000 \
  --output scan_results.json
```

### Full Scan with Probing

```bash
python masscan_ipv6_ai_scan.py \
  --target 2402:e740::/32 \
  --rate 22000 \
  --probe-ollama \
  --probe-grpc \
  --output results.db
```

## Usage

### Command Line Options

```
usage: masscan_ipv6_ai_scan.py [-h] --target TARGET [--rate RATE]
                               [--output OUTPUT] [--format FORMAT]
                               [--probe-ollama] [--probe-grpc]
                               [--timeout TIMEOUT] [--retries RETRIES]

IPv6 AI Infrastructure Scanner

required arguments:
  --target TARGET     Target IPv6 prefix (e.g., 2402:e740::/48)

optional arguments:
  --rate RATE         Scan rate (packets/second, default: 22000)
  --output OUTPUT     Output file (default: ai_scan_results.json)
  --format FORMAT     Output format: json, csv, db (default: json)
  --probe-ollama      Enable Ollama service probing
  --probe-grpc        Enable gRPC service probing
  --timeout TIMEOUT   Connection timeout in seconds (default: 5)
  --retries RETRIES   Number of retries (default: 3)
  --exclude EXCLUDE   Exclude file (one IP per line)
```

### Scan Configuration

Create a configuration file `scan_config.conf`:

```json
{
  "target": "2402:e740::/32",
  "rate": 22000,
  "ports": "11434,7000,50051,8000,7860,8501,8888,18789,18798,28789,56767",
  "timeout": 5,
  "retries": 3
}
```

Run with config:

```bash
python masscan_ipv6_ai_scan.py --config scan_config.conf
```

## Output

### JSON Output

```json
{
  "scan_info": {
    "target": "2402:e740::/48",
    "start_time": "2026-07-20T12:00:00",
    "end_time": "2026-07-20T12:15:00",
    "rate": 22000
  },
  "results": [
    {
      "ip": "2402:e740:1:1004::5",
      "port": 11434,
      "service": "ollama",
      "timestamp": "2026-07-20T12:10:00",
      "banner": "Ollama version 0.17.5",
      "risk_level": "HIGH"
    }
  ],
  "summary": {
    "total_hosts": 150,
    "ai_services": {
      "ollama": 4,
      "grpc": 30,
      "ai_web": 1067
    }
  }
}
```

### SQLite Database

```bash
# Query results
sqlite3 ai_scan_results.db "SELECT * FROM ollama_hosts"

# Export to CSV
sqlite3 ai_scan_results.db ".mode csv" ".output results.csv" "SELECT * FROM hosts"
```

## Advanced Usage

### Continuous Monitoring

```bash
# Run as a service
nohup python masscan_ipv6_ai_scan.py \
  --target 2402:e740::/32 \
  --rate 22000 \
  --output /var/log/ai_scan/results.db \
  --daemon &

# Check results
watch -n 60 "sqlite3 /var/log/ai_scan/results.db 'SELECT COUNT(*) FROM hosts'"
```

### Honeypot Detection

```bash
python honeypot_detector.py \
  --data ai_scan_results.db \
  --threshold 0.9 \
  --output honeypot_report.json
```

### Trend Analysis

```bash
python trend_analyzer.py \
  --database ai_scan_results.db \
  --period daily \
  --output trend_report.json
```

## Ethical Considerations

⚠️ **IMPORTANT**: Only scan networks you have authorization to scan.

- This tool is for authorized security research only
- Unauthorized scanning may be illegal
- Follow responsible disclosure practices
- Respect network bandwidth and resources

## Troubleshooting

### masscan not found

```bash
# Add to PATH
export PATH=$PATH:/usr/local/bin

# Or install
sudo make install
```

### Permission denied

```bash
# Run as root (required for raw sockets)
sudo python masscan_ipv6_ai_scan.py ...
```

### Slow scanning

```bash
# Increase rate (may be blocked by firewall)
--rate 50000

# Or decrease for better accuracy
--rate 10000
```

## License

MIT License - see LICENSE file for details.
