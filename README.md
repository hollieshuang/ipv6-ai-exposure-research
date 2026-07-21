# IPv6 AI Infrastructure Exposure Measurement

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Python-3.9+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/Research-IPv6%20Security-orange.svg" alt="Research">
</p>

> **⚠️ Disclaimer**: This research was conducted ethically. All scans were performed on authorized infrastructure (CERNET2) with proper permissions. No personal data was collected. See [ethics statement](#ethics-statement) for details.

---

## 📖 Overview

This repository contains the **first systematic measurement** of IPv6 AI infrastructure exposure, including detection rules, analysis scripts, and datasets from our research published .

## 🎯 Quick Start

### 1. Install Dependencies

```bash
# Clone the repository
git clone https://github.com/[your-username]/ipv6-ai-exposure-research.git
cd ipv6-ai-exposure-research

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Run Detection Rules

```bash
# For Snort
sudo snort -c detection_rules/snort_ai_exposure.rules -i eth0

# For Suricata
sudo suricata -c detection_rules/ -i eth0

# For Zeek
zeek -C -b detection_rules/zeek/ai_banner_extract.zeek -i eth0
```

### 3. Analyze Your Network

```bash
# Scan IPv6 addresses for AI service exposure
python analysis_scripts/masscan_ipv6_ai_scan.py --target 2402:e740::/64

# Probe Ollama services
python analysis_scripts/ollama_probe.py --input exposed_hosts.txt

# Detect honeypots
python analysis_scripts/honeypot_detector.py --data scan_results.db
```

---

## 📂 Repository Structure

```
ipv6-ai-exposure-research/
├── README.md                     # This file
├── LICENSE                       # MIT License
├── CITATION.cff                 # Citation file
├── requirements.txt             # Python dependencies
│
├── detection_rules/              # 🚨 IDS Detection Rules
│   ├── README.md                # Usage guide
│   ├── snort_ai_exposure.rules  # 17 Snort/Suricata rules
│   └── zeek/                    # Zeek scripts
│       ├── ai_banner_extract.zeek    # Banner extraction
│       └── ai_exposure_tracker.zeek  # Exposure tracking
│
├── analysis_scripts/            # 🔍 Analysis Tools
│   ├── masscan_ipv6_ai_scan.py       # IPv6 AI service scanner
│   ├── ollama_probe.py                # Ollama service probe
│   ├── grpc_probe.py                  # gRPC service probe
│   ├── honeypot_detector.py           # Honeypot detection
│   ├── trend_analyzer.py              # Trend analysis
│   └── requirements.txt               # Script dependencies
│
├── deployment/                  # 📦 Deployment Guides
│   ├── DEPLOYMENT_CERNET2.md   # CERNET2 measurement node
│   ├── scan_config.conf         # masscan configuration
│   └── bandwidth_control.sh     # Bandwidth management
│
├── data/                        # 📊 Datasets (Anonymized)
│   ├── README.md                # Data documentation
│   ├── cernet2_baseline.json    # CERNET2 exposure baseline
│   ├── longitudinal_tracking.json # Time-series analysis
│   └── honeypot_analysis.json   # Honeypot detection results
│
└── docs/                        # 📚 Documentation
    ├── architecture.md          # System architecture
    ├── ethic_statement.md       # Ethics statement
    └── troubleshooting.md        # Troubleshooting guide
```

---

## 🛡️ Detection Rules

### Snort/Suricata Rules (17 rules)

| SID | Service | Detection | Severity |
|-----|---------|----------|----------|
| 000001 | Ollama | Model enumeration (/api/tags) | HIGH |
………………
| 000017 | Generic | IPv6 AI scanning pattern | MEDIUM |

### Zeek Scripts

#### ai_banner_extract.zeek
Extracts AI service banners from network traffic:
- Identifies Ollama, gRPC, vLLM, OpenClaw services
- Extracts version information and model lists
- Assesses risk level automatically

#### ai_exposure_tracker.zeek
Tracks AI service exposure over time:
- Cross-snapshot persistence analysis
- Exposure duration calculation
- Trend report generation

---

## 🔬 Analysis Scripts

### masscan_ipv6_ai_scan.py

IPv6 AI service scanner using masscan:

```bash
python analysis_scripts/masscan_ipv6_ai_scan.py \
  --target 2402:e740::/48 \
  --rate 20000 \
  --output scan_results.json
```

### ollama_probe.py

Probe Ollama services for vulnerabilities:

```bash
python analysis_scripts/ollama_probe.py \
  --input exposed_hosts.txt \
  --output vulnerability_report.json
```

### honeypot_detector.py

Detect honeypot networks using entropy analysis:

```bash
python analysis_scripts/honeypot_detector.py \
  --data scan_results.db \
  --threshold 0.9
```

## 🛠️ Deployment

### Measurement Node

See [DEPLOYMENT_CERNET2.md](deployment/DEPLOYMENT_CERNET2.md) for detailed instructions.

**Requirements:**
- Linux server with IPv6 connectivity
- CERNET2 network access
- Python 3.9+
- masscan v1.3.9+

**Quick Setup:**
```bash
# Clone configuration
cp deployment/scan_config.conf.example scan_config.conf

# Edit configuration
vim scan_config.conf

# Start scanner
python analysis_scripts/masscan_ipv6_ai_scan.py --config scan_config.conf
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Detection Rules Guide](detection_rules/README.md) | How to deploy IDS rules |
| [Analysis Scripts Guide](analysis_scripts/README.md) | How to use analysis tools |
| [Deployment Guide](deployment/DEPLOYMENT_CERNET2.md) | CERNET2 measurement setup |
| [Architecture](docs/architecture.md) | System architecture overview |
| [Ethics Statement](docs/ethics_statement.md) | Research ethics |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**Code**: MIT License  
**Data**: CC BY 4.0

---

## ⚠️ Ethics Statement

This research was conducted following responsible security research practices:

1. **Authorized Scanning**: All scans were performed on authorized infrastructure (CERNET2) with proper permissions
2. **No Personal Data**: No personal information was collected or stored
3. **Vulnerability Disclosure**: Identified vulnerabilities were reported through appropriate channels
4. **Data Minimization**: Only necessary data was collected and retained
5. **Academic Purpose**: Research conducted for academic and defensive purposes only

See [Ethics Statement](docs/ethics_statement.md) for full details.

---

## 📧 Contact

**Research Team**: IPv6 AI Exposure Measurement Group

For questions about the research, please refer to the paper or open an issue.

---

<p align="center">
  <sub>Part of the IPv6 AI Security Research Initiative</sub>
</p>
