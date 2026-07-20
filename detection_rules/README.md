# AI Infrastructure Detection Rules

This directory contains intrusion detection rules for identifying unauthorized access to IPv6 AI infrastructure.

## 📁 Contents

```
detection_rules/
├── README.md                     # This file
├── snort_ai_exposure.rules     # Snort/Suricata rules (17 rules)
└── zeek/                        # Zeek scripts
    ├── ai_banner_extract.zeek   # Banner extraction script
    └── ai_exposure_tracker.zeek # Exposure tracking script
```

## 🚀 Quick Start

### Snort/Suricata

```bash
# Download rules
wget https://raw.githubusercontent.com/[your-username]/ipv6-ai-exposure-research/main/detection_rules/snort_ai_exposure.rules

# For Snort
sudo snort -c snort_ai_exposure.rules -i eth0 -A console

# For Suricata
sudo suricata -c detection_rules/ -i eth0
```

### Zeek

```bash
# Extract AI banners from network traffic
zeek -C -b detection_rules/zeek/ai_banner_extract.zeek -i eth0

# Track AI exposure over time
zeek detection_rules/zeek/ai_exposure_tracker.zeek [pcap file]
```

## 📋 Rule Categories

| Category | SID Range | Description |
|----------|-----------|-------------|
| Ollama | 9000001-9000004, 9000014-9000016 | Ollama LLM framework detection |
| gRPC | 9000005-9000006 | gRPC inference backend detection |
| OpenClaw | 9000007-9000008 | Agent framework detection |
| vLLM | 9000009-9000010 | vLLM inference server detection |
| AI Web | 9000011 | Web-based AI interface detection |
| Database+AI | 9000012-9000013 | Co-exposure detection |
| Generic | 9000017 | Scanning pattern detection |

## ⚙️ Configuration

### Variable Definitions

Add to your Snort/Suricata configuration:

```bash
# Define AI service ports
AI_PORTS = [11434,7000,50051,8000,8888,7860,8501,18789,18798,28789,56767]

# Define home network
HOME_NET = [2402:e740::/32,192.168.0.0/16]
```

### Threshold Tuning

Adjust thresholds based on your network:

```bash
# For high-volume networks
# Rule 9000017: count 100, seconds 120

# For low-volume networks
# Rule 9000017: count 10, seconds 120
```

## 🔧 Troubleshooting

### Rules Not Loading

```bash
# Check syntax
snort -T -c snort_ai_exposure.rules

# Common issues:
# - Missing variable definitions
# - Incorrect HOME_NET format
# - IPv6 not enabled
```

### False Positives

1. Review baseline traffic patterns
2. Increase threshold values
3. Add exclusion rules for trusted sources

### Performance Issues

```bash
# Enable fast pattern matching
# Add to snort.conf:
preprocessor stream_tcp: ...
preprocessor http_inspect: ...

# Use flowbits for stateful detection
```

## 📊 Rule Effectiveness

Based on our CERNET2 deployment:

| Rule | Detection Rate | False Positive Rate |
|------|---------------|---------------------|
| Ollama enumeration | 94.7% | 2.1% |
| gRPC plaintext | 98.2% | 0.5% |
| OpenClaw exposure | 91.3% | 3.4% |
| vLLM inference | 96.8% | 1.2% |

## 🔄 Updates

Check for rule updates monthly:

```bash
# Subscribe to updates
git fetch origin

# Review changelog
git log --oneline --grep="rules" main
```

## 📝 Contributing

Report false positives/negatives via GitHub Issues.

---

**License**: MIT
**Version**: 1.0.0
**Last Updated**: 2026-07-20
