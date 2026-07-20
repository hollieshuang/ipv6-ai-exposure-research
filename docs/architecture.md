# System Architecture

## Overview

The IPv6 AI Infrastructure Exposure Measurement System consists of four main components:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Measurement Layer                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   masscan   │  │    nmap     │  │  Protocol   │           │
│  │   Scanner   │  │   Prober    │  │   Probers   │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Data Processing Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Honeypot   │  │   Trend     │  │  Anomaly    │           │
│  │  Detector   │  │  Analyzer   │  │  Detector   │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Storage Layer                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   SQLite    │  │    JSON     │  │   SQLite    │           │
│  │   DB        │  │   Reports   │  │   Time-Series│          │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Detection & Alerting Layer                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Snort     │  │    Zeek    │  │   Alert    │           │
│  │   Rules    │  │   Scripts   │  │  System    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Measurement Layer

#### masscan Scanner
- **Purpose**: Large-scale IPv6 port scanning
- **Technology**: Custom TCP SYN scanning with IPv6 support
- **Rate**: Up to 22,000 packets/second
- **Ports**: AI service ports (11434, 50051, 8000, etc.)
- **Output**: JSON format with IP, port, protocol, timestamp

#### Protocol Probers
- **Ollama Probe**: HTTP-based API probing for model enumeration
- **gRPC Probe**: HTTP/2 connection detection
- **vLLM Probe**: OpenAI-compatible API probing

### 2. Data Processing Layer

#### Honeypot Detector
- **Algorithm**: Port exposure entropy analysis
- **Threshold**: H > 0.9 (normalized entropy)
- **Output**: Honeypot classification with confidence score

#### Trend Analyzer
- **Purpose**: Longitudinal exposure trend analysis
- **Metrics**: Persistence rate, growth rate, stability score
- **Period**: Daily, weekly, monthly aggregations

#### Anomaly Detector
- **Purpose**: Identify unusual exposure patterns
- **Methods**: Statistical analysis, pattern matching
- **Output**: Anomaly alerts with severity levels

### 3. Storage Layer

#### SQLite Database
- **Schema**: Normalized relational design
- **Tables**: hosts, ports, services, snapshots, alerts
- **Indexes**: Performance optimized for time-series queries

#### Time-Series Database
- **Purpose**: Historical trend storage
- **Operations**: Downsampling, aggregation, retention policies
- **Retention**: 30-day detailed, 1-year summarized

### 4. Detection Layer

#### Snort/Suricata Rules
- **Coverage**: 17 detection rules
- **Categories**: Ollama, gRPC, vLLM, OpenClaw, generic scanning
- **Format**: Compatible with Snort 2.9.x+ and Suricata 6.x+

#### Zeek Scripts
- **ai_banner_extract.zeek**: Real-time banner extraction
- **ai_exposure_tracker.zeek**: Longitudinal tracking

#### Alert System
- **Channels**: Email, Slack, webhook
- **Thresholds**: Configurable severity levels
- **Aggregation**: Alert deduplication and correlation

## Data Flow

```
1. SCAN
   User → Scanner → masscan → Results (JSON)

2. PROCESS
   JSON → Parser → Validator → SQLite DB

3. ANALYZE
   SQLite → Analyzer → Trends → Reports

4. DETECT
   Network Traffic → IDS → Alerts

5. ALERT
   Alerts → Aggregator → Channel → User
```

## API Reference

### Scanner API

```python
from scanner import IPv6AIScanner

scanner = IPv6AIScanner(target="2402:e740::/48")
results = scanner.scan()
```

### Analyzer API

```python
from analyzer import HoneypotDetector

detector = HoneypotDetector(threshold=0.9)
result = detector.analyze(data)
```

### Database API

```python
from database import ExposureDB

db = ExposureDB("results.db")
hosts = db.get_hosts_by_service("ollama")
```

## Deployment Modes

### Standalone Mode
- Single server deployment
- All components on one machine
- Suitable for small-scale scanning

### Distributed Mode
- Multiple scanner nodes
- Centralized data processing
- Suitable for large-scale scanning

### Hybrid Mode
- On-premises scanning
- Cloud-based analysis
- Optimal for institutional deployment

## Performance Characteristics

| Operation | Throughput | Latency |
|-----------|------------|---------|
| masscan scan | 22,000 pps | N/A |
| Port processing | 10,000/sec | <10ms |
| DB writes | 1,000/sec | <5ms |
| Honeypot detection | 1,000/sec | <50ms |
| Alert generation | 100/sec | <100ms |

## Scalability

### Horizontal Scaling
- Add scanner nodes for more throughput
- Load balance scan targets
- Aggregate results centrally

### Vertical Scaling
- Increase network bandwidth
- Add more CPU cores
- Expand storage capacity

## Security Considerations

### Network Security
- Firewall rules for scanner nodes
- Encrypted communication
- Access control lists

### Data Security
- Encrypted storage
- Access logging
- Backup policies

### System Security
- Regular security updates
- Hardened configuration
- Intrusion detection
