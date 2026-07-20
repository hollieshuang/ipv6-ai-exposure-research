# Data Documentation

This directory contains anonymized datasets from our IPv6 AI infrastructure exposure research.

## ⚠️ Privacy Notice

All data has been anonymized to protect privacy:

- IP addresses are partially redacted (prefix preserved)
- No personal information is included
- Sensitive banners have been removed or sanitized

## Files

| File | Description | Size |
|------|-------------|------|
| `cernet2_baseline.json` | CERNET2 exposure baseline | ~2KB |
| `longitudinal_tracking.json` | Time-series analysis | ~9KB |
| `honeypot_analysis.json` | Honeypot detection results | ~5KB |

## Data Format

### cernet2_baseline.json

```json
{
  "snapshot_date": "2026-07-18",
  "scope": {
    "total_scanned": 530000,
    "unique_ips": 1347,
    "total_ai_ports": 1139
  },
  "services": {
    "ollama": {
      "count": 4,
      "ports": [11434]
    },
    "grpc": {
      "count": 30,
      "ports": [50051]
    },
    "ai_web": {
      "count": 1067,
      "ports": [5000]
    }
  },
  "risk_assessment": {
    "high_risk": 4,
    "medium_risk": 30,
    "low_risk": 1067
  }
}
```

### longitudinal_tracking.json

```json
{
  "period": "2026-07-11 to 2026-07-18",
  "snapshots": 4,
  "trends": {
    "total_ips": {
      "start": 1150,
      "end": 1347,
      "change_pct": 17.1
    },
    "ollama": {
      "start": 3,
      "end": 4,
      "change_pct": 33.3,
      "trend": "increasing"
    },
    "grpc": {
      "start": 34,
      "end": 30,
      "change_pct": -11.8,
      "trend": "decreasing"
    }
  }
}
```

## Usage

### Load in Python

```python
import json

with open('cernet2_baseline.json', 'r') as f:
    data = json.load(f)

print(f"Total AI services: {data['scope']['total_ai_ports']}")
```

### Analyze in R

```r
library(jsonlite)
data <- fromJSON('cernet2_baseline.json')
summary(data)
```

## Citation

If you use this data, please cite:

```
IPv6 AI Exposure Measurement Research Group (2026).
CERNET2 AI Infrastructure Exposure Baseline Dataset.
