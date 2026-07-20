#!/usr/bin/env python3
"""
Trend Analyzer for IPv6 AI Infrastructure Exposure

Analyzes longitudinal exposure data and generates trend reports.
"""

import argparse
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

def load_snapshots(db_path: str) -> List[Dict]:
    """Load snapshots from SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    snapshots = []
    try:
        # Assume table 'snapshots' with timestamp and data
        cursor.execute("SELECT timestamp, data FROM snapshots ORDER BY timestamp")
        for ts, data in cursor.fetchall():
            snapshots.append({
                'timestamp': ts,
                'data': json.loads(data) if isinstance(data, str) else data
            })
    except sqlite3.Error:
        # Try alternative schema
        try:
            cursor.execute("SELECT * FROM trends ORDER BY timestamp")
            columns = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                snapshots.append(dict(zip(columns, row)))
        except sqlite3.Error:
            pass
    finally:
        conn.close()
    
    return snapshots

def calculate_trends(snapshots: List[Dict]) -> Dict:
    """Calculate trends from snapshot series."""
    if len(snapshots) < 2:
        return {'error': 'insufficient_data', 'count': len(snapshots)}
    
    # Extract service counts per snapshot
    series = defaultdict(list)
    for snap in snapshots:
        data = snap.get('data', snap)
        for service, count in data.items():
            if isinstance(count, (int, float)):
                series[service].append(count)
    
    trends = {}
    for service, counts in series.items():
        if len(counts) >= 2:
            start = counts[0]
            end = counts[-1]
            change_pct = ((end - start) / start * 100) if start > 0 else 0
            
            direction = 'stable'
            if change_pct > 5:
                direction = 'increasing'
            elif change_pct < -5:
                direction = 'decreasing'
            
            # Stability (coefficient of variation inverted)
            mean = sum(counts) / len(counts)
            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            cv = (variance ** 0.5) / mean if mean > 0 else 0
            stability = max(0.0, 1.0 - cv)
            
            trends[service] = {
                'start': start,
                'end': end,
                'change_pct': round(change_pct, 2),
                'direction': direction,
                'stability': round(stability, 3),
                'volatility': round(cv, 3)
            }
    
    return {
        'period': f"{snapshots[0].get('timestamp')} to {snapshots[-1].get('timestamp')}",
        'snapshot_count': len(snapshots),
        'trends': trends
    }

def main():
    parser = argparse.ArgumentParser(description="Trend analyzer for AI exposure")
    parser.add_argument("--database", "-d", required=True, help="SQLite database path")
    parser.add_argument("--period", "-p", default="daily", choices=["daily", "weekly", "monthly"])
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()
    
    snapshots = load_snapshots(args.database)
    
    if not snapshots:
        print("[!] No snapshot data found")
        return
    
    result = calculate_trends(snapshots)
    
    if 'error' in result:
        print(f"[!] Error: {result['error']}")
        return
    
    # Print summary
    print(f"\n[*] Trend Analysis ({result['period']})")
    print(f"    Period: {result['period']}")
    print(f"    Snapshots: {result['snapshot_count']}")
    print("\n    Service Trends:")
    for service, t in result['trends'].items():
        print(f"      {service}: {t['start']} → {t['end']} "
              f"({t['change_pct']:+}% {t['direction']})")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
