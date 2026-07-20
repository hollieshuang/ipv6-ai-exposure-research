#!/usr/bin/env python3
"""
Honeypot Detection for IPv6 AI Infrastructure Exposure

Uses port exposure entropy analysis to detect honeypot networks
or synthetic AI exposure datasets.
"""

import argparse
import json
import sqlite3
import math
from collections import defaultdict
from typing import Dict, List, Tuple

def calculate_entropy(port_counts: Dict[int, int]) -> float:
    """Calculate Shannon entropy of port exposure distribution."""
    total = sum(port_counts.values())
    if total == 0:
        return 0.0
    
    entropy = 0.0
    for count in port_counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def normalized_entropy(entropy: float, num_ports: int) -> float:
    """Normalize entropy to [0,1] range."""
    if num_ports <= 1:
        return 0.0
    max_entropy = math.log2(num_ports)
    if max_entropy == 0:
        return 0.0
    return entropy / max_entropy

def calculate_aliasing_factor(hosts: int, ip_port_pairs: int) -> float:
    """Calculate aliasing factor (ratio of pairs to hosts)."""
    if hosts == 0:
        return 0.0
    return ip_port_pairs / hosts

def analyze_prefix(data: List[Dict]) -> Dict:
    """Analyze a single network prefix for honeypot characteristics."""
    port_counts = defaultdict(int)
    hosts = set()
    ip_port_pairs = 0
    
    for entry in data:
        ip = entry.get('ip', '')
        ports = entry.get('ports', [])
        hosts.add(ip)
        for port in ports:
            port_counts[port] += 1
            ip_port_pairs += 1
    
    # Calculate metrics
    entropy = calculate_entropy(dict(port_counts))
    norm_entropy = normalized_entropy(entropy, len(port_counts))
    aliasing = calculate_aliasing_factor(len(hosts), ip_port_pairs)
    
    # Honeypot detection criteria
    is_honeypot = (
        norm_entropy > 0.9 and
        ip_port_pairs > 1000 and
        aliasing > 3.0
    )
    
    return {
        'total_hosts': len(hosts),
        'total_ports': sum(port_counts.values()),
        'unique_ports': len(port_counts),
        'entropy': entropy,
        'normalized_entropy': norm_entropy,
        'aliasing_factor': aliasing,
        'is_honeypot': is_honeypot,
        'port_distribution': dict(port_counts)
    }

def load_from_db(db_path: str) -> List[Dict]:
    """Load scan results from SQLite database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    results = []
    try:
        cursor.execute("SELECT ip, port FROM hosts")
        for ip, port in cursor.fetchall():
            results.append({'ip': ip, 'ports': [port]})
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
    finally:
        conn.close()
    
    return results

def load_from_json(json_path: str) -> List[Dict]:
    """Load scan results from JSON file."""
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    if isinstance(data, dict) and 'results' in data:
        return data['results']
    return data

def main():
    parser = argparse.ArgumentParser(description="Honeypot detector for IPv6 AI exposure")
    parser.add_argument("--data", "-d", required=True, help="Scan data (JSON or DB)")
    parser.add_argument("--threshold", "-t", type=float, default=0.9, help="Entropy threshold")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()
    
    # Load data
    if args.data.endswith('.db'):
        data = load_from_db(args.data)
    else:
        data = load_from_json(args.data)
    
    if not data:
        print("[!] No data loaded")
        return
    
    # Analyze
    result = analyze_prefix(data)
    result['threshold'] = args.threshold
    result['classified_as'] = "HONEYPOT" if result['is_honeypot'] else "REAL"
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[+] Results saved to {args.output}")
    
    # Print summary
    print("\n[*] Honeypot Analysis Results:")
    print(f"    Total Hosts: {result['total_hosts']}")
    print(f"    Total Ports: {result['total_ports']}")
    print(f"    Normalized Entropy: {result['normalized_entropy']:.4f}")
    print(f"    Aliasing Factor: {result['aliasing_factor']:.2f}")
    print(f"    Classification: {result['classified_as']}")
    
    if result['is_honeypot']:
        print("\n[!] WARNING: High probability honeypot network detected!")
        print("    Recommendation: Exclude from real-exposure analysis")

if __name__ == "__main__":
    main()
