#!/usr/bin/env python3
"""
IPv6 AI Infrastructure Scanner
Scans IPv6 networks for AI service exposure using masscan
"""

import argparse
import json
import subprocess
import tempfile
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
import sqlite3

# AI service ports
AI_PORTS = {
    11434: "ollama",
    7000: "ollama_alt",
    50051: "grpc",
    8000: "vllm",
    8888: "vllm_alt",
    7860: "gradio",
    8501: "streamlit",
    18789: "openclaw",
    18798: "openclaw_alt",
    28789: "openclaw_alt2",
    56767: "qclaw",
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="IPv6 AI Infrastructure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IPv6 prefix (e.g., 2402:e740::/48)"
    )
    parser.add_argument(
        "--rate", "-r",
        type=int,
        default=22000,
        help="Scan rate in packets/second (default: 22000)"
    )
    parser.add_argument(
        "--output", "-o",
        default="ai_scan_results.json",
        help="Output file (default: ai_scan_results.json)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "db"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--probe-ollama",
        action="store_true",
        help="Enable Ollama service probing"
    )
    parser.add_argument(
        "--probe-grpc",
        action="store_true",
        help="Enable gRPC service probing"
    )
    parser.add_argument(
        "--timeout", "-T",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--retries", "-R",
        type=int,
        default=3,
        help="Number of retries (default: 3)"
    )
    parser.add_argument(
        "--exclude",
        help="Exclude file (one IP per line)"
    )
    parser.add_argument(
        "--config",
        help="Configuration file (JSON)"
    )
    
    return parser.parse_args()

def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file."""
    with open(config_file, 'r') as f:
        return json.load(f)

def build_masscan_command(args, exclude_file: Optional[str] = None) -> List[str]:
    """Build masscan command."""
    ports = ",".join(map(str, AI_PORTS.keys()))
    
    cmd = [
        "masscan",
        "-p", ports,
        "-6",  # IPv6 mode
        args.target,
        "--rate", str(args.rate),
        "--wait", str(args.timeout),
        "--retries", str(args.retries),
        "-oJ", "-"  # JSON output to stdout
    ]
    
    if exclude_file:
        cmd.extend(["--exclude-file", exclude_file])
    
    return cmd

def run_masscan(cmd: List[str]) -> List[Dict]:
    """Run masscan and return results."""
    print(f"[*] Starting scan: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )
        
        if result.stderr:
            print(f"[*] masscan: {result.stderr}")
        
        # Parse JSON output
        results = []
        for line in result.stdout.strip().split('\n'):
            if line and line.startswith('{'):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        return results
        
    except subprocess.TimeoutExpired:
        print("[!] Scan timeout")
        return []
    except FileNotFoundError:
        print("[!] masscan not found. Please install masscan.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        return []

def analyze_results(results: List[Dict]) -> Dict:
    """Analyze scan results."""
    summary = {
        "total_hosts": 0,
        "total_ports": 0,
        "ai_services": {},
        "risk_distribution": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
    }
    
    hosts = set()
    
    for result in results:
        if result.get("ports"):
            for port_info in result["ports"]:
                ip = result.get("ip", "")
                port = port_info.get("port", 0)
                proto = port_info.get("proto", "tcp")
                
                hosts.add(ip)
                summary["total_ports"] += 1
                
                service = AI_PORTS.get(port, "unknown")
                
                if service not in summary["ai_services"]:
                    summary["ai_services"][service] = 0
                summary["ai_services"][service] += 1
                
                # Risk assessment
                if service in ["ollama", "openclaw"]:
                    summary["risk_distribution"]["HIGH"] += 1
                elif service in ["grpc", "vllm"]:
                    summary["risk_distribution"]["MEDIUM"] += 1
                else:
                    summary["risk_distribution"]["LOW"] += 1
    
    summary["total_hosts"] = len(hosts)
    
    return summary

def save_json(results: List[Dict], summary: Dict, output: str):
    """Save results as JSON."""
    output_data = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "tool": "masscan_ipv6_ai_scanner",
            "version": "1.0.0"
        },
        "results": results,
        "summary": summary
    }
    
    with open(output, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"[+] Results saved to {output}")

def save_csv(results: List[Dict], output: str):
    """Save results as CSV."""
    import csv
    
    with open(output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Protocol", "Service", "Timestamp"])
        
        for result in results:
            ip = result.get("ip", "")
            for port_info in result.get("ports", []):
                port = port_info.get("port", 0)
                proto = port_info.get("proto", "tcp")
                service = AI_PORTS.get(port, "unknown")
                timestamp = port_info.get("timestamp", "")
                
                writer.writerow([ip, port, proto, service, timestamp])
    
    print(f"[+] Results saved to {output}")

def save_db(results: List[Dict], output: str):
    """Save results to SQLite database."""
    conn = sqlite3.connect(output)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            service TEXT,
            timestamp TEXT,
            UNIQUE(ip, port)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            tool TEXT,
            version TEXT
        )
    """)
    
    # Insert results
    for result in results:
        ip = result.get("ip", "")
        for port_info in result.get("ports", []):
            port = port_info.get("port", 0)
            proto = port_info.get("proto", "tcp")
            service = AI_PORTS.get(port, "unknown")
            timestamp = port_info.get("timestamp", "")
            
            cursor.execute("""
                INSERT OR REPLACE INTO hosts (ip, port, protocol, service, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, port, proto, service, timestamp))
    
    # Insert scan info
    cursor.execute("""
        INSERT INTO scan_info (timestamp, tool, version)
        VALUES (?, ?, ?)
    """, (datetime.now().isoformat(), "masscan_ipv6_ai_scanner", "1.0.0"))
    
    conn.commit()
    conn.close()
    
    print(f"[+] Results saved to {output}")

def main():
    args = parse_args()
    
    # Load config if provided
    if args.config:
        config = load_config(args.config)
        for key, value in config.items():
            if not hasattr(args, key) or getattr(args, key) is None:
                setattr(args, key, value)
    
    # Handle exclude file
    exclude_file = None
    if args.exclude:
        exclude_file = args.exclude
        if not os.path.exists(exclude_file):
            print(f"[!] Exclude file not found: {exclude_file}")
            sys.exit(1)
    
    # Build and run masscan command
    cmd = build_masscan_command(args, exclude_file)
    results = run_masscan(cmd)
    
    if not results:
        print("[!] No results found")
        return
    
    # Analyze results
    summary = analyze_results(results)
    
    print("\n[*] Scan Summary:")
    print(f"    Total Hosts: {summary['total_hosts']}")
    print(f"    Total Ports: {summary['total_ports']}")
    print(f"    AI Services: {summary['ai_services']}")
    print(f"    Risk Distribution: {summary['risk_distribution']}")
    
    # Save results based on format
    output = args.output
    if args.format == "json":
        save_json(results, summary, output)
    elif args.format == "csv":
        # Change extension to .csv
        if not output.endswith('.csv'):
            output = output.rsplit('.', 1)[0] + '.csv'
        save_csv(results, output)
    elif args.format == "db":
        # Change extension to .db
        if not output.endswith('.db'):
            output = output.rsplit('.', 1)[0] + '.db'
        save_db(results, output)
    
    print("\n[*] Scan complete!")

if __name__ == "__main__":
    main()
