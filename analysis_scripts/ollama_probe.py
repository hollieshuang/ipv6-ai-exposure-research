#!/usr/bin/env python3
"""
Ollama Service Probe

Probes Ollama API endpoints for unauthorized access validation.
"""

import argparse
import json
import socket
import time
from typing import Dict, List, Optional

OLLAMA_PORTS = [11434, 7000]

def probe_ollama(host: str, port: int = 11434, timeout: int = 5) -> Dict:
    """Probe a single Ollama host."""
    result = {
        'host': host,
        'port': port,
        'reachable': False,
        'version': None,
        'models': [],
        'vulnerable': False,
        'error': None
    }
    
    try:
        # Connect
        sock = socket.create_connection((host, port), timeout=timeout)
        result['reachable'] = True
        
        # Send version request
        sock.sendall(b"GET /api/version HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.5)
        data = sock.recv(4096).decode('utf-8', errors='ignore')
        
        if 'version' in data.lower():
            # Extract version (simplified)
            import re
            match = re.search(r'"version"\s*:\s*"([^"]+)"', data)
            if match:
                result['version'] = match.group(1)
        
        # Send tags request (model enumeration)
        sock.sendall(b"GET /api/tags HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.5)
        data = sock.recv(8192).decode('utf-8', errors='ignore')
        
        if 'models' in data.lower():
            # Extract model names (simplified)
            import re
            models = re.findall(r'"name"\s*:\s*"([^"]+)"', data)
            result['models'] = models
            result['vulnerable'] = True  # Unauthenticated model enumeration
        
        sock.close()
        
    except socket.timeout:
        result['error'] = 'timeout'
    except ConnectionRefusedError:
        result['error'] = 'connection_refused'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def main():
    parser = argparse.ArgumentParser(description="Ollama service probe")
    parser.add_argument("--input", "-i", required=True, help="Input file (hosts, one per line or JSON)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--timeout", "-T", type=int, default=5, help="Timeout seconds")
    parser.add_argument("--port", "-p", type=int, default=11434, help="Ollama port")
    args = parser.parse_args()
    
    # Load hosts
    hosts = []
    if args.input.endswith('.json'):
        with open(args.input) as f:
            data = json.load(f)
            if isinstance(data, list):
                hosts = [d.get('ip', '') for d in data if d.get('ip')]
            elif isinstance(data, dict) and 'results' in data:
                for r in data['results']:
                    for p in r.get('ports', []):
                        if p.get('port') in OLLAMA_PORTS:
                            hosts.append(r.get('ip', ''))
    else:
        with open(args.input) as f:
            hosts = [line.strip() for line in f if line.strip()]
    
    if not hosts:
        print("[!] No hosts found")
        return
    
    print(f"[*] Probing {len(hosts)} hosts...")
    
    results = []
    vulnerable = 0
    for host in hosts:
        res = probe_ollama(host, args.port, args.timeout)
        results.append(res)
        if res['vulnerable']:
            vulnerable += 1
            print(f"  [!] VULNERABLE: {host}:{args.port} - {len(res['models'])} models exposed")
    
    # Summary
    print(f"\n[*] Summary:")
    print(f"    Total Hosts: {len(hosts)}")
    print(f"    Reachable: {sum(1 for r in results if r['reachable'])}")
    print(f"    Vulnerable: {vulnerable}")
    
    # Save
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
