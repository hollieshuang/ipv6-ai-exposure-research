#!/usr/bin/env python3
"""
gRPC Service Probe

Detects gRPC/Triton inference backends by sending HTTP/2 connection preface.
"""

import argparse
import socket
import time
from typing import Dict, List

GRPC_PORTS = [50051]

# HTTP/2 connection preface
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def probe_grpc(host: str, port: int = 50051, timeout: int = 4) -> Dict:
    """Probe a single gRPC host."""
    result = {
        'host': host,
        'port': port,
        'reachable': False,
        'is_grpc': False,
        'uses_tls': False,
        'error': None
    }
    
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result['reachable'] = True
        
        # Send HTTP/2 preface
        sock.sendall(HTTP2_PREFACE)
        time.sleep(0.5)
        
        # Receive response (should be HTTP/2 SETTINGS frame)
        data = sock.recv(1024)
        if data and len(data) >= 6:
            # Check for HTTP/2 frame magic (0x5052492a)
            if data[:4] == b"PRI " or data[0] == 0x00:
                result['is_grpc'] = True
        
        sock.close()
        
    except socket.timeout:
        result['error'] = 'timeout'
    except ConnectionRefusedError:
        result['error'] = 'connection_refused'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def main():
    parser = argparse.ArgumentParser(description="gRPC service probe")
    parser.add_argument("--input", "-i", required=True, help="Input file (hosts)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--timeout", "-T", type=int, default=4, help="Timeout seconds")
    parser.add_argument("--port", "-p", type=int, default=50051, help="gRPC port")
    args = parser.parse_args()
    
    # Load hosts
    hosts = []
    if args.input.endswith('.json'):
        import json
        with open(args.input) as f:
            data = json.load(f)
            if isinstance(data, list):
                hosts = [d.get('ip', '') for d in data if d.get('ip')]
    else:
        with open(args.input) as f:
            hosts = [line.strip() for line in f if line.strip()]
    
    if not hosts:
        print("[!] No hosts found")
        return
    
    print(f"[*] Probing {len(hosts)} gRPC hosts...")
    
    results = []
    grpc_count = 0
    for host in hosts:
        res = probe_grpc(host, args.port, args.timeout)
        results.append(res)
        if res['is_grpc']:
            grpc_count += 1
            print(f"  [+] gRPC detected: {host}:{args.port}")
    
    print(f"\n[*] Summary:")
    print(f"    Total Hosts: {len(hosts)}")
    print(f"    Reachable: {sum(1 for r in results if r['reachable'])}")
    print(f"    gRPC Confirmed: {grpc_count}")
    
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
