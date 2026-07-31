#!/usr/bin/env python3
"""OSINT enrichment for OT alert sources.

Uses Team Cymru DNS-based lookup (no API key required) to resolve the
ASN/owner and geolocation country for a given IP address.
"""
import argparse
import json
import socket


def asn_lookup(ip):
    query = f"{ip}.origin.asn.cymru.com"
    try:
        answers = socket.getaddrinfo(query, 0, socket.AF_INET)
    except socket.gaierror:
        return None
    for answer in answers:
        parts = [int(x) for x in answer[4][0].split(".")]
        if len(parts) == 4:
            return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    return None


def asn_owner_lookup(ip):
    try:
        sock = socket.create_connection(("whois.cymru.com", 43), timeout=5)
        sock.sendall(f"begin\nverbose\n{ip}\nend\n".encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
    except OSError:
        return None
    text = response.decode(errors="replace")
    for line in text.splitlines():
        if line.startswith("|") and "AS" in line:
            return line.strip(" |")
    return None


def geo_lookup(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "unknown"
    cc = host.rsplit(".", 1)[-1]
    return cc if len(cc) == 2 else "unknown"


def enrich(ip):
    return {
        "ip": ip,
        "asn_owner": asn_owner_lookup(ip),
        "country_cc": geo_lookup(ip),
    }


def main():
    parser = argparse.ArgumentParser(description="Enrich alert source IPs with OSINT data")
    parser.add_argument("ips", nargs="+", help="IP addresses to enrich")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    results = [enrich(ip) for ip in args.ips]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['ip']:<16} {r['asn_owner'] or 'n/a':<40} {r['country_cc']}")


if __name__ == "__main__":
    main()
