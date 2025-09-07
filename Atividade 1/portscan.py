#!/usr/bin/env python3
import argparse
import concurrent.futures
import ipaddress
import os
import socket
import sys
import time
from typing import Iterable, List, Optional, Set, Tuple, Dict


def parse_targets(targets: List[str]) -> List[str]:
    out: List[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        # CIDR/network expansion
        try:
            net = ipaddress.ip_network(t, strict=False)
            # limit expansion to reasonable size
            if net.num_addresses > 1_048_576:  # 2^20
                raise ValueError(f"Network too large to expand: {t} ({net.num_addresses} hosts)")
            for ip in net.hosts() if isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else []:
                out.append(str(ip))
            if net.num_addresses == 1:
                out.append(str(net.network_address))
            continue
        except ValueError:
            pass

        # Single IP or hostname
        out.append(t)
    # remove duplicates preserving order
    seen = set()
    deduped = []
    for x in out:
        if x not in seen:
            deduped.append(x)
            seen.add(x)
    return deduped


def parse_ports(ports: str) -> List[int]:
    res: Set[int] = set()
    for part in ports.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            start = int(a)
            end = int(b)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    res.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                res.add(p)
    return sorted(res)


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def tcp_connect_scan(target: str, port: int, timeout: float) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((target, port))
        if result == 0:
            return 'open'
        # common filtered/closed distinctions are not available with connect_ex
        # Treat non-zero errno as closed (timeout handled below)
        return 'closed'
    except socket.timeout:
        return 'filtered'
    except Exception:
        return 'closed'
    finally:
        try:
            s.close()
        except Exception:
            pass


def try_import_scapy():
    try:
        from scapy.all import IP, TCP, sr1, conf
        return IP, TCP, sr1, conf
    except Exception:
        return None


def tcp_syn_scan(target: str, port: int, timeout: float) -> Optional[str]:
    pkg = try_import_scapy()
    if pkg is None:
        return None
    IP, TCP, sr1, conf = pkg
    # Scapy can be noisy; reduce verbosity
    conf.verb = 0
    pkt = IP(dst=target) / TCP(dport=port, flags='S')
    try:
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            return 'filtered'  # no response or silently dropped
        if resp.haslayer(TCP):
            tcp = resp.getlayer(TCP)
            if tcp.flags & 0x12:  # SYN/ACK
                # Send RST to close half-open connection
                rst = IP(dst=target) / TCP(dport=port, flags='R', seq=tcp.ack, ack=tcp.seq + 1)
                try:
                    # fire and forget; no need to wait
                    sr1(rst, timeout=0.1)
                except Exception:
                    pass
                return 'open'
            if tcp.flags & 0x14:  # RST/ACK
                return 'closed'
        # ICMP or other reply
        return 'filtered'
    except PermissionError:
        # raw sockets need root
        return None
    except Exception:
        return 'filtered'


def udp_probe_scan(target: str, port: int, timeout: float) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        # Connect associates destination; ICMP errors are reported on the socket
        s.connect((target, port))
        # Send a small payload; some services expect specific payloads, but empty is okay for a basic scan
        try:
            s.send(b"\x00")
        except Exception:
            pass
        try:
            _ = s.recv(1024)
            # If we got a UDP payload back, likely open
            return 'open'
        except socket.timeout:
            # No reply could be open or filtered
            return 'open|filtered'
        except ConnectionRefusedError:
            return 'closed'
        except OSError as e:
            # On Linux, ICMP Port Unreachable often maps to ECONNREFUSED
            if getattr(e, 'errno', None) in (111, 113, 111):  # placeholders; fall back to closed
                return 'closed'
            return 'open|filtered'
    finally:
        try:
            s.close()
        except Exception:
            pass


def resolve_target(target: str) -> Optional[str]:
    # Resolve hostnames to IPv4 addresses (basic)
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


def scan_worker(args) -> Tuple[str, int, str, str]:
    target_ip, port, proto, timeout, use_syn = args
    status = 'unknown'
    if proto == 'tcp':
        if use_syn:
            syn_res = tcp_syn_scan(target_ip, port, timeout)
            if syn_res is not None:
                status = syn_res
            else:
                status = tcp_connect_scan(target_ip, port, timeout)
        else:
            status = tcp_connect_scan(target_ip, port, timeout)
    else:
        status = udp_probe_scan(target_ip, port, timeout)
    return (target_ip, port, proto, status)


def format_result(results: List[Tuple[str, int, str, str]], show_closed: bool) -> str:
    # Group by target then protocol
    grouped: Dict[Tuple[str, str], List[Tuple[int, str]]] = {}
    for target, port, proto, status in results:
        key = (target, proto)
        grouped.setdefault(key, []).append((port, status))

    lines: List[str] = []
    for (target, proto), entries in sorted(grouped.items(), key=lambda x: (x[0][0], x[0][1])):
        lines.append(f"Host {target} ({proto.upper()}):")
        for port, status in sorted(entries, key=lambda x: x[0]):
            if not show_closed and status in ('closed',):
                continue
            lines.append(f"  {proto}/{port}: {status}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(
        description='Simple TCP/UDP port scanner for Linux (works on others too).',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('targets', nargs='+', help='Targets: IPs, hostnames, or CIDRs (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='1-1024', help='Ports: comma list and/or ranges (e.g., 22,80,443,8000-8100)')
    parser.add_argument('--tcp', action='store_true', help='Scan TCP only')
    parser.add_argument('--udp', action='store_true', help='Scan UDP only')
    parser.add_argument('--syn', action='store_true', help='Use TCP SYN scan (requires root and scapy), else falls back to connect scan')
    parser.add_argument('-w', '--workers', type=int, default=min(100, (os.cpu_count() or 2) * 25), help='Max parallel workers')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Per-port timeout in seconds')
    parser.add_argument('--show-closed', action='store_true', help='Include closed ports in output')
    args = parser.parse_args()

    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports)

    if not targets:
        print('No valid targets provided', file=sys.stderr)
        return 2
    if not ports:
        print('No valid ports provided', file=sys.stderr)
        return 2

    scan_tcp = args.tcp or (not args.tcp and not args.udp)
    scan_udp = args.udp or (not args.tcp and not args.udp)

    if args.syn and not is_root():
        print('Warning: TCP SYN scan requested but not running as root; using TCP connect scan instead.', file=sys.stderr)

    job_args: List[Tuple[str, int, str, float, bool]] = []
    for t in targets:
        ip = resolve_target(t)
        if ip is None:
            print(f"Warning: could not resolve {t}, skipping.", file=sys.stderr)
            continue
        for p in ports:
            if scan_tcp:
                job_args.append((ip, p, 'tcp', args.timeout, args.syn and is_root()))
            if scan_udp:
                job_args.append((ip, p, 'udp', args.timeout, False))

    if not job_args:
        print('Nothing to scan; exiting.')
        return 1

    start = time.time()
    results: List[Tuple[str, int, str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for res in executor.map(scan_worker, job_args, chunksize=50):
            results.append(res)

    dur = time.time() - start
    sys.stdout.write(format_result(results, show_closed=args.show_closed))
    sys.stderr.write(f"Scanned {len(job_args)} sockets in {dur:.2f}s\n")
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(130)

