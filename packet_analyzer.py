#!/usr/bin/env python3
"""
網路封包分析工具 (Network Packet Analyzer)
使用 Scapy 擷取並解析網路封包，支援過濾與統計報表輸出
"""

import sys
import time
import signal
import argparse
import json
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, Ether,
        get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[警告] Scapy 未安裝。執行: pip install scapy")


# ─────────────────────────── 統計資料容器 ───────────────────────────

class PacketStats:
    def __init__(self):
        self.total = 0
        self.by_protocol: dict[str, int] = defaultdict(int)
        self.by_src_ip:   dict[str, int] = defaultdict(int)
        self.by_dst_ip:   dict[str, int] = defaultdict(int)
        self.by_src_port: dict[int, int]  = defaultdict(int)
        self.by_dst_port: dict[int, int]  = defaultdict(int)
        self.total_bytes  = 0
        self.start_time   = time.time()
        self.packets: list[dict] = []   # 詳細封包記錄（最多保留 N 筆）
        self.MAX_RECORDS = 1000

    def record(self, pkt_info: dict):
        self.total += 1
        self.total_bytes += pkt_info.get("length", 0)
        proto = pkt_info.get("protocol", "OTHER")
        self.by_protocol[proto] += 1
        if pkt_info.get("src_ip"):
            self.by_src_ip[pkt_info["src_ip"]] += 1
        if pkt_info.get("dst_ip"):
            self.by_dst_ip[pkt_info["dst_ip"]] += 1
        if pkt_info.get("src_port") is not None:
            self.by_src_port[pkt_info["src_port"]] += 1
        if pkt_info.get("dst_port") is not None:
            self.by_dst_port[pkt_info["dst_port"]] += 1
        if len(self.packets) < self.MAX_RECORDS:
            self.packets.append(pkt_info)

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time


# ─────────────────────────── 封包解析 ───────────────────────────────

def parse_packet(pkt) -> dict | None:
    """解析 Scapy 封包，回傳結構化字典；無法解析時回傳 None。"""
    if not pkt.haslayer(IP):
        return None

    ip   = pkt[IP]
    info = {
        "timestamp": datetime.now().isoformat(timespec="milliseconds"),
        "src_ip":    ip.src,
        "dst_ip":    ip.dst,
        "ttl":       ip.ttl,
        "length":    len(pkt),
        "protocol":  "OTHER",
        "src_port":  None,
        "dst_port":  None,
        "flags":     None,
        "detail":    "",
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.update({
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags":    str(tcp.flags),
        })
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info.update({
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
        })
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        info.update({
            "protocol": "ICMP",
            "detail":   f"type={icmp.type} code={icmp.code}",
        })

    return info


# ─────────────────────────── 過濾邏輯 ───────────────────────────────

def build_filter(args) -> str:
    """根據 CLI 參數組合 BPF 過濾字串。"""
    parts = []
    if args.protocol:
        parts.append(args.protocol.lower())
    if args.src_ip:
        parts.append(f"src host {args.src_ip}")
    if args.dst_ip:
        parts.append(f"dst host {args.dst_ip}")
    if args.port:
        parts.append(f"port {args.port}")
    return " and ".join(parts) if parts else ""


def matches_filter(info: dict, args) -> bool:
    """Python 層的二次過濾（BPF 不支援時的備用方案）。"""
    if args.protocol and info["protocol"].lower() != args.protocol.lower():
        return False
    if args.src_ip and info["src_ip"] != args.src_ip:
        return False
    if args.dst_ip and info["dst_ip"] != args.dst_ip:
        return False
    if args.port:
        if info["src_port"] != args.port and info["dst_port"] != args.port:
            return False
    return True


# ─────────────────────────── 輸出格式 ───────────────────────────────

COLORS = {
    "TCP":   "\033[94m",   # 藍
    "UDP":   "\033[92m",   # 綠
    "ICMP":  "\033[93m",   # 黃
    "OTHER": "\033[90m",   # 灰
    "RESET": "\033[0m",
    "BOLD":  "\033[1m",
    "RED":   "\033[91m",
    "CYAN":  "\033[96m",
}


def colorize(text: str, color: str) -> str:
    if sys.stdout.isatty():
        return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"
    return text


def print_packet(info: dict, verbose: bool = False):
    proto  = info["protocol"]
    color  = proto if proto in COLORS else "OTHER"
    label  = colorize(f"[{proto:5s}]", color)
    src    = f"{info['src_ip']}:{info['src_port']}" if info["src_port"] else info["src_ip"]
    dst    = f"{info['dst_ip']}:{info['dst_port']}" if info["dst_port"] else info["dst_ip"]
    length = colorize(f"{info['length']:5d}B", "CYAN")
    flags  = f" flags={info['flags']}" if info.get("flags") else ""
    detail = f" {info['detail']}"       if info.get("detail") else ""
    print(f"{info['timestamp']}  {label}  {src:<25} → {dst:<25}  {length}{flags}{detail}")

    if verbose:
        print(f"         TTL={info['ttl']}")


def print_report(stats: PacketStats, top_n: int = 10):
    sep  = "─" * 64
    bold = lambda s: colorize(s, "BOLD")

    print(f"\n{bold('═' * 64)}")
    print(bold("  📊 封包統計報表  Network Packet Analysis Report"))
    print(bold('═' * 64))

    elapsed = stats.elapsed
    pps     = stats.total / elapsed if elapsed else 0
    bps     = stats.total_bytes / elapsed if elapsed else 0

    print(f"  擷取時長   : {elapsed:.1f} 秒")
    print(f"  封包總數   : {stats.total:,}")
    print(f"  總流量     : {stats.total_bytes:,} Bytes ({stats.total_bytes/1024:.1f} KB)")
    print(f"  封包速率   : {pps:.1f} pkt/s")
    print(f"  流量速率   : {bps/1024:.2f} KB/s")

    # ── 協定分布 ──
    print(f"\n{sep}")
    print(bold("  協定分布 (Protocol Distribution)"))
    print(sep)
    for proto, count in sorted(stats.by_protocol.items(), key=lambda x: -x[1]):
        pct = count / stats.total * 100 if stats.total else 0
        bar = "█" * int(pct / 2)
        print(f"  {proto:<8} {count:>6,}  {pct:5.1f}%  {colorize(bar, proto if proto in COLORS else 'OTHER')}")

    # ── Top 來源 IP ──
    print(f"\n{sep}")
    print(bold(f"  Top {top_n} 來源 IP (Source IP)"))
    print(sep)
    top_src = sorted(stats.by_src_ip.items(), key=lambda x: -x[1])[:top_n]
    for ip, cnt in top_src:
        print(f"  {ip:<20}  {cnt:>6,} 封包")

    # ── Top 目的 IP ──
    print(f"\n{sep}")
    print(bold(f"  Top {top_n} 目的 IP (Destination IP)"))
    print(sep)
    top_dst = sorted(stats.by_dst_ip.items(), key=lambda x: -x[1])[:top_n]
    for ip, cnt in top_dst:
        print(f"  {ip:<20}  {cnt:>6,} 封包")

    # ── Top 目的 Port ──
    if stats.by_dst_port:
        print(f"\n{sep}")
        print(bold(f"  Top {top_n} 目的 Port (Destination Port)"))
        print(sep)
        top_port = sorted(stats.by_dst_port.items(), key=lambda x: -x[1])[:top_n]
        for port, cnt in top_port:
            svc = _well_known(port)
            print(f"  {port:<6} {svc:<12}  {cnt:>6,} 封包")

    print(bold('═' * 64))


def _well_known(port: int) -> str:
    WK = {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",25:"SMTP",
          53:"DNS",110:"POP3",143:"IMAP",3306:"MySQL",
          5432:"PostgreSQL",6379:"Redis",8080:"HTTP-ALT",
          3389:"RDP",23:"Telnet",161:"SNMP"}
    return f"({WK[port]})" if port in WK else ""


# ─────────────────────────── 匯出 ───────────────────────────────────

def export_json(stats: PacketStats, path: str):
    data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_packets": stats.total,
            "total_bytes":   stats.total_bytes,
            "elapsed_sec":   round(stats.elapsed, 2),
            "protocols":     dict(stats.by_protocol),
        },
        "top_src_ips":   dict(sorted(stats.by_src_ip.items(),  key=lambda x: -x[1])[:20]),
        "top_dst_ips":   dict(sorted(stats.by_dst_ip.items(),  key=lambda x: -x[1])[:20]),
        "top_dst_ports": {str(k): v for k, v in sorted(stats.by_dst_port.items(), key=lambda x: -x[1])[:20]},
        "packets":       stats.packets,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[✓] JSON 報表已儲存：{path}")


def export_csv(stats: PacketStats, path: str):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["timestamp","protocol","src_ip","src_port",
                      "dst_ip","dst_port","length","flags","ttl","detail"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(stats.packets)
    print(f"[✓] CSV 報表已儲存：{path}")


# ─────────────────────────── 主程式 ─────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🔍 網路封包分析工具 — Python + Scapy",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
範例:
  sudo python3 packet_analyzer.py                          # 擷取所有封包（10 秒）
  sudo python3 packet_analyzer.py -i eth0 -c 100          # eth0 介面，擷取 100 個封包
  sudo python3 packet_analyzer.py --protocol tcp           # 只分析 TCP
  sudo python3 packet_analyzer.py --protocol udp --port 53 # DNS 流量
  sudo python3 packet_analyzer.py --src-ip 192.168.1.1     # 特定來源 IP
  sudo python3 packet_analyzer.py -t 30 --export-json report.json
  sudo python3 packet_analyzer.py --list-interfaces        # 列出網路介面
        """
    )

    parser.add_argument("-i",  "--interface",    default=None,    help="網路介面（預設自動選擇）")
    parser.add_argument("-c",  "--count",        type=int, default=0, help="擷取封包數量（0=無限制）")
    parser.add_argument("-t",  "--timeout",      type=int, default=10, help="擷取時間（秒，預設 10）")
    parser.add_argument("-v",  "--verbose",      action="store_true", help="顯示詳細欄位")
    parser.add_argument("-q",  "--quiet",        action="store_true", help="靜默模式（只顯示統計）")
    parser.add_argument("--protocol",            choices=["tcp","udp","icmp"], help="過濾協定")
    parser.add_argument("--src-ip",              dest="src_ip",   help="過濾來源 IP")
    parser.add_argument("--dst-ip",              dest="dst_ip",   help="過濾目的 IP")
    parser.add_argument("--port",                type=int,        help="過濾 Port（來源或目的）")
    parser.add_argument("--top",                 type=int, default=10, help="報表 Top N 數量（預設 10）")
    parser.add_argument("--export-json",         metavar="FILE",  help="匯出 JSON 報表")
    parser.add_argument("--export-csv",          metavar="FILE",  help="匯出 CSV 封包記錄")
    parser.add_argument("--list-interfaces",     action="store_true", help="列出可用網路介面後退出")

    args = parser.parse_args()

    # ── 列出介面 ──
    if args.list_interfaces:
        if not SCAPY_AVAILABLE:
            sys.exit("請先安裝 Scapy: pip install scapy")
        print("可用網路介面:")
        for iface in get_if_list():
            print(f"  {iface}")
        sys.exit(0)

    if not SCAPY_AVAILABLE:
        sys.exit("請先安裝 Scapy: pip install scapy")

    # ── 準備 ──
    stats      = PacketStats()
    bpf_filter = build_filter(args)

    print(colorize("🔍 網路封包分析工具", "BOLD"))
    print(f"   介面     : {args.interface or '(自動)'}")
    print(f"   BPF 過濾 : {bpf_filter or '(無)'}")
    print(f"   封包上限 : {args.count or '無限制'}")
    print(f"   擷取時間 : {args.timeout} 秒")
    print(colorize("─" * 64, "CYAN"))
    if not args.quiet:
        print(f"{'時間戳':24} {'協定':7} {'來源':25} {'目的':25} {'長度':6}")
        print("─" * 100)

    # ── Ctrl+C 優雅結束 ──
    def _sigint(sig, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _sigint)

    # ── 封包回呼 ──
    def handle(pkt):
        info = parse_packet(pkt)
        if info is None:
            return
        if not matches_filter(info, args):
            return
        stats.record(info)
        if not args.quiet:
            print_packet(info, args.verbose)

    # ── 開始擷取 ──
    try:
        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=handle,
            count=args.count,
            timeout=args.timeout,
            store=False,
        )
    except PermissionError:
        print(colorize("[錯誤] 需要 root 權限。請使用 sudo 執行。", "RED"))
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[中斷] 使用者中止擷取。")

    # ── 輸出報表 ──
    print_report(stats, top_n=args.top)

    if args.export_json:
        export_json(stats, args.export_json)
    if args.export_csv:
        export_csv(stats, args.export_csv)


if __name__ == "__main__":
    main()
