#!/usr/bin/env python3
"""
Demo 模式：產生模擬封包資料並輸出統計報表
（無需 root 權限，用於功能展示）
"""
import random, time, sys
from collections import defaultdict
from datetime import datetime, timedelta

# ── 模擬資料 ──────────────────────────────────────────────────────
PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
COMMON_PORTS = [80, 443, 22, 53, 3306, 8080, 443, 80, 443]
IPS = [f"192.168.1.{i}" for i in range(2, 15)] + \
      ["10.0.0.1", "172.16.0.5", "8.8.8.8", "1.1.1.1", "104.21.0.50"]

def generate_packets(n=500):
    pkts = []
    ts = datetime.now() - timedelta(seconds=30)
    for _ in range(n):
        proto = random.choice(PROTOCOLS)
        src_ip, dst_ip = random.choice(IPS), random.choice(IPS)
        src_p = random.randint(1024, 65535) if proto != "ICMP" else None
        dst_p = random.choice(COMMON_PORTS)  if proto != "ICMP" else None
        pkts.append({
            "timestamp": ts.isoformat(timespec="milliseconds"),
            "protocol":  proto,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_p,
            "dst_port":  dst_p,
            "length":    random.randint(64, 1500),
            "flags":     random.choice(["S","SA","A","FA","PA"]) if proto == "TCP" else None,
            "ttl":       random.choice([64, 128, 255]),
            "detail":    "",
        })
        ts += timedelta(milliseconds=random.randint(10, 200))
    return pkts

# ── 統計 ──────────────────────────────────────────────────────────
COLORS = {
    "TCP":   "\033[94m", "UDP":   "\033[92m",
    "ICMP":  "\033[93m", "OTHER": "\033[90m",
    "RESET": "\033[0m",  "BOLD":  "\033[1m",
    "CYAN":  "\033[96m", "RED":   "\033[91m",
}
def c(text, k): return f"{COLORS.get(k,'')}{text}{COLORS['RESET']}"
def bold(s): return c(s, "BOLD")

WK = {80:"HTTP",443:"HTTPS",22:"SSH",53:"DNS",3306:"MySQL",8080:"HTTP-ALT"}

def run_demo():
    print(bold("\n🔍 封包分析工具 — Demo 模式"))
    print(c("  (模擬 500 個封包，展示統計報表功能)", "CYAN"))
    print("─"*64)

    pkts = generate_packets(500)

    by_proto = defaultdict(int)
    by_src   = defaultdict(int)
    by_dst   = defaultdict(int)
    by_dport = defaultdict(int)
    total_bytes = 0

    for p in pkts:
        by_proto[p["protocol"]] += 1
        by_src[p["src_ip"]]   += 1
        by_dst[p["dst_ip"]]   += 1
        total_bytes += p["length"]
        if p["dst_port"]: by_dport[p["dst_port"]] += 1

    # ── 即時輸出前 15 筆 ──
    print(f"\n{'時間戳':24} {'協定':7} {'來源':28} {'目的':28} {'長度':6}")
    print("─"*100)
    for p in pkts[:15]:
        proto = p["protocol"]
        col   = proto if proto in COLORS else "OTHER"
        label = c(f"[{proto:5s}]", col)
        src   = f"{p['src_ip']}:{p['src_port']}" if p["src_port"] else p["src_ip"]
        dst   = f"{p['dst_ip']}:{p['dst_port']}" if p["dst_port"] else p["dst_ip"]
        lng   = c(f"{p['length']:5d}B", "CYAN")
        flg   = f" [{p['flags']}]" if p.get("flags") else ""
        print(f"{p['timestamp']}  {label}  {src:<28} → {dst:<28}  {lng}{flg}")
    print(f"  … (共 {len(pkts)} 封包)")

    sep = "─"*64

    # ── 統計報表 ──
    print(f"\n{bold('═'*64)}")
    print(bold("  📊 封包統計報表"))
    print(bold('═'*64))
    print(f"  封包總數   : {len(pkts):,}")
    print(f"  總流量     : {total_bytes:,} Bytes  ({total_bytes/1024:.1f} KB)")
    print(f"  模擬時長   : 30.0 秒")
    print(f"  封包速率   : {len(pkts)/30:.1f} pkt/s")
    print(f"  流量速率   : {total_bytes/30/1024:.2f} KB/s")

    print(f"\n{sep}")
    print(bold("  協定分布"))
    print(sep)
    for proto, cnt in sorted(by_proto.items(), key=lambda x:-x[1]):
        pct = cnt/len(pkts)*100
        bar = "█" * int(pct/2)
        col = proto if proto in COLORS else "OTHER"
        print(f"  {proto:<8} {cnt:>5,}  {pct:5.1f}%  {c(bar, col)}")

    print(f"\n{sep}")
    print(bold("  Top 10 來源 IP"))
    print(sep)
    for ip, cnt in sorted(by_src.items(), key=lambda x:-x[1])[:10]:
        print(f"  {ip:<20}  {cnt:>5,} 封包")

    print(f"\n{sep}")
    print(bold("  Top 10 目的 Port"))
    print(sep)
    for port, cnt in sorted(by_dport.items(), key=lambda x:-x[1])[:10]:
        svc = f"({WK[port]})" if port in WK else ""
        print(f"  {port:<6} {svc:<10}  {cnt:>5,} 封包")

    print(bold('═'*64))
    print(bold("\n✅ Demo 完成！實際使用請執行："))
    print("  sudo python3 packet_analyzer.py --help\n")

if __name__ == "__main__":
    run_demo()
