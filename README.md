# 🔍 Python 網路封包分析工具

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)
![Requires](https://img.shields.io/badge/Requires-root%20%2F%20sudo-red)

以 Python + Scapy 擷取並解析網路封包，支援協定過濾、IP/Port 過濾，以及彩色統計報表輸出。

---

## 📁 檔案結構

```
packet_analyzer/
├── packet_analyzer.py   # 主程式（需 root / Scapy）
├── demo_report.py       # Demo 模擬展示（無需 root）
└── README.md
```

---

## ⚙️ 安裝需求

```bash
pip install scapy
```

| 平台 | 需求 |
|------|------|
| Linux | `sudo` / root 權限 |
| macOS | `sudo` / root 權限 |
| Windows | 安裝 [Npcap](https://npcap.com/) |

---

## 🚀 快速開始

### 步驟 1：確認網路介面名稱

```bash
sudo python3 packet_analyzer.py --list-interfaces
```

```
# 輸出範例：
可用網路介面:
  lo
  eth0        ← Linux 實體網卡
  ens33       ← VMware 常見名稱
  wlan0       ← 無線網卡
  en0         ← macOS 常見名稱
```

### 步驟 2：查詢本機 IP

```bash
# Linux
ip addr show <介面名稱>

# macOS
ifconfig <介面名稱>
```

> ⚠️ **過濾 IP 前務必確認本機環境的實際 IP**，否則封包數會是 0（這是正常行為，不是程式錯誤）。

### 步驟 3：開始擷取

```bash
# 擷取所有流量（10 秒）
sudo python3 packet_analyzer.py -i <介面名稱>

# 無需 root 的 Demo 模式
python3 demo_report.py
```

---

## 📖 使用範例

> 下方範例中的 IP（`203.0.113.x`）為 [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) 文件保留位址，請替換成你環境的實際 IP。

### 過濾協定
```bash
sudo python3 packet_analyzer.py -i <介面名稱> --protocol tcp
sudo python3 packet_analyzer.py -i <介面名稱> --protocol udp
sudo python3 packet_analyzer.py -i <介面名稱> --protocol icmp
```

### 過濾特定 IP
```bash
# 來源 IP
sudo python3 packet_analyzer.py -i <介面名稱> --src-ip 203.0.113.10

# 目的 IP
sudo python3 packet_analyzer.py -i <介面名稱> --dst-ip 203.0.113.20

# 同時過濾來源與目的
sudo python3 packet_analyzer.py -i <介面名稱> --src-ip 203.0.113.10 --dst-ip 203.0.113.20
```

### 過濾特定 Port
```bash
# SSH（Port 22）
sudo python3 packet_analyzer.py -i <介面名稱> --protocol tcp --port 22

# DNS（Port 53）
sudo python3 packet_analyzer.py -i <介面名稱> --protocol udp --port 53

# HTTPS（Port 443，需在擷取期間有實際連線）
sudo python3 packet_analyzer.py -i <介面名稱> --protocol tcp --port 443
```

### 限制封包數量 & 擷取時間
```bash
# 擷取 200 個封包後停止
sudo python3 packet_analyzer.py -i <介面名稱> -c 200

# 擷取 30 秒後停止
sudo python3 packet_analyzer.py -i <介面名稱> -t 30
```

### 組合過濾 + 匯出報表
```bash
sudo python3 packet_analyzer.py -i <介面名稱> \
  --protocol tcp --port 22 -t 30 \
  --export-json report.json \
  --export-csv packets.csv
```

### 靜默模式（只顯示統計，不即時輸出封包）
```bash
sudo python3 packet_analyzer.py -i <介面名稱> -q -t 30
```

---

## 📊 輸出說明

### 即時封包輸出格式

```
時間戳                     協定    來源                        目的                      長度
2026-04-24T06:53:33.890  [TCP  ]  203.0.113.10:51606  →  203.0.113.20:22   60B  flags=A
```

| 欄位 | 說明 |
|------|------|
| 時間戳 | 封包擷取時間（毫秒精度）|
| 協定 | TCP / UDP / ICMP |
| 來源 | src_ip:src_port |
| 目的 | dst_ip:dst_port |
| 長度 | 封包大小（Bytes）|
| Flags | TCP 旗標（S / SA / A / PA / FA）|

### 統計報表包含

- 封包總數、總流量、封包速率、流量速率
- 協定分布（含彩色長條圖）
- Top N 來源 IP / 目的 IP
- Top N 目的 Port（自動顯示 HTTP / HTTPS / SSH / DNS 等服務名稱）

![image](https://github.com/xuanxxx2002/Packet-Sniffing-Python/blob/main/image.png)
---

## 🔧 CLI 參數一覽

| 參數 | 預設值 | 說明 |
|------|--------|------|
| `-i, --interface` | 自動 | 指定網路介面 |
| `-c, --count` | 0（無限）| 擷取封包數上限 |
| `-t, --timeout` | 10 | 擷取時間（秒）|
| `--protocol` | — | 過濾協定：`tcp` / `udp` / `icmp` |
| `--src-ip` | — | 過濾來源 IP |
| `--dst-ip` | — | 過濾目的 IP |
| `--port` | — | 過濾 Port（來源或目的）|
| `--top` | 10 | 報表 Top N 數量 |
| `--export-json` | — | 匯出 JSON 統計報表 |
| `--export-csv` | — | 匯出 CSV 封包記錄 |
| `-v, --verbose` | — | 顯示 TTL 等詳細欄位 |
| `-q, --quiet` | — | 靜默模式（只顯示統計）|
| `--list-interfaces` | — | 列出可用網路介面後退出 |

---

## 📝 License

MIT
