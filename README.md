# 🚀 Network Packet Analyzer (Mini Wireshark in Modern C++)

A high-performance **network packet capture and analysis tool** built from scratch in **C++17** using:

- Boost.Asio (async systems programming)
- Boost.Program_options (CLI framework)
- libpcap / Npcap (raw packet capture)
- Multithreading + lock-safe analytics

This project replicates the **core internals of Wireshark/tcpdump** and demonstrates how real packet analyzers are built at the **systems + networking layer**.

---

# 📌 Problem Statement

Modern networks generate **thousands to millions of packets per second**.

Engineers need to understand:

- Who is talking to whom?
- Which hosts consume the most bandwidth?
- Which protocols dominate traffic?
- What websites are accessed?
- Where are bottlenecks or suspicious flows?

Professional tools like **Wireshark** solve this — but they are large and complex.

👉 This project demonstrates **how those tools actually work internally** by implementing a lightweight packet analyzer directly in C++.

---

# 🎯 Objectives

This project is designed to demonstrate:

✅ Low-level networking knowledge  
✅ Systems programming  
✅ Packet parsing  
✅ Async + multithreaded architecture  
✅ Real-time analytics  
✅ Production-quality design  

It is intentionally implemented **without high-level wrappers** to show:

- raw packet handling
- protocol decoding
- flow tracking
- deep packet inspection

---

# ✨ Features

## 🔹 Live Packet Capture
- Uses libpcap/Npcap (same backend as Wireshark)
- Promiscuous mode support
- BPF filters
- Real NIC traffic capture

---

## 🔹 Protocol Parsing
Parses manually:
- Ethernet
- IPv4
- TCP
- UDP

No external parsing libraries — full header decoding implemented from scratch.

---

## 🔹 Flow Tracking (5-Tuple Conversations)
Tracks conversations using:


Per-flow metrics:
- packets
- bytes
- duration

Example:
TCP 192.168.1.5:51234 <-> 142.250.183.14:443 bytes=18000 pkts=25



---

## 🔹 Top Talkers (Bandwidth Analysis)
Shows:
- Top source IPs
- Top destination IPs

Useful for:
- detecting bandwidth hogs
- performance debugging
- anomaly detection

---

## 🔹 HTTP Host Extraction (Deep Packet Inspection)
Extracts plaintext HTTP:

GET /index.html
Host: example.com

Displays:

⚠ HTTPS is encrypted → host not visible unless TLS SNI parsing is added.

---

## 🔹 PCAP Export
Save packets:

--pcap-out capture.pcap



Open directly in:
- Wireshark
- tcpdump
- tshark

Makes the tool interoperable with professional analyzers.

---

## 🔹 Real-Time Analytics
Every second:
- packets/sec
- bytes/sec
- protocol counts
- top talkers
- top flows
- top HTTP hosts

---

## 🔹 High Performance Design
- Dedicated capture thread
- Boost.Asio thread pool
- lock-safe stats
- non-blocking pipeline
- zero copy buffers

---

# 🏗 Architecture

NIC
↓
libpcap capture
↓
Async queue
↓
Parser threads
↓
Stats + Analytics
↓
Console output / PCAP writer





---

# 📂 Project Structure

network-packet-analyzer/
│
├── include/npa/
│ ├── config.hpp → CLI options
│ ├── packet.hpp → packet metadata struct
│ ├── parser.hpp → protocol parser
│ ├── stats.hpp → counters
│ ├── analytics.hpp → flows/talkers/hosts
│ ├── pcap_capture.hpp → libpcap wrapper
│ ├── pcap_writer.hpp → pcap exporter
│ └── util.hpp → helpers
│
├── src/
│ ├── main.cpp
│ ├── parser.cpp
│ ├── stats.cpp
│ ├── analytics.cpp
│ ├── pcap_capture.cpp
│ ├── pcap_writer.cpp
│ ├── config.cpp
│ └── util.cpp
│
├── CMakeLists.txt
└── README.md





---

# ⚙️ Requirements

## Linux (Recommended)
sudo apt install build-essential cmake libboost-all-dev libpcap-dev



## macOS
brew install boost cmake libpcap


## Windows
Install:
Npcap (WinPcap compatible mode)

---

# 🔨 Build

mkdir build
cd build
cmake ..
make -j


Binary:
build/npa


---

# ▶️ How to Run

## Basic
sudo ./npa --iface eth0


---

## Common Options

### TCP only
sudo ./npa --iface eth0 --filter "tcp"


### Verbose mode
sudo ./npa --iface eth0 -v


### Save to pcap
sudo ./npa --iface eth0 --pcap-out capture.pcap


### Show analytics
sudo ./npa --iface eth0 --top-talkers 5 --top-flows 5 --top-hosts 5


---

# 🧪 Testing

### Generate HTTP traffic
curl http://example.com


### Generate HTTPS
curl https://google.com


### Ping
ping google.com



### Open Wireshark
wireshark capture.pcap


---

# 📥 Inputs

### Command line flags
| Option | Description |
|--------|------------|
| --iface | network interface |
| --filter | BPF filter |
| -v | verbose packets |
| --pcap-out | save packets |
| --top-talkers | show bandwidth hogs |
| --top-flows | show conversations |
| --top-hosts | show HTTP hosts |

---

# 📤 Outputs

### Console
Interval: packets=42 bytes=40210
proto: TCP=1200 UDP=250 OTHER=50
Top talkers
Top flows
Top HTTP hosts


### Verbose
TCP 192.168.1.5:443 -> 142.250.183.14:51234 len=1500
HTTP GET / Host=example.com

### PCAP
capture.pcap (Wireshark compatible)



---

# 🧠 Technical Depth Demonstrated

## Networking
- raw packet capture
- BPF filtering
- header parsing
- TCP payload extraction
- HTTP inspection

## Systems
- asynchronous design
- thread pools
- lock-safe analytics
- real-time processing
- memory efficiency

## Engineering
- modular architecture
- clean separation of concerns
- CMake builds
- portable
- production style CLI

---

# 📈 Resume Value

This project demonstrates:

- Systems Programming
- Networking Internals
- C++ Performance Engineering
- Async Architecture
- Deep Packet Inspection
- Observability / Security Concepts

Comparable to:
- Wireshark internals
- tcpdump
- IDS/IPS tools
- flow analyzers

---

# 🚀 Future Improvements

- TLS SNI extraction (HTTPS host detection)
- IPv6 support
- JSON export
- ncurses dashboard
- flow eviction
- replay mode
- intrusion detection rules

---s

# 📜 License
MIT

---

# 👤 Author
Ansh Prem  
C++ • Systems • Networking • Performance Engineering
