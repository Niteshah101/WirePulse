# WirePulse: Low-Level Intrusion & Anomaly Detection System

A high-performance, low-level network monitoring tool built from scratch using native Python raw sockets (`AF_PACKET`). The application bypasses user-space abstractions to parse raw Layer 2 and Layer 3 frames directly from the network interface card (NIC), performing stateful detection against common link-layer and network-layer exploitation vectors.

---

## 🚀 Key Architectural Features

* **Zero-Dependency Raw Packet Capture:** Uses Linux native raw network sockets (`socket.SOCK_RAW`) to intercept raw frame streams without relying on external packet capture wrappers like Scapy or libpcap.
* **Low-Level Protocol Decoding:** Performs inline binary layout stripping using Python’s `struct` module to unpack Ethernet headers, ARP structures, IPv4 packets, and TCP flag states directly from memory buffers.
* **Stateful Anomaly Detection Engine:** Maintains real-time mapping tables to perform immediate stateful correlation against anomalous network traffic signatures.

---

## 🛠️ Implemented Detection Capabilities

### 1. Link-Layer Exploitation: ARP Cache Poisoning (Man-in-the-Middle)

The engine monitors the mapping between Layer 3 IP addresses and Layer 2 MAC addresses.

* **Detection Logic:** It stores existing IP-to-MAC resolutions dynamically. If an incoming ARP frame attempts to update an active IP with a differing hardware address, the tool flags a potential spoofing or Man-in-the-Middle (MitM) occurrence.

### 2. Reconnaissance: Stealth TCP SYN Port Scanning

The engine decodes Layer 4 transmission parameters to expose covert host scanning profiles.

* **Detection Logic:** It filters incoming IPv4 streams for pure `SYN` flags (where `SYN == 1` and `ACK == 0`). The tool dynamically counts unique targeted ports per unique source IP address. If the count exceeds the threshold within its tracking table, it registers a stealth scanner alert.

---

## 📦 Tech Stack & Dependencies

* **Core Language:** Python 3.x
* **Standard Modules:** `socket`, `struct`, `os`, `sys`, `datetime`
* **Privilege Requirements:** Root access (`CAP_NET_RAW` capability or `sudo` permissions) to open raw socket boundaries.

---

## ⚙️ Installation & Usage

### Prerequisites

Ensure your Linux system has raw network capturing capabilities enabled on your target interface (e.g., `eth0`, `wlan0`).

### Execution

1. Clone the repository:
```bash
git clone https://github.com/Niteshah101/WirePulse.git
cd WirePulse

```


2. Execute the engine as root, specifying your target interface monitor:
```bash

sudo python3 wirepulse eth0

```



### Output Profile Example

```text
Listening on eth0
[+] Scanning for ARP poisioning..
[+] Scanning for Active port scan..

[2026-07-18 09:47:29][!!] Potential active port scanning found from [192.168.4.25]
[2026-07-18 09:48:22][!!] Potential ARP poisioning found for [192.168.4.49] from [aa:bb:cc:dd:ee:fd]
Clossing Socket


```

---

## 🗺️ Engineering Roadmap (Future Implementations)

* [ ] **High-Speed Ingestion Optimization:** Integrate native `ctypes` mappings or memory-mapped socket ring buffers (`PACKET_MMAP`) to increase throughput performance past 10,000 requests per second.
* [ ] **Layer 3 Volumetric Defense:** Implement automated sliding-window velocity metrics to detect ICMP Smurf Attacks targeting broadcast boundaries.
* [ ] **Automated Forensics Output:** Integrate a PCAP logging mechanism to stream flagged frames straight into Wireshark-compatible files for validation.