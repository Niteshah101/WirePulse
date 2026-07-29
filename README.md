# WirePulse ⚡

**High-Throughput Low-Level Intrusion Detection System**

*Built with Python, Linux `AF_PACKET` Sockets, `mmap`, `ctypes`, and PCAP Logging*

---

## 🚀 Overview & Key Architecture

WirePulse is a zero-dependency Network Intrusion Detection System (NIDS) built from scratch to capture and decode Layer 2–4 network traffic directly from hardware interfaces without third-party wrappers like Scapy or libpcap.

```
[ NIC ] ──► [ PACKET_MMAP Kernel Ring Buffer ] ──► [ ctypes C-Struct Overlay ] ──► [ Stateful Threat Engine ]
                                                                                         │
                                                                                         ▼
                                                                                [ alerts.pcap Forensics ]

```

* **Zero-Copy Ingestion (`PACKET_MMAP`):** Bypasses kernel-to-user context switching and memory copies by binding directly to a mapped Linux ring buffer (`PACKET_RX_RING`).


* **Zero-Allocation Parsing (`ctypes`):** Replaces byte-slicing and `struct.unpack` with `ctypes.BigEndianStructure` memory overlays, extracting headers at C execution speed with zero memory allocation.


* **Automated PCAP Forensics:** Writes flagged threat frames straight into standard Wireshark-compatible `.pcap` files for incident response validation.



---

## 🛡️ Active Threat Detection Capabilities

* **ARP Cache Poisoning (Layer 2):** Tracks dynamic IP-to-MAC resolutions in memory. Flags spoofed ARP responses attempting hardware address re-mappings (MitM attacks).


* **Stealth TCP SYN Scans (Layer 4):** Decodes TCP flag states (`SYN == 1`, `ACK == 0`), tracking unique target ports per source IP to flag scanning profiles.


* **Volumetric ICMP Floods (Layer 3):** Uses a time-based sliding window to evaluate ICMP packet velocity. Includes rate-throttled forensic sampling to protect system disk space.



---

## ⚙️ Quick Start

```bash
# Clone repository
git clone https://github.com/Niteshah101/WirePulse.git && cd WirePulse

# Run engine as root on target interface
sudo python3 wirepulse.py eth0

# Inspect forensic alerts in Wireshark
wireshark alerts.pcap

```

---

## 🗺️ Roadmap Progression

* [x] **Zero-Copy Ingestion:** Integrated `PACKET_MMAP` kernel ring buffers.


* [x] **Binary Memory Mapping:** Mapped `ctypes` C structures directly over physical RAM offsets.


* [x] **Volumetric Rate Limiting:** Built sliding-window counters for ICMP flood detection.


* [x] **Automated PCAP Forensics:** Native Libpcap header serializer for alert logging.