import socket
import sys
import os
import struct
import ctypes
import time
import mmap
from datetime import datetime

SOL_PACKET = 263
PACKET_RX_RING = 5
TP_STATUS_KERNEL = 0
TP_STATUS_USER = 1

# Ring Buffer Sizing (256 KB total ring capacity)
BLOCK_SIZE = 4096 * 4  # 16 KB per block
BLOCK_NR = 16          # 16 blocks
FRAME_SIZE = 2048      # 2 KB per frame slot
FRAME_NR = (BLOCK_SIZE * BLOCK_NR) // FRAME_SIZE


class EthernetHeader(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("dst_mac", ctypes.c_uint8 * 6),
        ("src_mac", ctypes.c_uint8 * 6),
        ("eth_type", ctypes.c_uint16)
    ]

class IPv4Header(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("ver_ihl",  ctypes.c_uint8),
        ("tos",      ctypes.c_uint8),
        ("tot_len",  ctypes.c_uint16),
        ("id",       ctypes.c_uint16),
        ("frag_off", ctypes.c_uint16),
        ("ttl",      ctypes.c_uint8),
        ("protocol", ctypes.c_uint8),
        ("check",    ctypes.c_uint16),
        ("saddr",    ctypes.c_uint32),
        ("daddr",    ctypes.c_uint32)
    ]

# writing alerted raw packet in pcap for future investigation
class PCAPLogger:
    """Writes flagged raw ethernet frames straight into a standard .pcap file."""
    def __init__(self, filename="alerts.pcap"):
        self.filename = filename
        if not os.path.exists(self.filename):
            with open(self.filename, "wb") as f:
                # Libpcap Global Header (24 Bytes)
                # Magic Number (0xa1b2c3d4), Major 2, Minor 4, GMT 0, Accur 0, Snaplen 65535, LinkType 1 (Ethernet)
                global_hdr = struct.pack("=IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
                f.write(global_hdr)

    def write_packet(self, raw_bytes):
        now = time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1000000)
        length = len(raw_bytes)

        # Libpcap Packet Header (16 Bytes)
        pcap_hdr = struct.pack("=IIII", ts_sec, ts_usec, length, length)
        
        with open(self.filename, "ab") as f:
            f.write(pcap_hdr + raw_bytes)


class NetworkScanEngine:
    def __init__(self, pcap_logger):
        self.arp_table = {}
        self.track_port_scan = {}
        self.icmp_tracker = {}  # {src_ip: [timestamp1, timestamp2, ...]}
        self.pcap_logger = pcap_logger

    def scan_arp_poisoning(self, src_ip, src_mac, raw_frame):
        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac != src_mac:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}][!!] Potential ARP poisoning found for [{src_ip}] from [{src_mac}]")
                self.pcap_logger.write_packet(raw_frame)
        else:
            self.arp_table[src_ip] = src_mac

    def scan_port_scan(self, src_ip, dst_port, raw_frame, threshold_ports=5):
        if src_ip not in self.track_port_scan:
            self.track_port_scan[src_ip] = {"dst_ports": set(), "is_alerted": False}
        
        tracker = self.track_port_scan[src_ip]
        tracker["dst_ports"].add(dst_port)

        if len(tracker["dst_ports"]) > threshold_ports and not tracker["is_alerted"]:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}][!!] Potential active port scanning found from [{src_ip}]")
            tracker["is_alerted"] = True
            self.pcap_logger.write_packet(raw_frame)

    def scan_icmp_flood(self, src_ip, raw_frame, threshold_rate=15, window_seconds=3):
        """Volumetric Defense: Sliding-window detection for ICMP Smurf/Floods."""
        now = time.time()
        
        if src_ip not in self.icmp_tracker:
            self.icmp_tracker[src_ip] = []

        # Prune timestamps older than our sliding time window
        self.icmp_tracker[src_ip] = [ts for ts in self.icmp_tracker[src_ip] if now - ts <= window_seconds]
        self.icmp_tracker[src_ip].append(now)

        if len(self.icmp_tracker[src_ip]) > threshold_rate:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}][!!] ICMP Volumetric Flood / Smurf Attack detected from [{src_ip}] "
                  f"({len(self.icmp_tracker[src_ip])} pkts/{window_seconds}s)")
            self.pcap_logger.write_packet(raw_frame)
            # Clear window temporarily to avoid continuous console spamming
            self.icmp_tracker[src_ip] = []


def env_check():
    if os.getuid() != 0:
        print("[!] Root Access required! Please run with sudo.")
        sys.exit(1)
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} [interface]")
        sys.exit(1)

def format_mac(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)

def format_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def main():
    env_check()
    interface = sys.argv[1]
    
    pcap = PCAPLogger("alerts.pcap")
    scanner = NetworkScanEngine(pcap_logger=pcap)

    # Open Raw Socket
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    
    # Configure PACKET_MMAP Ring Buffer
    req = struct.pack("IIII", BLOCK_SIZE, BLOCK_NR, FRAME_SIZE, FRAME_NR)
    raw_socket.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
    raw_socket.bind((interface, 0))

    # Map Kernel Memory directly into Python
    
    ring = mmap.mmap(
        fileno=raw_socket.fileno(),
        length=BLOCK_SIZE * BLOCK_NR,
        flags=mmap.MAP_SHARED,
        prot=mmap.PROT_READ | mmap.PROT_WRITE
    )

    print(f"Listening on {interface} (PACKET_MMAP Enabled)")
    print("[+] Scanning for ARP poisoning...")
    print("[+] Scanning for Active port scans...")
    print("[+] Scanning for Volumetric ICMP floods...")
    print("[+] Logging alert forensics to 'alerts.pcap'\n")

    frame_idx = 0

    try:
        while True:
            offset = frame_idx * FRAME_SIZE
            tp_status = struct.unpack("I", ring[offset:offset + 4])[0]

            # Check if Kernel has handed memory ownership to User Space
            if tp_status & TP_STATUS_USER:
                tp_snaplen, tp_mac = struct.unpack("IH", ring[offset + 12:offset + 18])
                packet_start = offset + tp_mac
                raw_frame = ring[packet_start : packet_start + tp_snaplen]

                # --- FAST LAYER 2 PARSING (ctypes) ---
                eth = EthernetHeader.from_buffer(ring, packet_start)
                eth_type = eth.eth_type

                # ARP Protocol (0x0806)
                if eth_type == 0x0806:
                    arp_bytes = raw_frame[14:42]
                    if len(arp_bytes) >= 28:
                        arp_hdr = struct.unpack("!HHBBH6s4s6s4s", arp_bytes)
                        src_mac = format_mac(arp_hdr[5])
                        src_ip = socket.inet_ntoa(arp_hdr[6])
                        scanner.scan_arp_poisoning(src_ip, src_mac, raw_frame)

                # IPv4 Protocol (0x0800)
                elif eth_type == 0x0800:
                    ip_offset = packet_start + 14
                    ip = IPv4Header.from_buffer(ring, ip_offset)
                    
                    ihl = (ip.ver_ihl & 0x0F) * 4
                    protocol_id = ip.protocol
                    src_ip = format_ip(ip.saddr)

                    # TCP Protocol (6) -> Port Scan Detection
                    if protocol_id == 6:
                        tcp_offset = ip_offset + ihl
                        tcp_bytes = ring[tcp_offset : tcp_offset + 14]
                        if len(tcp_bytes) >= 14:
                            _, dst_port, _, _, _, flags = struct.unpack("!HHIIBB", tcp_bytes)
                            is_syn = (flags & 0x02) > 0
                            is_ack = (flags & 0x10) > 0
                            if is_syn and not is_ack:
                                scanner.scan_port_scan(src_ip, dst_port, raw_frame)

                    # ICMP Protocol (1) -> Volumetric Defense
                    elif protocol_id == 1:
                        scanner.scan_icmp_flood(src_ip, raw_frame)

                # Release Ring Slot back to Kernel DMA
                ring[offset:offset + 4] = struct.pack("I", TP_STATUS_KERNEL)
                frame_idx = (frame_idx + 1) % FRAME_NR

            else:
                # Yield CPU briefly if no new frames in ring slot
                time.sleep(0.0001)

    except KeyboardInterrupt:
        print("\n[+] Shutting down engine cleanly...")
        ring.close()
        raw_socket.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
