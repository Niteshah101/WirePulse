import socket
import sys
import os
import struct
import datetime

class NetworkScanEngine:
    def __init__(self):
        self.arp_table = {}
        self.track_port_scan = {}

    def scan_arp_poisioning(self, src_ip, src_mac):
        if src_ip in self.arp_table:
            hst_mac = self.arp_table[src_ip]
            if hst_mac != src_mac:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}][!!] Potential ARP poisioning found for [{src_ip}] from [{src_mac}]")
        else:        
            self.arp_table[src_ip] = src_mac

    def scan_port_scan(self, src_ip, dst_port, threshold_port=5):
        if src_ip not in self.track_port_scan:
            self.track_port_scan[src_ip] = {"dst_port": set(), "is_alerted": False}
        if src_ip in self.track_port_scan:
            self.track_port_scan[src_ip]["dst_port"].add(dst_port)
            scan_port_count = len(self.track_port_scan[src_ip]["dst_port"])
            if (
                scan_port_count > threshold_port
                and not self.track_port_scan[src_ip]["is_alerted"]
            ):
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}][!!] Potential active port scanning found from [{src_ip}]")
                self.track_port_scan[src_ip]["is_alerted"] = True

            else:
                pass


def env_check():
    if os.getuid() != 0:
        print("Root Access required!!")
        sys.exit(1)
    if len(sys.argv) < 2:
        print(f"Use example: python3 {sys.argv[0].split("/")[-1]} [interface]")
        sys.exit(1)


def format_mac(mac_addr_bytes):
    return ":".join(f"{i:02x}" for i in mac_addr_bytes)


def format_ip(ip_addr_bytes):
    return socket.inet_ntoa(ip_addr_bytes)


def parse_ARP_packet(raw_arp_bytes, scanner):
    arp_header = struct.unpack("!HHBBH6s4s6s4s", raw_arp_bytes[:28])
    op_code = arp_header[4]
    src_mac = format_mac(arp_header[5])
    src_ip = format_ip(arp_header[6])
    dst_mac = format_mac(arp_header[7])
    dst_ip = format_ip(arp_header[8])
    scanner.scan_arp_poisioning(src_ip, src_mac)


def parse_TCP_IP_packet(raw_tcp_ip_bytes, scanner):
    if len(raw_tcp_ip_bytes) < 20:
        return
    
    ip_header = struct.unpack("!BBHHHBBH4s4s", raw_tcp_ip_bytes[:20])
    version_ihl = ip_header[0]
    ihl = (version_ihl & 0xF) * 4
    protocol_id = ip_header[
        6
    ]  # if protocol id is '6' then it is tcp connection, 1: ICMP, 17: UDP
    src_ip = format_ip(ip_header[8])
    dst_ip = format_ip(ip_header[9])

    if protocol_id == 6:
        tcp_header = struct.unpack("!HHIIBB", raw_tcp_ip_bytes[ihl : ihl + 14])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        flag = tcp_header[5]
        is_syn = (flag & 0x02) > 0
        is_ack = (flag & 0x10) > 0
        if is_syn and not is_ack:
            scanner.scan_port_scan(src_ip, dst_port)
    else:
        pass


def main():

    env_check()
    interface = sys.argv[1]
    scanner = NetworkScanEngine()
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    raw_socket.bind((interface, 0))
    print(f"Listening on {interface}")
    print("[+] Scanning for ARP poisioning..")
    print("[+] Scanning for Active port scan..\n")
    while True:
        try:
            raw_packet, addr = raw_socket.recvfrom(65535)
            _, _, eth_type = struct.unpack("!6s6sH", raw_packet[:14])
            if eth_type == 0x0806:
                parse_ARP_packet(raw_packet[14:], scanner)
            elif eth_type == 0x0800:
                parse_TCP_IP_packet(raw_packet[14:], scanner)
            else:
                pass

        except KeyboardInterrupt:
            print("Clossing Socket")
            raw_socket.close()
            sys.exit(0)


if __name__ == "__main__":
    main()
