#!/usr/bin/env pyhton3

import socket
import struct
import sys
import os

def environment_check():
    if len(sys.argv) < 2:
        print("Interface required")
        print(f"Example uses: python3 {sys.argv[0].split("/")[-1]} [interface_name]")
        sys.exit(1) 

    if os.getuid() != 0:
        print("Run as root!")
        sys.exit(1)

def format_mac(binary_mac):
    return ":".join(f"{b:02x}"for b in binary_mac)

def format_ip(binary_ip):
    return socket.inet_ntoa(binary_ip)



def unpacked_arp_packet(raw_arp_payload):
    unpacked_arp = struct.unpack("!HHBBH6s4s6s4s", raw_arp_payload)
    #unpacked_arp (header_type, protocol_type, head_len, pro_len, opcode, s_mac, s_ip, t_mac, t_ip)
    opcode = unpacked_arp[4]
    sender_mac = format_mac(unpacked_arp[5])
    sender_ip = format_ip(unpacked_arp[6])
    target_mac = format_mac(unpacked_arp[7])
    target_ip = format_ip(unpacked_arp[8])

    if opcode == 1:
        print("ARP REQUEST")
        print(f"Host: {sender_ip} is asking: who has IP {target_ip}")
        print("-" * 60)   
    elif opcode == 2:
        print("    [ARP Protocol Layer Decoded: REPLY]")
        print(f"    ├── Owner IP Address : {sender_ip}")
        print(f"    ├── Hardware MAC Link: {sender_mac}")
        print(f"    └── Target Receiver  : {target_ip} ({target_mac})")
        print("-" * 60)

    
def main():
    environment_check()
    target_interface = sys.argv[1]

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) # 0x0003 flags for all I/O traffic
    raw_socket.bind((target_interface, 0))
    print(f"[+] Multi-protocol Demux Engine active on {target_interface}.....")
    print("[*] Filtering for live ARP (0x0806) packets")

    try:
        while True:
            raw_data, addr = raw_socket.recvfrom(65565)

            eth_header_raw = raw_data[:14]
            _, _, eth_type = struct.unpack("!6s6sH", eth_header_raw)

            if eth_type == 0x0806: # eth_type ARP hex value is : 0x0806
                raw_arp_payload = raw_data[14:14+28] # ARP header size is 28 bytes
                unpacked_arp_packet(raw_arp_payload)
    except KeyboardInterrupt:
        print("[*] Stopping demultiplexing piplines. Closing sockets.")
        raw_socket.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
