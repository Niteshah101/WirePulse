# Programmable Traffic Sniffer & Active Anomaly Engine

A high-performance, low-level network security auditing tool developed in **Python** and **C**. This application interfaces directly with Layer 2 link-layer sockets to ingest raw frame data, demultiplex encapsulation layouts, and execute stateful heuristic tracking to detect active network attacks (such as ARP cache poisoning and aggressive port scanning profiles) in real time.



## System Architecture & Progress Matrix

The engine is engineered to bypass high-level network stack abstractions (like standard TCP/UDP socket bindings) by establishing direct kernel ring interfaces via `AF_PACKET`.