# NIDS From Scratch

A Network Intrusion Detection System (NIDS) pipeline built from scratch using Python sockets and Scapy.

This project captures packets on a macOS host machine, streams them over TCP to an Ubuntu virtual machine, reconstructs the packets remotely, and stores them in rotating PCAP files for later analysis. Currently, only the packet streaming is finished. Detection rules and dashboards will be implemented in the future.

## Features

- Live packet capture with Scapy
- TCP socket packet streaming
- Custom TCP framing protocol
- Exact-byte packet reconstruction
- Rotating PCAP storage
- Automatic retention cleanup
- Human-readable packet logging

## Technologies Used

- Python 3
- Scapy
- TCP sockets
- VMware Fusion
- Ubuntu Server
- tcpdump

## VMware Setup

The project uses a macOS host machine and an Ubuntu Server VM running in VMware Fusion.

The receiving device does not need to be Ubuntu specifically. Any operating system capable of running the required dependencies and communicating with the host machine can function as the collector.

The collector is intentionally separated from the host machine to follow the security principle of storing logs on a separate system.

The VM was configured with a host-only network adapter so the host and VM could communicate over a private internal network.

## Ubuntu VM Setup


Update packages:

```bash
sudo apt update
```

Install Python and pip:

```bash
sudo apt install python3 python3-pip
```

Install tcpdump:

```bash
sudo apt install tcpdump
```

Install Scapy:

```bash
pip install scapy
```

## macOS Setup

Install Scapy:

```bash
pip3 install scapy
```

Run packet sniffing with elevated privileges:

```bash
sudo python3 sniffer.py
```

## Requirements

```text
scapy>=2.5.0
```

## How It Works

The macOS machine acts as the packet sensor.

Scapy captures packets, serializes them into raw bytes, and sends them over a TCP socket to the Ubuntu VM.

Because TCP is a byte-stream protocol and does not preserve message boundaries, the project uses a custom framing protocol:

```text
[length][packet]
```

Each transmitted packet contains:

1. A 4-byte packet length
2. The raw serialized packet bytes

The Ubuntu VM receives the stream, reconstructs the packets using exact-byte reads, rebuilds them with Scapy, and stores them in rotating PCAP files.

## Future Improvements

- Detection engine
- Flow tracking
- Real-time dashboards
- Suricata integration