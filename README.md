# NIDS From Scratch

A Network Intrusion Detection System (NIDS) pipeline built from scratch using Python sockets and Scapy.

This project captures packets on a macOS host machine, streams them over TCP to an Ubuntu virtual machine, reconstructs the packets remotely, runs modular detection rules against live traffic, and stores alerts and rotating PCAP files for forensic analysis.

## Features

- Live packet capture with Scapy
- TCP socket packet streaming
- Custom TCP framing protocol
- Exact-byte packet reconstruction
- Rotating PCAP storage with 24-hour retention
- Automatic retention cleanup
- Human-readable packet logging
- Modular detection engine
- Flood detection for ICMP, TCP, and UDP
- Sliding window rate-based anomaly detection
- Attack state tracking with deduplication
- Structured JSON alert logging

## Technologies Used

- Python 3
- Scapy
- TCP sockets
- VMware Fusion
- Ubuntu Server

## Project Structure

```
nids-from-scratch/
├── client/
│   └── client_connect.py     # runs on macOS, captures and streams packets
├── server/
│   ├── server_connect.py     # runs on Ubuntu VM, main loop
│   ├── capture.py            # PcapWriter, file rotation, retention
│   └── alert.py              # alert logging to JSON
└── detectors/
    ├── __init__.py           # empty — detector registration coming soon
    └── utils.py              # shared state, sliding window, rate tracking
```

## VMware Setup

The project uses a macOS host machine and an Ubuntu Server VM running in VMware Fusion. The receiving device does not need to be Ubuntu specifically — any machine capable of running the required dependencies and communicating with the host can function as the collector.

The collector is intentionally separated from the host machine to follow the security principle of storing logs on a separate system.

The VM was configured with a host-only network adapter so the host and VM can communicate over a private internal network.

## Ubuntu VM Setup

Update packages:
```bash
sudo apt update
```

Install Python and pip:
```bash
sudo apt install python3 python3-pip
```

Install Scapy:
```bash
pip install scapy --break-system-packages
```

Clone the repository:
```bash
git clone https://github.com/kcvenkat/nids-from-scratch
cd nids-from-scratch
```

Run the server with elevated privileges:
```bash
sudo python3 server/server_connect.py
```

## macOS Setup

Install Scapy:
```bash
pip3 install scapy
```

Run the client with elevated privileges:
```bash
sudo python3 client/client_connect.py
```

## How It Works

The macOS machine acts as the packet sensor. Scapy captures packets on the active network interface, serializes them into raw bytes, and streams them over TCP to the Ubuntu VM using a custom framing protocol:

```
[4-byte length][raw packet bytes]
```

The Ubuntu VM receives the stream, reconstructs each packet using exact-byte reads, and passes it through the detection engine. Each detector runs independently against every packet. If a threshold is crossed, a structured JSON alert is written to `alerts.json` and printed to the terminal.

PCAP files rotate every 30 minutes and are retained for 24 hours before the oldest file is deleted.

## Alert Format

Each alert is written as a JSON line to `alerts.json`:

```json
{
  "id": "8afa056d",
  "timestamp": "2026-05-27T00:32:07.737336+00:00",
  "src_ip": "192.168.0.208",
  "dst_ip": "192.168.0.110",
  "protocol": "ICMP",
  "alert_type": "flood",
  "message": "ICMP flood detected from 192.168.0.208"
}
```

## Adding A New Detector

1. Create or add a function to the appropriate file in `detectors/`
2. The function must accept a single `pkt` argument
3. Import and add it to the `DETECTORS` list in `detectors/__init__.py`

## Requirements

```text
scapy>=2.5.0
```

## Future Improvements

- Additional detectors — port scan, ARP spoof, NULL/FIN/XMAS scan, SSH brute force, DNS tunneling
- Suricata integration
- Real-time dashboard
- LLM-powered alert analysis
- Voice-based AI security assistant