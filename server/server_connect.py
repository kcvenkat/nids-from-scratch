# This script is to be run on the virtual machine for network log collection
import socket
import struct
from scapy.all import PcapWriter, IP, TCP, UDP, ICMP
import os
from datetime import datetime, timezone
import time
from collections import defaultdict, deque
import uuid
import json

PORT = 5000
MAX_FILES = 48
ROTATE_INTERVAL = 1800

tracker = defaultdict(lambda: {
    "ICMP": deque(),
    "TCP": deque(),
    "UDP": deque()
})

attack_state = defaultdict(lambda: {
    "ICMP": False,
    "TCP": False,
    "UDP": False
})

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen(1)

def print_formatted(pkt):
    pkt_time = datetime.fromtimestamp(
    pkt.time,
    tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")

    threshold = 0

    if IP in pkt:

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        protocol = pkt[IP].proto
        now = time.time()

        if ICMP in pkt:
            src_port = "-"
            dst_port = "-"
            protocol = "ICMP"
            threshold = 50
        elif TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"
            threshold = 100

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"
            threshold = 200

        else:
            src_port = "-"
            dst_port = "-"
            return
        count = track_and_check(src_ip, dst_ip, protocol, 10, threshold)
            
        print(f"{pkt_time}      {src_ip}:{src_port} ---> {dst_ip}:{dst_port}     [{protocol}]")
        
def print_tracker():
    print("\n" + "="*60)
    print(f"{'IP Address':<20} {'Protocol':<10} {'Count'}")
    print("="*60)
    for ip, protocols in tracker.items():
        for proto, timestamps in protocols.items():
            print(f"{ip:<20} {proto:<10} {len(timestamps)}")
    print("="*60 + "\n")
      
def get_filename():
    return datetime.now(tz=timezone.utc).strftime("captures/pcap_%Y-%m-%d_%H-%M-%S.%f.pcap")

def get_window_count(src_ip, protocol, window):
    now = time.time()
    timestamps = tracker[src_ip][protocol]

    while timestamps and now - timestamps[0] > window:
        timestamps.popleft()

    return len(timestamps)

def track_and_check(src_ip, dst_ip, protocol, window, threshold):
    tracker[src_ip][protocol].append(time.time())
    count = get_window_count(src_ip, protocol, window)
    if count > threshold:
        if not attack_state[src_ip][protocol]:
            attack_state[src_ip][protocol] = True
            alert(src_ip, dst_ip, protocol)
            return count
    else:
        attack_state[src_ip][protocol] = False
    return None

def create_writer():
    writer = PcapWriter(get_filename(), append = False, sync = True)
    return writer

def remove_oldest():
    pcap_files = sorted([f for f in os.listdir("captures") if f.endswith(".pcap")])
    if len(pcap_files) > MAX_FILES:
            os.remove(os.path.join("captures", pcap_files[0]))
    
def rotate():
    global writer
    writer.close()
    writer = create_writer()
    remove_oldest()

def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            return None
        
        data += chunk

    return data

def alert(src, dst, protocol):
    print("ALERT ALERT ALERT ALERT ALERT ALERT")
    print()
    print()
    alert_log = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "alert_type": "flood",
        "message": f"{protocol} flood detected from {src}"
    }

    with open("alerts.json", "a") as f:
        f.write(json.dumps(alert_log) + "\n")

try:
    print("listening...")

    conn, addr = server.accept()

    print("Connected", addr)

    os.makedirs("captures", exist_ok = True)
    writer = create_writer()

    file_create_time = time.time()

    while True:
        if time.time() - file_create_time >= ROTATE_INTERVAL:
            rotate()
            file_create_time = time.time()
        
        length_data = recv_exact(conn, 4)

        if not length_data:
            print('TCP packet length unable to be acquired.')
            break

        pkt_len = struct.unpack("!I", length_data)[0]
        pkt_data = recv_exact(conn, pkt_len)

        if not pkt_data:
            print('Data break detected. Exiting.')
            break
        
        pkt = Ether(pkt_data)
        writer.write(pkt)

        print_formatted(pkt)
        
except KeyboardInterrupt:
    print_tracker()
finally:
    writer.close()
    conn.close()
    server.close()