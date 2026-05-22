# This script is to be run on the virtual machine for network log collection
import socket
import struct
from scapy.all import PcapWriter, Ether, IP, TCP, UDP, ICMP
import os
from datetime import datetime, timezone
import time
from collections import defaultdict

PORT = 5000
WINDOW = 10

tracker = defaultdict(lambda: {
    "ICMP": {"count": 0, "window_start": time.time()},
    "TCP": {"count": 0, "window_start": time.time()},
    "UDP": {"count": 0, "window_start": time.time()}
})

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen(1)

def print_formatted(pkt):
    pkt_time = datetime.fromtimestamp(
    pkt.time,
    tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")

    if IP in pkt:

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        protocol = pkt[IP].proto
        now = time.time()

        if ICMP in pkt:
            src_port = "-"
            dst_port = "-"
            protocol = "ICMP"
        elif TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"

        else:
            src_port = "-"
            dst_port = "-"
            return

        print(f"{pkt_time}      {src_ip}:{src_port} ---> {dst_ip}:{dst_port}     [{protocol}]")

        if now - tracker[src_ip][protocol]["window_start"] >= WINDOW:
            tracker[src_ip][protocol]["count"] = 0
            tracker[src_ip][protocol]["window_start"] = now
        
        tracker[src_ip][protocol]["count"] += 1
        
def print_tracker(pkt):
    print("\n" + "="*60)
    print(f"{'IP Address':<20} {'Protocol':<10} {'Count':<10} {'Window Age'}")
    print("="*60)
    for ip, protocols in tracker.items():
        for proto, data in protocols.items():
            age = round(time.time() - data["window_start"], 2)
            print(f"{ip:<20} {proto:<10} {data['count']:<10} {age}s")
    print("="*60 + "\n")
      
def get_filename():
    return datetime.now(tz=timezone.utc).strftime("captures/pcap_%Y-%m-%d_%H-%M-%S.%f.pcap")

def create_writer():
    writer = PcapWriter(get_filename(), append = False, sync = True)
    return writer

def remove_oldest():
    pcap_files = sorted([f for f in os.listdir("captures") if f.endswith(".pcap")])
    if len(pcap_files) > 12:
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

try:
    print("listening...")

    conn, addr = server.accept()

    print("Connected", addr)

    os.makedirs("captures", exist_ok = True)
    writer = create_writer()

    file_create_time = time.time()

    while True:
        if time.time() - file_create_time>= 300:
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
    print_tracker(pkt)
finally:
    writer.close()
    conn.close()
    server.close()