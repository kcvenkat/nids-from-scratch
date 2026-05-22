import socket
import struct
from scapy.all import PcapWriter, Ether, IP, TCP, UDP
import os
from datetime import datetime, timezone
import time

PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen(1)

def print_formatted():
    pkt_time = datetime.fromtimestamp(
    pkt.time,
    tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")

    if IP in pkt:

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        protocol = pkt[IP].proto

        if TCP in pkt:
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

        print(f"{pkt_time}      {src_ip}:{src_port} ---> {dst_ip}:{dst_port}     [{protocol}]")
        
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

    print_formatted()

writer.close()
conn.close()