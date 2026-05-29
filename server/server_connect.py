# This script is to be run on the virtual machine for network log collection
import socket
import struct
from scapy.all import Ether, IP, TCP, UDP, ICMP #type:ignore
from .capture import *
import os
import time

PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", PORT))
server.listen(1)

def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            return None
        
        data += chunk

    return data

conn = None
writer = None

try:
    print("listening...")

    conn, addr = server.accept()

    print("Connected", addr)

    os.makedirs("captures", exist_ok = True)
    writer = create_writer()

    file_create_time = time.time()

    while True:
        if time.time() - file_create_time >= ROTATE_INTERVAL:
            writer = rotate(writer)
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
    if writer:
        writer.close()
    if conn:
        conn.close()
    server.close()