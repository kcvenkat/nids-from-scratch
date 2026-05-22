from scapy.all import sniff
import struct
import socket

SERVER = "172.16.109.129"
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

def detect(pkt):
    try:
        raw_pkt = bytes(pkt)
        pkt_len = struct.pack("!I", len(raw_pkt))
        client.sendall(pkt_len + raw_pkt)
        
    except Exception as e:
        print("ERROR:", e)

try:
    sniff(iface ="en0", prn= detect, store = False)
finally:
    client.close()