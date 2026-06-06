#This script is to be run on the host to connect with the virtual machine for packet sniffing

from scapy.all import sniff
import struct
import socket

SERVER = "172.16.109.129"
PORT = 5000
IFACE = "en0"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

def detect(pkt):
    try:
        raw_pkt = bytes(pkt)
        pkt_len = struct.pack("!I", len(raw_pkt))
        client.sendall(pkt_len + raw_pkt)
    except BrokenPipeError:
        print("VM disconnected — stopping capture")
        raise SystemExit  # cleanly exits the sniff loop
    except Exception as e:
        print("ERROR:", e)

try:
    sniff(iface = IFACE, prn= detect, store = False)
except KeyboardInterrupt:
    print("Stopping capture...")
except BrokenPipeError:
    print("Session terminated on VM")
finally:
    client.close()