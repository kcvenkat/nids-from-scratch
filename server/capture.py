from scapy.all import PcapWriter, IP, ICMP, UDP, TCP #type: ignore
from datetime import datetime, timezone
import os
from detectors.utils import tracker

MAX_FILES = 48
ROTATE_INTERVAL = 1800

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

        flags = ""
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
            flags = str(pkt[TCP].flags)

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"
            threshold = 200

        else:
            src_port = "-"
            dst_port = "-"
            return
            
        print(f"{pkt_time}      {src_ip}:{src_port} ---> {dst_ip}:{dst_port}     [{protocol}{':' + flags if flags else ''}]")
        
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

def create_writer():
    writer = PcapWriter(get_filename(), append = False, sync = True)
    return writer

def remove_oldest():
    pcap_files = sorted([f for f in os.listdir("captures") if f.endswith(".pcap")])
    if len(pcap_files) > MAX_FILES:
            os.remove(os.path.join("captures", pcap_files[0]))
    
def rotate(writer):
    writer.close()
    new_writer = create_writer()
    remove_oldest()
    return new_writer