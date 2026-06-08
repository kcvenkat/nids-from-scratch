from scapy.all import PcapWriter, IP, ICMP, UDP, TCP, ARP #type: ignore
from datetime import datetime, timezone
import os
from detectors.utils import *
from detectors import DETECTORS

MAX_FILES = 48
ROTATE_INTERVAL = 1800

def print_formatted(pkt):
    pkt_time = datetime.fromtimestamp(
    pkt.time,
    tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")

    if ARP in pkt:
        event_type = f"ARP:{pkt[ARP].op}"
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        src_port = "-"
        dst_port = "-"
        
    elif IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        event_type = pkt[IP].proto

        if ICMP in pkt:
            event_type = f"ICMP:{pkt[ICMP].type}"
            src_port = "-"
            dst_port = "-"
        elif TCP in pkt:
            event_type = f"TCP:{pkt[TCP].flags}"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            
            conn = (src_ip, src_port, dst_ip, dst_port)
            record_port(src_ip, dst_ip, event_type, dst_port)
            
            if event_type == "TCP:S":
                record_tcp(src_ip, src_port, dst_ip, dst_port)
            elif event_type == "TCP:SA":
                conn = reverse_conn(conn)
                if conn in tcp_connection_tracker:
                    set_synack(conn)
            elif event_type == "TCP:A":
                if conn in tcp_connection_tracker:
                    set_ack(conn)
        elif UDP in pkt:
            event_type = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            record_port(src_ip, dst_ip, event_type, dst_port)
        else:
            src_port = "-"
            dst_port = "-"
            return
    else:
        return
            
    print(f"{pkt_time}      {src_ip}:{src_port} ---> {dst_ip}:{dst_port}     [{event_type}]")
    record_packet(src_ip, event_type)
        
    for detector in DETECTORS:
        if detector(src_ip, dst_ip, event_type):
            return

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