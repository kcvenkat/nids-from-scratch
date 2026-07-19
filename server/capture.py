from scapy.all import PcapWriter, IP, ICMP, UDP, TCP, ARP #type: ignore
from datetime import datetime, timezone
import os
import time
from server.detection.matcher import match_rule
from server.detection.tracker import *
from shared.event import Event
from shared.rule import RULE_OBJECTS
from server.actions.perform import perform_action
from server.detection.tracker import record_packet, record_port, record_unique_host, record_tcp
from shared.loader import load_rules

MAX_FILES = 48
ROTATE_INTERVAL = 1800

def print_formatted(pkt):
    timestamp = time.time()
    pkt_time = datetime.fromtimestamp(
    pkt.time,
    tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")
    timestamp = time.time()

    protocol = None
    event_type = None

    src_port = None
    dst_port = None

    flags = None
    icmp_type = None
    arp_op = None

    if ARP in pkt:
        protocol = "ARP"

        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

        arp_op = pkt[ARP].op
        event_type = f"ARP:{arp_op}"

    elif IP in pkt:

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if ICMP in pkt:
            protocol = "ICMP"

            icmp_type = pkt[ICMP].type
            event_type = f"ICMP:{icmp_type}"

        elif TCP in pkt:
            protocol = "TCP"

            flags = str(pkt[TCP].flags)

            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            event_type = f"TCP:{flags}"

            if flags == "S":
                record_tcp(src_ip, src_port, dst_ip, dst_port)
        elif UDP in pkt:
            protocol = "UDP"

            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            event_type = "UDP"

        else:
            return

    else:
        return
                
    print(f"{pkt_time}      {src_ip}:{src_port} ---> {dst_ip}:{dst_port}     [{event_type}]")
    record_packet(src_ip, dst_ip, event_type)
    record_unique_host(src_ip, dst_ip)
    if src_port is not None and dst_port is not None:
        record_port(src_ip, dst_ip, dst_port, event_type)
    

    event = Event(
        timestamp=timestamp,

        protocol=protocol,
        event_type=event_type,

        src_ip=src_ip,
        dst_ip=dst_ip,

        src_port=src_port,
        dst_port=dst_port,

        flags=flags,
        icmp_type=icmp_type,
        arp_op=arp_op
    )

    for rule in RULE_OBJECTS:
        matched = match_rule(rule, event)
        print(f"[SCAN CHECK] dst_port={dst_port} src={src_ip}:{src_port} -> dst={dst_ip} "
            f"rule_sid={rule.sid} matched={matched}")
        perform_action(rule, event)

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