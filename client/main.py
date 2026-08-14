from scapy.all import sniff
import struct
import socket
from LUCY.assistant import run_assistant
import threading
import os
from dotenv import load_dotenv

SERVER = "172.16.109.129"
PORT = 5000
IFACE = "en0"


def detect(pkt, client):
    try:
        raw_pkt = bytes(pkt)
        pkt_len = struct.pack("!I", len(raw_pkt))
        client.sendall(pkt_len + raw_pkt)
    except BrokenPipeError:
        print("VM disconnected — stopping capture")
        raise SystemExit
    except Exception as e:
        print("ERROR:", e)



def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER, PORT))

    try:
        sniff(
            iface=IFACE,
            prn=lambda pkt: detect(pkt, client),
            store=False
        )
    except KeyboardInterrupt:
        print("Stopping capture...")
    except BrokenPipeError:
        print("Session terminated on VM")
    finally:
        client.close()


if __name__ == "__main__":
    load_dotenv()

    AI_ENABLED = bool(os.getenv("GEMINI_API_KEY"))
    if AI_ENABLED:
        main_thread = threading.Thread(target=main)
        main_thread.start()

        run_assistant()

        main_thread.join()
        print("Program has fully closed")
    else:
        main()