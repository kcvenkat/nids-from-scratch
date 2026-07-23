import socket
import struct
import os
import time
from scapy.all import Ether
from .capture import *
import readchar
import threading

PORT = 5000
UI_MODE = "menu"
RUNNING = True
conn = None
server = None

def recv_exact(sock, size):
    data = b""

    try:
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
    except OSError:
        return None

    return data


def main():
    global conn, server
    load_rules()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", PORT))
    server.listen(1)

    conn = None
    writer = None

    try:
        print("Listening...")

        conn, addr = server.accept()
        print("Connected:", addr)

        os.makedirs("captures", exist_ok=True)
        writer = create_writer()
        file_create_time = time.time()

        while True:
            if time.time() - file_create_time >= ROTATE_INTERVAL:
                writer = rotate(writer)
                file_create_time = time.time()

            length_data = recv_exact(conn, 4)
            if not length_data:
                print("TCP packet length unable to be acquired.")
                break

            pkt_len = struct.unpack("!I", length_data)[0]
            pkt_data = recv_exact(conn, pkt_len)
            if not pkt_data:
                print("Data break detected. Exiting.")
                break

            pkt = Ether(pkt_data)
            writer.write(pkt)
            pkt_tuple = capture_check(pkt)

            if UI_MODE == "flow" and pkt_tuple is not None:
                print_formatted(pkt_tuple)

    except KeyboardInterrupt:
        print_tracker()

    finally:
        if writer:
            writer.close()
        if conn:
            conn.close()
        server.close()

def menu():
    global UI_MODE
    global RUNNING

    while RUNNING:
        if UI_MODE == "menu":
            print("\n--- MENU ---")
            print("1. Verbose Tracking (press q to quit)")
            print("2. View/Edit Rules")
            print("3. Exit")
            print("Select an option (1-3): ")

            choice = readchar.readkey()

            if choice == "1":
                print("\n-> Verbose tracking enabled. Press 'q' to quit and return to the menu.")
                UI_MODE = "flow"
            elif choice == "2":
                print("\n Opening rules.txt for editing...")
            elif choice == "3":
                print("\n Ending packet captures before exiting the program...")
                RUNNING = False
                if conn:
                    conn.close()
                if server:
                    server.close()
            else:
                print("\nInvalid choice. Try again.")

        elif UI_MODE == "flow":
            choice = readchar.readkey()
            if choice == "q":
                print("\n-> Returning to the main menu...")
                UI_MODE = "menu"

if __name__ == "__main__":
    main_thread = threading.Thread(target=main)
    main_thread.start()

    menu()

    main_thread.join()
    print("Program has fully closed")
