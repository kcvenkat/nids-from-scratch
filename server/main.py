import socket
import struct
import os
import time
from scapy.all import Ether
from .capture import *
import readchar
import threading
from shared.rule_edit import add_rule, edit_rule, remove_rule, view_rules_table, view_rule_details

PORT = 5000
UI_MODE = "menu"
RUNNING = True
conn = None
server = None
connected = threading.Event()

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
        connected.set()

        os.makedirs("captures", exist_ok=True)
        writer = create_writer()
        file_create_time = time.time()

        while RUNNING:
            if time.time() - file_create_time >= ROTATE_INTERVAL:
                writer = rotate(writer)
                file_create_time = time.time()

            length_data = recv_exact(conn, 4)
            if not length_data:
                if UI_MODE != "exit":
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
def collect_sid():
    key = input("\nEnter the SID of the rule you want to view details for: ")
    while not key.isdigit():
        key = input("Invalid SID. Please enter a numeric value: ")
    return int(key)

def rule_edit_menu():
    global UI_MODE

    while UI_MODE == "rule_edit":
        print("\n--- RULE MENU ---")
        print("1. View Rules")
        print("2. View Rule Details")
        print("3. Add Rule")
        print("4. Edit Rule")
        print("5. Delete Rule")

        choice = readchar.readkey()

        if choice == "1":
            view_rules_table()
            print("Press 'q' to return to the rule menu.")
            while True:
                if readchar.readkey().lower() == "q":
                    break
        elif choice == "2":
            key = collect_sid()
            view_rule_details(key)
            print("Press 'q' to return to the rule menu.")
            while True:
                if readchar.readkey().lower() == "q":
                    break
        elif choice == "3":
            rule_string = input("Enter the new rule: ")
            done = add_rule(rule_string)
            if done:
                print("Rule successfully added.")
        elif choice == "4":
            key = collect_sid()
            done = edit_rule(key, new_rule=input("Enter the new rule string: "))
            if done:
                print("Rule successfully edited.")
            else:
                print("Rule edit failed. Please check the SID or RULE SYNTAX and try again.")
        elif choice == "5":
            key = collect_sid()
            done = remove_rule(key)
            if done:
                print("Rule successfully removed.")
            else:
                print("Rule removal failed. Please check the SID and try again.")
        elif choice == "q":
            print("\n-> Returning to the main menu...")
            UI_MODE = "menu"

def menu():
    global UI_MODE, RUNNING

    print("Waiting for connection...")
    connected.wait()

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
                print("\n Opening rule editor...")
                UI_MODE = "rule_edit"
                rule_edit_menu()
                print("Press 'q' to return to the main menu.")
            elif choice == "3":
                print("\n Ending packet captures before exiting the program...")
                RUNNING = False
                if conn:
                    try:
                        conn.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
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
