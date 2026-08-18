import socket
import struct
import os
import time
from scapy.all import Ether
from .capture import *
import readchar
import threading
from server.data_objects.rule_edit import add_rule, edit_rule, remove_rule, view_rules_table, view_rule_details

PORT = 5000
UI_MODE = "menu"
RUNNING = True
RULE_RECV_PORT = 5001
conn = None
server = None
connected = threading.Event()

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SERVER_DIR)

RULES_FILE = os.path.join(ROOT_DIR, "rules.txt")
ALERTS_FILE = os.path.join(ROOT_DIR, "alerts.jsonl")
LOGS_FILE = os.path.join(ROOT_DIR, "logs.jsonl")

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

def send_text(sock, text):
    data = text.encode("utf-8")

    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)

def read_text_file(path):
    if not os.path.exists(path):
        return "ERROR: File not found."

    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        return f"ERROR: {e}"

def ai_listener():
    ai_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ai_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ai_server.bind(("0.0.0.0", RULE_RECV_PORT))
    ai_server.listen(1)
    ai_server.settimeout(1.0)

    try:
        while RUNNING:
            try:
                ai_conn, rule_addr = ai_server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                length_data = recv_exact(ai_conn, 4)
                if length_data is None:
                    continue
                data_len = struct.unpack("!I", length_data)[0]
                rule_data = recv_exact(ai_conn, data_len)
                if rule_data is None:
                    continue
                message = rule_data.decode("utf-8")

                if message == "GET_RULES":
                    rules = read_text_file(RULES_FILE)
                    send_text(ai_conn, rules)
                elif message == "GET_ALERTS":
                    alerts = read_text_file(ALERTS_FILE)
                    send_text(ai_conn, alerts)
                elif message == "GET_LOGS":
                    logs = read_text_file(LOGS_FILE)
                    send_text(ai_conn, logs)
                elif message.startswith("APPEND_RULES|"):
                    new_rules = message.split("|", 1)[1]
                    if not new_rules.strip():
                        send_text(ai_conn,"EMPTY")
                    else:
                        with open(RULES_FILE, "a", encoding="utf-8") as f:
                            f.write("\n" + new_rules.strip())
                        send_text(ai_conn, "OK")
                else:
                    send_text(ai_conn, "ERROR: Unknown command")
            except (OSError, UnicodeDecodeError) as e:
                print(f"ERROR: {e}")
            finally:
                ai_conn.close()
    finally:
        ai_server.close()

def main():
    global RUNNING, conn, server
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
            if length_data is None:
                if RUNNING:
                    print("TCP packet length unable to be acquired.")
                break

            pkt_len = struct.unpack("!I", length_data)[0]
            pkt_data = recv_exact(conn, pkt_len)
            if pkt_data is None:
                if RUNNING:
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
                UI_MODE = "exit"
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
    packet_thread = threading.Thread(target=main)
    ai_thread = threading.Thread(target=ai_listener)

    packet_thread.start()
    ai_thread.start()

    menu()

    packet_thread.join()
    ai_thread.join()
    print("Program has fully closed")
