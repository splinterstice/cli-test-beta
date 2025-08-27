#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Muhammed Shafin P
# Licensed under the GNU General Public License v3.0 (GPLv3).
# See the LICENSE file in the project root for full license information.
#

import subprocess
import sys
import os
import json
import getpass
import threading
import socket
import random
import time
from flask import Flask ,request,jsonify
import hashlib
import os
import base64
import requests
import base58
import base91
import zlib
from Crypto.Cipher import AES   
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import socks
def encode1(data: str) -> str:
    shifted = ''.join(chr((ord(c) + 3) % 256) for c in data)
    return shifted[::-1]

def decode1(data: str) -> str:
    reversed_str = data[::-1]
    return ''.join(chr((ord(c) - 3) % 256) for c in reversed_str)

# -------------------------------
# Method 2 (Custom Base32 Alphabet)
# -------------------------------
custom_alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBA987654"
standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def encode2(data: str) -> str:
    b32 = base64.b32encode(data.encode()).decode()
    return ''.join(
        custom_alphabet[standard_alphabet.index(ch)] if ch in standard_alphabet else ch
        for ch in b32
    )

def decode2(data: str) -> str:
    remapped = ''.join(
        standard_alphabet[custom_alphabet.index(ch)] if ch in custom_alphabet else ch
        for ch in data
    )
    return base64.b32decode(remapped.encode()).decode()

# -------------------------------
# Method 3 (XOR with rotating key + Base85)
# -------------------------------
xor_key = b"SuperSecret"

def encode3(data: str) -> str:
    raw_bytes = data.encode()
    xored = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(raw_bytes)])
    return base64.b85encode(xored).decode()

def decode3(data: str) -> str:
    xored = base64.b85decode(data.encode())
    raw_bytes = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(xored)])
    return raw_bytes.decode()

# -------------------------------
# Method 4 (Reverse + XOR + Custom Tag + Base64 → Base85)
# -------------------------------
custom_tag = "CUSTOMTAG"

def encode4(data: str) -> str:
    reversed_data = data[::-1]
    xored = bytes([ord(c) ^ xor_key[i % len(xor_key)] for i, c in enumerate(reversed_data)])
    tagged = xored + custom_tag.encode()
    b64 = base64.b64encode(tagged)
    return base64.b85encode(b64).decode()

def decode4(data: str) -> str:
    b64 = base64.b85decode(data.encode())
    tagged = base64.b64decode(b64)
    raw = tagged[:-len(custom_tag)]
    reversed_data = ''.join(chr(b ^ xor_key[i % len(xor_key)]) for i, b in enumerate(raw))
    return reversed_data[::-1]

# -------------------------------
# Method 5 (Shift + Base91)
# -------------------------------
def encode5(data: str) -> str:
    shifted = bytes([(ord(c) + 7) % 256 for c in data])
    return base91.encode(shifted)

def decode5(data: str) -> str:
    shifted = base91.decode(data)
    return ''.join(chr((b - 7) % 256) for b in shifted)

# -------------------------------
# Method 6 (Shuffle + Base58)
# -------------------------------
shuffle_map = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "QWERTYUIOPASDFGHJKLZXCVBNMpoiuytrewqlkjhgfdsamnbvcxz9876543210"
)

def encode6(data: str) -> str:
    shuffled = data.translate(shuffle_map).encode()
    return base58.b58encode(shuffled).decode()

def decode6(data: str) -> str:
    shuffled = base58.b58decode(data.encode()).decode()
    reverse_map = {v: k for k, v in shuffle_map.items()}
    return shuffled.translate(str.maketrans(reverse_map))

# -------------------------------
# Method 7 (Binary + Zlib + Base85)
# -------------------------------
def encode7(data: str) -> str:
    binary = ''.join(format(ord(c), '08b') for c in data)
    compressed = zlib.compress(binary.encode())
    return base64.b85encode(compressed).decode()

def decode7(data: str) -> str:
    decompressed = zlib.decompress(base64.b85decode(data.encode())).decode()
    chars = [chr(int(decompressed[i:i+8], 2)) for i in range(0, len(decompressed), 8)]
    return ''.join(chars)

# -------------------------------
# Helper functions (AES-GCM and complex encoding/decoding)
# -------------------------------
def encrypt_message(message: str, key: bytes) -> tuple[str, str, str]:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(cipher.nonce).decode(),
        base64.b64encode(tag).decode()
    )

def decrypt_message(ciphertext_b64: str, nonce_b64: str, tag_b64: str, key: bytes) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def complex_encode(username: str, userid: str, key: bytes) -> str:
    encoded_value = encode4(userid) + ' ' + encode7(username)
    ciphertext, nonce, tag = encrypt_message(encoded_value, key)
    encrypted = ciphertext + ' ' + nonce + ' ' + tag
    encrypted_encoded = encode3(encrypted)
    return encrypted_encoded

def complex_decode(data: str, key: bytes) -> tuple[str, str]:
    decoded_encrypted = decode3(data)
    ciphertext, nonce, tag = decoded_encrypted.split(' ')
    decrypted = decrypt_message(ciphertext, nonce, tag, key)
    encoded_userid, encoded_username = decrypted.split(' ')
    userid = decode4(encoded_userid)
    username = decode7(encoded_username)
    return userid, username

def read_file(path):
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return f.read().strip()
    except:
        return ""
    return ""

def get_stable_device_id():
    # Collect hardware values
    product_uuid = read_file("/sys/class/dmi/id/product_uuid")
    board_serial = read_file("/sys/class/dmi/id/board_serial")
    chassis_serial = read_file("/sys/class/dmi/id/chassis_serial")

    # CPU model (from /proc/cpuinfo)
    cpu_model = ""
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if "model name" in line:
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except:
        pass

    # Combine raw values
    combined = f"{product_uuid}-{board_serial}-{chassis_serial}-{cpu_model}"

    # Encode with Base64
    b64_encoded = base64.b64encode(combined.encode()).decode()

    # Hash the Base64 result
    device_id = hashlib.sha256(b64_encoded.encode()).hexdigest()
    return device_id

# ------------------ Config ------------------
key_db = {
    'sample1': 'my_secret_key',
    'sample2': 'another_secret',
    'sample3': 'different_key',
    'sample4': 'unique_key_value',
    'sample5': 'key_for_testing',
    'sample6': 'secure_key123',
    'sample7': 'test_key_value',
    'sample8': 'example_key_456',
    'sample9': 'my_test_key_789',
    'sample10': 'final_key_value'
}

onion_address = None
onion_port = None
chosen_key_id = None
chosen_key_value = None
user_id = get_stable_device_id()
check_address = None
login_address = 'http://41.216.189.250:6080/check'
register_address = 'http://41.216.189.250:6080/save'
login_address_forclinet = '41.216.189.250'
login_port_for_clinet = 5030
sock_port = None
username_ = None
available_contacts = []
client_socket = None
messages = []
messages_lock = threading.Lock()
contacts = []
DSP_FILE = os.path.join(os.path.dirname(__file__), "dspem.py")

# ------------------ Helpers ------------------
def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def check_password(pwd: str) -> bool:
    try:
        result = subprocess.run(
            ["sudo", "-S", "true"],
            input=pwd + "\n",
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False

def run_dspem(password, local_port=5000, onion_port=8080):
    """Run dspem.py and check if Tor service started correctly."""
    cmd = [
        sys.executable, "-u",
        DSP_FILE,
        "--password", password,
        "--local-port", str(local_port),
        "--onion-port", str(onion_port)
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    success = False

    def reader():
        nonlocal success
        global onion_address, onion_port
        for line in iter(proc.stdout.readline, ''):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("status") == "success":
                    onion_address = data["address"]
                    onion_port = int(data["port"])
                    sock_port = int(data["socks_port"])
                    print(f"✅ Onion Service Running: {onion_address}:{onion_port} ,socks port: {sock_port}")
                    success = True
                    break
                elif data.get("status") == "error":
                    print("❌ Tor can't be started:", data.get("message", "Unknown error"))
                    proc.terminate()
                    success = False
                    break
            except json.JSONDecodeError:
                print("[dspem]", line, flush=True)

    # run in same thread (blocking) until success/error
    reader()
    return proc if success else None

# ------------------ Main ------------------
if __name__ == "__main__":
    # 1. Ask password until correct
    password = None
    while True:
        pwd = getpass.getpass("Enter sudo password: ")
        if check_password(pwd):
            password = pwd
            break
        else:
            print("❌ Wrong password, try again.")

    # 2. Ask onion port
    while True:
        try:
            user_port = int(input("Enter onion port (1024–65535): "))
            if 1024 <= user_port <= 65535:
                break
            else:
                print("❌ Port must be between 1024 and 65535.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    # 3. Choose key
    key_list = list(key_db.items())
    max_index = len(key_list) - 1
    while True:
        try:
            choice = int(input(f"Choose key index (0–{max_index}, or -1 for random): "))
            if choice == -1:
                chosen_key_id, chosen_key_value = random.choice(key_list)
                print(f"🔑 Random key chosen: {chosen_key_id}")
                break
            elif 0 <= choice <= max_index:
                chosen_key_id, chosen_key_value = key_list[choice]
                print(f"🔑 Key chosen: {chosen_key_id}")
                break
            else:
                print("❌ Invalid index.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    # 4. Pick local port
    local_port = get_free_port()
    print(f"🔌 Local Flask port: {local_port}")

    # 5. Start Tor first
    proc = run_dspem(password, local_port=local_port, onion_port=user_port)
    if not proc:
        print("❌ Exiting because Tor service failed.")
        sys.exit(1)
    

    def check_user_registered():
        global check_address,chosen_key_id, chosen_key_value,user_id,register_address
        print('userid:',user_id)
        encoded_data_created = complex_encode(user_id,user_id,SHA256.new(chosen_key_value.encode()).digest())

        register_check = requests.post(login_address, json={
            "sid": chosen_key_id,
            "encoded_data":encoded_data_created})
        if  register_check.json().get("status") == "found":
            print("✅ User already registered.")
        else:
            print("❌ User not registered. Please register first.")
            print("➡️ Redirecting to registration...")
            while True:
                please_input = input("please enter your username for registration: ")
                if please_input:
                    break
                else:
                    print("❌ Username cannot be empty.")
            value = base64.b64encode(user_id.encode()).decode()
            encoded_data_register = complex_encode(value,user_id,SHA256.new(chosen_key_value.encode()).digest())
            register_it = requests.post(register_address, json={
                "sid": chosen_key_id,
                "username": please_input,
                "encoded_data": encoded_data_register
            })
            if register_it.json().get("status") == "success":
                print("✅ Registration successful.")
            else:
                print("❌ Registration failed. Please try again.")
                sys.exit(1)
    check_user_registered()
    current_directory = os.path.dirname(os.path.abspath(__file__))
    contacts_file_path = os.path.join(current_directory, "data.jsonl")

    def save_contact(userid: str, username: str):
        """Save a contact as base64 encoded JSON line"""
        entry = {
            "userid": base64.b64encode(userid.encode()).decode(),
            "username": base64.b64encode(username.encode()).decode()
        }
        with open(contacts_file_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def load_contacts():
        """Load and decode contacts from the file"""
        global contacts_file_path,contacts
        if os.path.exists(contacts_file_path):
            with open(contacts_file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        userid = base64.b64decode(entry.get("userid","")).decode()
                        username = base64.b64decode(entry.get("username","")).decode()
                        contacts.append({"userid": userid, "username": username})
                    except Exception as e:
                        print("❌ Error reading contact:", e)
        return contacts
    if not os.path.exists(contacts_file_path):
        # Create file if not found
        open(contacts_file_path, "w").close()
        print("📄 No contacts file found. Created new file.")
    else:
        contacts = load_contacts()
        if not contacts:
            print("ℹ️ No contacts found.")
        else:
            print(f"✅ Contacts found ({len(contacts)}):")
            for c in contacts:
                print(f" - {c['username']}")
    def login_and_check():
        global check_address, chosen_key_id, chosen_key_value, user_id, login_address,contacts,login_address_forclinet,login_port_for_clinet,onion_address,onion_port,sock_port,username_,available_contacts,client_socket

        for i in contacts:
            user_id_ = i['userid']
            encoded_data_created_ = complex_encode(user_id_,user_id_,SHA256.new(chosen_key_value.encode()).digest())
            register_check_ = requests.post(login_address, json={
                "sid": chosen_key_id,
                "encoded_data":encoded_data_created_})
            if  register_check_.json().get("status") == "found":
                print(f"✅ Contact '{i['username']}' is registered.")
                available_contacts.append(i)
            else:
                print(f"❌ Contact '{i['username']}' is NOT registered.")
        try:
            client_socket = socks.socksocket()
            client_socket.set_proxy(socks.SOCKS5, "127.0.0.1", sock_port)
            client_socket.connect((login_address_forclinet, login_port_for_clinet))
            print(f"✅ Connected to server via Tor at to login address.")
        except Exception as e:
            print("❌ Failed to connect to server via Tor. Check your Tor setup.")
            print("Error details:", e)
            sys.exit(1)
        key = SHA256.new(chosen_key_value.encode()).digest()
        print("[+] Phase 1: Sending login request...")
        username_ = input("Enter your username for login: ").strip()
        encoded_user_data = complex_encode(username_, user_id, key)
        login_request = {
            "value": "login",
            "sid": chosen_key_id,
            "encoded_user_data": encoded_user_data
        }
        client_socket.sendall(json.dumps(login_request).encode())
        login_response = json.loads(client_socket.recv(4096).decode())
        if login_response.get("status") != "true":
            print("[-] Login failed. Exiting.")
            client_socket.close()
            sys.exit(1)
        print("[+] Login successful.")
        print("[+] Phase 2: Authecating...")
        encoded_ip_port = complex_encode(onion_address,f'{onion_port}',key)
        main1_request = {
            "value": "main1",
            "encoded_ip_port": encoded_ip_port,
      # A sample port for this client
            "sid": chosen_key_id
        }
        client_socket.sendall(json.dumps(main1_request).encode())
        main1_response = json.loads(client_socket.recv(4096).decode())
        if main1_response.get("status") != "true":
            print("[-] User status update failed. Exiting.")
            client_socket.close()
            sys.exit(1)
        print("[+] User status updated successfully.")
        if available_contacts:
            print("[+] checking for available contacts for messaging:")
            for i in available_contacts:
                TARGET_USERID = i['userid']
                TARGET_USERNAME = i['username']
                encoded_request_data = complex_encode(TARGET_USERID,TARGET_USERNAME,key)
                request_data_request = {
                "value": "request",
                "encoded_request_data": encoded_request_data,
                "sid": chosen_key_id
                }
                client_socket.sendall(json.dumps(request_data_request).encode())
                request_data_response = json.loads(client_socket.recv(4096).decode())
                if request_data_response.get("status") == "true":
                    encoded_data = request_data_response.get("encoded_data")
                    decoded_port,decoded_ip = complex_decode(encoded_data, key)
                    i.update({"ip":decoded_ip,"port":decoded_port})
                else:
                    print(f"[-] Request for user :{i['username']} data failed.")
                    continue
        else:
            print("[-] No available contacts to check.")
        if available_contacts:
                print("✅ Available contacts for messaging:")
                for c in available_contacts:
                    print(f" - {c['username']}")
        else:
                print("❌ No contacts available for messaging.")
    login_and_check()
    def add_message(msg):
        """Thread-safe append to messages"""
        with messages_lock:
            messages.append(msg)

    def get_messages():
        """Thread-safe read of all messages"""
        with messages_lock:
            return list(messages)  # return a copy
        


    # 6. Only start Flask if Tor was successful
    app = Flask(__name__)

    @app.route("/",methods=["POST"])
    def home():
        global messages
        try:
            request_got = request.get_json() or {}
            usernow_=None
            if request_got:
                checking_user = request_got.get("encoded_data")
                checking_sid = request_got.get("sid")
                for i in available_contacts:
                    try:
                        keyvalue = key_db.get(checking_sid)
                        userid, username = complex_decode(checking_user, SHA256.new(keyvalue.encode()).digest())
                        if userid == i['userid'] and username == i['username']:
                            usernow_ = i
                            break
                    except:
                        continue
                got = request_got.get("value")
                gotdecoded = base64.b64decode(got).decode()
                nowtime = time.strftime("%H:%M:%S", time.localtime())
                add_message({'fromname': usernow_['username'],'fromid':usernow_['userid'],'time':nowtime,'toid':user_id,'toname':username_,"message": gotdecoded})
            if usernow_:
                return jsonify({"status": "success"})
            return jsonify({"status": "fail"})
        except:
            return jsonify({"status": "error"})
    

    threading.Thread(
        target=lambda: app.run(port=local_port, debug=False, use_reloader=False),
        daemon=True
    ).start()
    print(f"🚀 Flask server started on http://127.0.0.1:{local_port}")
    def send_message(targetuserid, message):
        global client_socket, chosen_key_id, chosen_key_value
        key = SHA256.new(chosen_key_value.encode()).digest()
        f=0
        for i in available_contacts:
            if i['userid'] == targetuserid:
                f=1
                if 'ip' in i and 'port' in i:
                    target_username = i['username']
                    target_ip = i['ip']
                    target_port = int(i['port'])
                    break
        if f==0:
            print("[-] Target user not found in available contacts.")
            return {'status':'not_found'}
        else:
            encoded_data_setted = complex_encode(target_username,targetuserid, key)
            message_encoded = base64.b64encode(message.encode())
            message_request = {
                "value": message_encoded.decode(),
                "sid": chosen_key_id,
                "encoded_data": encoded_data_setted
            }
            try:
                response = requests.post(f"http://{target_ip}:{target_port}/", json=message_request,proxies={"http": f"socks5h://127.0.0.1:{sock_port}","https": f"socks5h://127.0.0.1:{sock_port}"},timeout=10)
                if response.status_code == 200:
                    resp_json = response.json()
                    if resp_json.get("status") == "success":
                        return {'status': 'success'}
                    else:
                        return {'status': 'fail'}
                else:
                    return {'status': 'http_error'}
            except requests.exceptions.ConnectTimeout:
                    return {'status': 'timeout'}
            except requests.exceptions.ConnectionError:
                    return {'status': 'connection_error'}
            except requests.exceptions.RequestException as e:
                    return {'status': 'exception', 'error': str(e)}

    def reupdate_contacts():
        global contacts, available_contacts,contacts_file_path,chosen_key_id, chosen_key_value,login_address,key_db,client_socket
        key= SHA256.new(chosen_key_value.encode()).digest()
        try:
            available_contacts = []

            if not os.path.exists(contacts_file_path):
                # Create file if not found
                open(contacts_file_path, "w").close()
                print("📄 No contacts file found. Created new file.")
            else:
                contacts = load_contacts()
                if not contacts:
                    print("ℹ️ No contacts found.")
                    available_contacts = []
                else:
                    for i in contacts:
                        user_id_ = i['userid']
                        encoded_data_created_ = complex_encode(user_id_,user_id_,SHA256.new(chosen_key_value.encode()).digest())
                        register_check_ = requests.post(login_address, json={
                            "sid": chosen_key_id,
                            "encoded_data":encoded_data_created_})
                        if  register_check_.json().get("status") == "found":
                            print(f"✅ Contact '{i['username']}' is registered.")
                            available_contacts.append(i)
                        else:
                            pass
            if available_contacts:
                print("[+] checking for available contacts for messaging:")
                for i in available_contacts:
                    TARGET_USERID = i['userid']
                    TARGET_USERNAME = i['username']
                    encoded_request_data = complex_encode(TARGET_USERID,TARGET_USERNAME,key)
                    request_data_request = {
                    "value": "request",
                    "encoded_request_data": encoded_request_data,
                    "sid": chosen_key_id
                    }
                    client_socket.sendall(json.dumps(request_data_request).encode())
                    request_data_response = json.loads(client_socket.recv(4096).decode())
                    if request_data_response.get("status") == "true":
                        encoded_data = request_data_response.get("encoded_data")
                        decoded_port,decoded_ip = complex_decode(encoded_data, key)
                        i.update({"ip":decoded_ip,"port":decoded_port})
                    else:
                        continue
            else:
                pass
            if available_contacts:
                return {'status':'success'}
        except:
            return {'status':'error'}

    import curses
    import time
    import threading

    def live_ui(stdscr):
        curses.curs_set(1)
        stdscr.nodelay(True)
        input_str = ""
        
        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            mid = width // 2  # vertical split

            # --------- Left Pane: Messages ---------
            stdscr.addstr(0, 0, "Messages:")
            with messages_lock:
                display_msgs = messages[-(height-5):]  # last N messages
                for idx, msg in enumerate(display_msgs):
                    line = f"{msg['time']} | {msg['fromname']}: {msg['message']}"
                    if idx+1 < height:
                        stdscr.addstr(1+idx, 0, line)

            # --------- Right Pane: Contacts ---------
            stdscr.addstr(0, mid+1, "Contacts:")
            with messages_lock:
                if not available_contacts:
                    stdscr.addstr(1, mid+1, "No contacts")
                else:
                    for idx, c in enumerate(available_contacts):
                        line = f"{c['userid']} | {c['username']}"
                        if idx+1 < height:
                            stdscr.addstr(1+idx, mid+1, line)

            # --------- Input line at bottom ---------
            stdscr.addstr(height-2, 0, "Type: " + input_str)
            stdscr.clrtoeol()
            stdscr.refresh()

            # --------- Handle input ---------
            try:
                ch = stdscr.getch()
                if ch == -1:
                    time.sleep(0.05)
                    continue
                elif ch in (10, 13):  # Enter key
                    if input_str.strip().startswith("@"):
                        try:
                            parts = input_str.strip().split(" ", 1)
                            target_id = parts[0][1:]  # remove @
                            msg_text = parts[1] if len(parts) > 1 else ""
                            if msg_text:
                                # Try sending the message
                                result = send_message(target_id, msg_text)
                                
                                # If network-related error, retry after reupdate_contacts
                                if result['status'] in ('timeout', 'http_error', 'connection_error'):
                                    reupdate_contacts()  # refresh available_contacts
                                    # Check if target is still online
                                    target_contact = next((c for c in available_contacts if c['userid'] == target_id), None)
                                    if target_contact and 'ip' in target_contact and 'port' in target_contact:
                                        # Try sending again
                                        result = send_message(target_id, msg_text)
                                    else:
                                        result = {'status': 'fail', 'error': f"{target_id} is offline or unreachable."}
                                
                                # Add message to local messages for display
                                add_message({
                                    'fromname': username_,
                                    'fromid': user_id,
                                    'time': time.strftime("%H:%M:%S"),
                                    'toid': target_id,
                                    'toname': next((c['username'] for c in available_contacts if c['userid']==target_id), target_id),
                                    'message': msg_text
                                })
                                
                                # If still failed, show system message
                                if result['status'] != 'success':
                                    add_message({
                                        'fromname': "System",
                                        'fromid': "0",
                                        'time': time.strftime("%H:%M:%S"),
                                        'toid': user_id,
                                        'toname': username_,
                                        'message': f"Failed to send to {target_id}: {result.get('error', result['status'])}"
                                    })

                        except Exception as e:
                            add_message({
                                'fromname': "System",
                                'fromid': "0",
                                'time': time.strftime("%H:%M:%S"),
                                'toid': user_id,
                                'toname': username_,
                                'message': f"Invalid format: {str(e)}"
                            })
                    input_str = ""

                elif ch in (8, 127):  # Backspace
                    input_str = input_str[:-1]
                else:
                    input_str += chr(ch)
            except:
                pass

    # Start the live CLI UI in a daemon thread
    threading.Thread(target=curses.wrapper, args=(live_ui,), daemon=True).start()
   


    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        proc.terminate()
        client_socket.close()
        print("\n[*] Exiting...")
        exit(0)

