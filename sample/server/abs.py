#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Muhammed Shafin P
# Licensed under the GNU General Public License v3.0 (GPLv3).
# See the LICENSE file in the project root for full license information.
#


# custom_encoders_socket.py
import socket
import threading
import json
import base64
import base91
import base58
import zlib
import datetime
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from supabase import create_client, Client

# --- Supabase Configuration ---
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
if not SUPABASE_URL or not SUPABASE_KEY:
    print("[-] Please set SUPABASE_URL and SUPABASE_KEY environment variables.")
    exit()
    print("For now, using dummy values. This will not connect to a real database.")

def get_supabase_client() -> Client:
    """Initializes and returns a Supabase client."""
    return create_client(SUPABASE_URL, SUPABASE_KEY)

# All the original encoding and decoding methods
# -------------------------------
# Method 1 (Shift + Reverse)
# -------------------------------
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

# -------------------------------
# Shared Data and Configuration
# -------------------------------
key_db = {
    'sample1':'my_secret_key','sample2':'another_secret','sample3':'different_key','sample4':'unique_key_value',
    'sample5':'key_for_testing','sample6':'secure_key123','sample7':'test_key_value','sample8':'example_key_456',
    'sample9':'my_test_key_789','sample10':'final_key_value'
}

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5030
BUFFER_SIZE = 6000

# A lock to safely update the shared database from multiple threads
db_lock = threading.Lock()

# -------------------------------
# Socket Server and Handler
# -------------------------------
def client_handler(conn: socket.socket, addr: tuple):
    """
    Handles a single client connection, managing the login, data update,
    and data request phases using Supabase.
    """
    print(f"[+] New connection from {addr[0]}:{addr[1]}")
    current_userid = None
    supabase = get_supabase_client()
    
    try:
        # Phase 1: Login
        data = conn.recv(BUFFER_SIZE)
        if not data:
            raise ValueError("No data received, disconnecting.")
        
        request = json.loads(data.decode())
        
        if request.get("value") == 'login':
            sid = request.get("sid")
            encoded_user_data = request.get("encoded_user_data")
            
            if sid not in key_db:
                conn.sendall(json.dumps({"status": "false", "message": "Invalid sid"}).encode())
                return

            key = SHA256.new(key_db[sid].encode()).digest()
            userid, username = complex_decode(encoded_user_data, key)
            
            with db_lock:
                response = supabase.table('users').select('*').eq('userid', userid).execute()
                user_record = response.data[0] if response.data else None
            
            if user_record and user_record.get("username") == username:
                current_userid = userid
                conn.sendall(json.dumps({"status": "true", "message": "Login successful. Please send 'main1' with your IP and port."}).encode())
            else:
                conn.sendall(json.dumps({"status": "false", "message": "Invalid credentials"}).encode())
                return
        else:
            conn.sendall(json.dumps({"status": "false", "message": "First request must be 'login'"}).encode())
            return
            
        # Phase 2: Update IP and Port
        data = conn.recv(BUFFER_SIZE)
        if not data:
            raise ValueError("No data received, disconnecting.")

        request = json.loads(data.decode())
        if request.get("value") == 'main1' and current_userid:
            sid = request.get("sid")
            encoded_ip_port = request.get("encoded_ip_port")
            key = SHA256.new(key_db[sid].encode()).digest()
            port,ip = complex_decode(encoded_ip_port, key)

            
            if sid not in key_db:
                conn.sendall(json.dumps({"status": "false", "message": "Invalid sid"}).encode())
                return
            
            # Update user data in Supabase, including login details
            now = datetime.datetime.now(datetime.timezone.utc)
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S.%f%z")
            with db_lock:
                # First, get the current record to save the previous login time
                response = supabase.table('users').select('login_time').eq('userid', current_userid).execute()
                old_login_time = response.data[0]['login_time'] if response.data and 'login_time' in response.data[0] else None

                supabase.table('users').update({
                    "ip": ip,
                    "port": port,
                    "is_online": True,
                    "login_time": formatted_time,
                    "day": now.strftime("%A"),
                    "last_login": old_login_time
                }).eq('userid', current_userid).execute()
            
            conn.sendall(json.dumps({"status": "true", "message": "User status updated"}).encode())
        else:
            conn.sendall(json.dumps({"status": "false", "message": "Second request must be 'main1'"}).encode())
            return

        # Phase 3: Handle subsequent requests
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            
            request = json.loads(data.decode())
            if request.get("value") == 'request' and current_userid:
                sid = request.get("sid")
                key = SHA256.new(key_db[sid].encode()).digest()
                encoded_request_data = request.get("encoded_request_data")
                target_username,target_userid = complex_decode(encoded_request_data, key)
                print('Request for:', target_userid, target_username)


                
                if sid not in key_db:
                    conn.sendall(json.dumps({"status": "false", "message": "Invalid sid"}).encode())
                    continue

                key = SHA256.new(key_db[sid].encode()).digest()
                with db_lock:
                    response = supabase.table('users').select('*').eq('userid', target_userid).execute()
                    target_user = response.data[0] if response.data else None
                
                if target_user:
                    if target_username != target_user.get("username"):
                        conn.sendall(json.dumps({"status": "false", "message": "Username does not match"}).encode())
                        continue
                    if target_user["is_online"]:
                        re_encoded_data = complex_encode(target_user["ip"], target_user["port"], key)
                        conn.sendall(json.dumps({"status": "true", "encoded_data": re_encoded_data}).encode())
                    else:
                        conn.sendall(json.dumps({"status": "false", "message": "User is offline"}).encode())
                else:
                    conn.sendall(json.dumps({"status": "false", "message": "User not found"}).encode())
            else:
                conn.sendall(json.dumps({"status": "false", "message": "Invalid request"}).encode())
                
    except (socket.error, json.JSONDecodeError, ValueError) as e:
        print(f"[-] Error from {addr}: {e}")
    except Exception as e:
        conn.sendall(json.dumps({"status": "false", "message": f"An error occurred:"}).encode())
    finally:
        # Cleanup: Mark user offline on disconnection
        if current_userid:
            with db_lock:
                try:
                    supabase.table('users').update({"is_online": False}).eq('userid', current_userid).execute()
                    print(f"[-] User {current_userid} disconnected.")
                except Exception as e:
                    print(f"[-] Failed to update user status in Supabase: {e}")
        conn.close()

def main_server():
    """
    Initializes and runs the main socket server.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5) # Max 5 queued connections
    print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}")
    
    while True:
        try:
            conn, addr = server_socket.accept()
            # Start a new thread for each client
            client_thread = threading.Thread(target=client_handler, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            server_socket.close()
            break
        except Exception as e:
            print(f"Server error: {e}")

if __name__ == "__main__":
    main_server()
