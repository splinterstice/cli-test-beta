#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Muhammed Shafin P
# Licensed under the GNU General Public License v3.0 (GPLv3).
# See the LICENSE file in the project root for full license information.
#

from flask import Flask, request, jsonify
from supabase import create_client, Client
import os
import base64
import base58
import base91
import zlib
from Crypto.Cipher import AES   
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

app = Flask(__name__)
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
key_db = {
    'sample1':'my_secret_key','sample2':'another_secret','sample3':'different_key','sample4':'unique_key_value',
    'sample5':'key_for_testing','sample6':'secure_key123','sample7':'test_key_value','sample8':'example_key_456',
    'sample9':'my_test_key_789','sample10':'final_key_value'
}
# Load Supabase credentials (e.g., from environment variables)
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

TABLE_NAME = "userdata"

@app.route("/save", methods=["POST"])
def save_user_data():
    data = request.get_json() or {}
    encoded_data = data.get('encoded_data')
    sid = data.get('sid')
    key = SHA256.new(key_db[sid].encode()).digest()
    user_id,value = complex_decode(encoded_data,key)
    username = data.get("username")
    
    if not all([username, user_id, value]):
        return jsonify({"status": 'error'})
    
    try:

            supabase.table(TABLE_NAME).insert({
                  "username": username,
                  "userid": user_id,
                  "value": value
              }).execute()

            supabase.table("users").insert({
                  "username": username,
                  "userid": user_id,
              }).execute()
        
    except:
        return jsonify({"status": 'error'})
    else:
        return jsonify({"status": 'success'})
@app.route("/check", methods=["POST"])
def check_user():
    data = request.get_json() or {}
    encoded_data = data.get('encoded_data')
    sid = data.get('sid')
    key = SHA256.new(key_db[sid].encode()).digest()
    user_id,value = complex_decode(encoded_data,key)
    
    if not all([value, user_id]):
        return jsonify({"status": 'error'})
    
    try:
        response = supabase.table(TABLE_NAME).select("*").eq("userid", user_id).execute()
        records = response.data
        if records:
            return jsonify({"status": 'found'})
        else:
            return jsonify({"status": 'not found'})
    except:
        return jsonify({"status": 'error'})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6080, debug=True)
