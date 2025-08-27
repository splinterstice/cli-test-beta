#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Muhammed Shafin P
# Licensed under the GNU General Public License v3.0 (GPLv3).
# See the LICENSE file in the project root for full license information.
#

import subprocess
import time
import socket
from stem.control import Controller
import shutil
import tempfile
import os
import atexit
import argparse

tor_proc = None
onion_address, onion_port = None, 8080
freeport = None
freeport_s = None
password = None

def cleanup():
    global tor_proc
    if tor_proc:
        print("[*] Cleaning up Tor process...")
        tor_proc.terminate()
        tor_proc.wait()
atexit.register(cleanup)


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    print(f"[*] Found free port: {port}")
    return port


def get_package_manager():
    for pm in ["apt", "dnf", "yum", "pacman", "zypper"]:
        if shutil.which(pm):
            return pm
    return None


def start_tor(control_port=9051, socket_port=9050):
    data_dir = tempfile.mkdtemp(prefix="tor-")
    cmd = [
        "tor",
        "--ControlPort", str(control_port),
        "--SocksPort", str(socket_port),
        "--CookieAuthentication", "0",
        "--DataDirectory", data_dir,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        if is_port_open("127.0.0.1", control_port):
            return proc
        time.sleep(0.5)
    raise RuntimeError(f"Tor did not open control port {control_port}")


def run_sudo_command(command, password):
    try:
        result = subprocess.run(
            ["sudo", "-S"] + command,
            input=password + "\n",
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Command failed: {e}")
        return False


def install_package(pkg_name, password):
    pm = get_package_manager()
    if not pm:
        print("❌ No supported package manager found.")
        return False

    print(f"📦 Installing {pkg_name} using {pm}...")
    try:
        if pm == "apt":
            run_sudo_command(["apt", "update"], password)
            return run_sudo_command(["apt", "install", "-y", pkg_name], password)
        elif pm == "dnf":
            return run_sudo_command(["dnf", "install", "-y", pkg_name], password)
        elif pm == "yum":
            return run_sudo_command(["yum", "install", "-y", pkg_name], password)
        elif pm == "pacman":
            return run_sudo_command(["pacman", "-Sy", pkg_name, "--noconfirm"], password)
        elif pm == "zypper":
            return run_sudo_command(["zypper", "install", "-y", pkg_name], password)
    except subprocess.CalledProcessError:
        print(f"❌ Failed to install {pkg_name} using {pm}.")
        return False


def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


def setup_hidden_service(local_port: int, onion_port: int = 80, control_port: int = None):
    global onion_address, freeport, freeport_s, tor_proc, password

    # Install Tor if missing
    try:
        if shutil.which("tor") is None:
            raise FileNotFoundError
        else:
            subprocess.run(["tor", "--version"], check=True, capture_output=True)
    except FileNotFoundError:
        print("[*] Tor not found. Installing...")
        if not install_package("tor", password):
            raise RuntimeError("Failed to install Tor.")
        print("[*] Tor installed successfully.")
        time.sleep(2)

    # Stop existing Tor
    tor_running = subprocess.run(["pgrep", "tor"], capture_output=True)
    result_tor_run = subprocess.run(["ps", "-ef"], capture_output=True, text=True)
    if tor_running.returncode == 0 or "tor" in result_tor_run.stdout:
        print("[*] Stopping already running Tor...")
        run_sudo_command(["pkill", "tor"], password)

    # Start Tor
    if control_port is None:
        control_port = freeport
    tor_proc = start_tor(control_port=control_port, socket_port=freeport_s)
    if not is_port_open("127.0.0.1", control_port):
        raise RuntimeError(f"Tor control port {control_port} is not open.")

    # Create hidden service
    with Controller.from_port(port=control_port) as controller:
        controller.authenticate()
        result = controller.create_ephemeral_hidden_service(
            {onion_port: local_port}, await_publication=True
        )
        onion_address = result.service_id + ".onion"
        print('{'+f'"status":"success", "address":"{onion_address}","port":"{onion_port}","socks_port":"{freeport_s}"'+'}')
        return onion_address, onion_port


def return_onion():
    global onion_address, onion_port
    if onion_address is None or onion_port is None:
        print('{"status": "error", message: "Onion service not set up yet."}')
    return onion_address, onion_port


# ---------------- MAIN ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--password", type=str, required=True, help="Sudo password")
    parser.add_argument("--local-port", type=int, default=5000, help="Local app port")
    parser.add_argument("--onion-port", type=int, default=8080, help="Public onion port")
    args = parser.parse_args()

    password = args.password
    freeport = get_free_port()
    freeport_s = get_free_port()
    try:
        onion, port = setup_hidden_service(local_port=args.local_port, onion_port=args.onion_port)
    except :
        print('{"status": "error", message: "Onion service not set up yet."}')

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tor_proc.terminate()
        tor_proc.wait()
        print("\n[*] Exiting and cleaning up...")



    