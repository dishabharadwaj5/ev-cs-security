import socket
import json
from datetime import datetime
import secrets
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64
import os
import sys
import psutil
import threading
import time
import keyboard

EV_ID = "EV003"
STATION_ID = "CS124"
SERVER_IP = "10.20.201.5"
SERVER_PORT = 9999
CS_PUBLIC_KEY_FILE = "cs_public_key.pem"
CERT_FILE = "expanded_ev_pinned_certificates.json"
LOCATION_FILE = "location.json"
MAX_KWH = 75

cipher_aes_iv = None
aes_key_global = None
stop_flag = False
sock = None

def get_battery_percentage():
    try:
        battery = psutil.sensors_battery()
        return int(battery.percent) if battery else 60
    except:
        return 60

def get_gps_location():
    try:
        with open(LOCATION_FILE, 'r') as f:
            data = json.load(f)
            return float(data["latitude"]), float(data["longitude"])
    except:
        return 12.971891, 77.641151

def load_fingerprint():
    with open(CERT_FILE) as f:
        data = json.load(f)
        for ev in data:
            if ev["ev_id"] == EV_ID:
                for s in ev["pinned_stations"]:
                    if s["station_id"] == STATION_ID:
                        return s["fingerprint"]
    raise Exception("Fingerprint not found")

def encrypt_payload(payload_dict):
    global cipher_aes_iv, aes_key_global
    aes_key = secrets.token_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(json.dumps(payload_dict).encode(), AES.block_size))
    cipher_aes_iv = cipher_aes.iv
    aes_key_global = aes_key

    with open(CS_PUBLIC_KEY_FILE, "rb") as f:
        cs_pub = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(cs_pub)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    return json.dumps({
        "key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(cipher_aes.iv).decode(),
        "data": base64.b64encode(ciphertext).decode()
    }).encode() + b"\n"

def decrypt_response(encrypted_data):
    decoded = base64.b64decode(encrypted_data)
    cipher = AES.new(aes_key_global, AES.MODE_CBC, cipher_aes_iv)
    decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
    return json.loads(decrypted.decode())

def user_interrupt():
    global stop_flag, sock
    while not stop_flag:
        if keyboard.is_pressed('s'):
            stop_flag = True
            sock.sendall(b"stop_charging\n")
            print("\n⚠ Charging stopped by user.")
            break
        time.sleep(0.1)

def print_progress_bar(current_percent, target_percent):
    bar_len = 30
    filled_len = int(bar_len * current_percent / target_percent)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    percent_display = int((current_percent / target_percent) * 100)
    sys.stdout.write(f"\r Charging: |{bar}| {percent_display}%")
    sys.stdout.flush()

def run_ev_client():
    global stop_flag, sock
    try:
        lat, lon = get_gps_location()
        battery = get_battery_percentage()
        fingerprint = load_fingerprint()

        desired_percent = int(input("Enter desired charge % (e.g., 80): ").strip())
        if not (0 <= desired_percent <= 100):
            print("Invalid percentage.")
            return

        energy_needed = round((desired_percent - battery) * MAX_KWH / 100, 2)
        if energy_needed <= 0:
            print("No additional charge needed.")
            return

        payload = {
            "ev_id": EV_ID,
            "station_id": STATION_ID,
            "presented_fingerprint": fingerprint,
            "location": {"latitude": lat, "longitude": lon},
            "battery": battery,
            "request_power": energy_needed,
            "timestamp": datetime.now().isoformat(),
            "nonce": secrets.token_hex(16)
        }

        encrypted = encrypt_payload(payload)

        sock = socket.socket()
        sock.connect((SERVER_IP, SERVER_PORT))
        sock.sendall(encrypted)

        threading.Thread(target=user_interrupt, daemon=True).start()

        buffer = b""
        while not buffer.endswith(b"\n"):
            part = sock.recv(1024)
            buffer += part
        msg = buffer.decode().strip()
        billing = decrypt_response(msg)
        print("\n Billing Info:")
        for k, v in billing.items():
            print(f"  {k}: {v}")

        current = battery
        target = desired_percent
        print(" Charging started. Press 's' to stop.\n")

        while current < target:
            if stop_flag:
                break
            current += 1
            sock.sendall(f"progress:{current}\n".encode())

            buffer = b""
            while not buffer.endswith(b"\n"):
                buffer += sock.recv(1024)
            update = decrypt_response(buffer.strip())
            print_progress_bar(current, target)
            print(f" ₹{update['bill_amount']}", end='')
            time.sleep(0.5)

        if not stop_flag:
            print("\n Charging complete.")

        sock.sendall(f"final_battery:{current}\n".encode())
        sock.close()

    except Exception as e:
        print("Client error:", e)

if __name__ == "__main__":
    run_ev_client()
