import socket
import json
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode
from Crypto.Util.Padding import unpad, pad
from datetime import datetime
import hashlib

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999
LOG_FILE = "cs_sessions.json"
RATE_PER_KWH = 8
MAX_KWH = 75
PRIVATE_KEY_FILE = "cs_private_key.pem"

# Ensure log file exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)

# Load private RSA key
with open(PRIVATE_KEY_FILE, "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

def decrypt_aes_key(encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(b64decode(encrypted_key))

def decrypt_payload(encrypted_key, iv, encrypted_data):
    aes_key = decrypt_aes_key(encrypted_key)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, b64decode(iv))
    decrypted = unpad(cipher_aes.decrypt(b64decode(encrypted_data)), AES.block_size)
    payload = json.loads(decrypted.decode())

    try:
        dt = datetime.fromisoformat(payload["timestamp"]).astimezone()
        payload["date"] = dt.strftime("%Y-%m-%d")
        payload["time"] = dt.strftime("%H:%M:%S")
        payload["day"] = dt.strftime("%A")
    except:
        payload["date"] = "00-00-0000"
        payload["time"] = "00:00:00"
        payload["day"] = "Unknown"

    return payload, aes_key, b64decode(iv)

def encrypt_response(aes_key, iv, response_dict):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = pad(json.dumps(response_dict).encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return b64encode(encrypted).decode()

def generate_token(payload):
    loc = payload.get("location", {})
    fields = [
        payload.get("ev_id", ""),
        payload.get("station_id", ""),
        payload.get("date", ""),
        payload.get("time", ""),
        str(loc.get("latitude", "")),
        str(loc.get("longitude", "")),
        str(payload.get("battery", "")),
        str(payload.get("request_power", ""))
    ]
    return hashlib.sha256("|".join(fields).encode()).hexdigest()

def is_replay(token):
    try:
        with open(LOG_FILE) as f:
            logs = json.load(f)
        return any(generate_token(entry) == token for entry in logs)
    except:
        return False

def is_stale(timestamp_str, max_age=120):
    try:
        request_time = datetime.fromisoformat(timestamp_str).astimezone()
        now = datetime.now().astimezone()
        delta = (now - request_time).total_seconds()
        print(f"[INFO] Timestamp delta: {delta:.2f} seconds")
        return delta > max_age or delta < -10
    except:
        return True

def log_session(entry):
    try:
        with open(LOG_FILE) as f:
            logs = json.load(f)
    except:
        logs = []
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

# Start server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(5)
print(f"\n Charging Station running on port {SERVER_PORT}...")

while True:
    client_socket, addr = server_socket.accept()
    print(f"\n[ New connection from {addr[0]} ]")

    try:
        data = client_socket.recv(4096)
        if not data:
            client_socket.close()
            continue

        try:
            encrypted_packet = json.loads(data.decode())
        except Exception as e:
            print("[ DECODE ERROR]", e)
            client_socket.send(b"REJECT: Could not decode incoming packet\n")
            client_socket.close()
            continue

        payload, aes_key, iv = decrypt_payload(
            encrypted_packet["key"],
            encrypted_packet["iv"],
            encrypted_packet["data"]
        )

        loc = payload.get("location", {})
        lat = loc.get("latitude", "N/A")
        lon = loc.get("longitude", "N/A")
        print(f"[EV Location] Latitude: {lat}, Longitude: {lon}")

        if is_stale(payload.get("timestamp", "")):
            client_socket.send(b"REJECT: Stale timestamp\n")
            client_socket.close()
            continue

        token = generate_token(payload)
        if is_replay(token):
            client_socket.send(b"REJECT: Replay attack\n")
            client_socket.close()
            continue

        log_session(payload)

        base_battery = int(payload.get("battery", 0))
        energy_per_percent = MAX_KWH / 100

        bill_response = {
            "status": "charging_started",
            "message": "Session accepted. Send progress updates."
        }
        encrypted_msg = encrypt_response(aes_key, iv, bill_response)
        client_socket.send(encrypted_msg.encode() + b"\n")

        while True:
            cmd = client_socket.recv(2048)
            if not cmd:
                break

            if cmd.strip() == b"stop_charging":
                print("Charging stopped by EV.")
                break

            try:
                decoded = b64decode(cmd.strip())
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
                data_obj = json.loads(decrypted.decode())

                if "progress" in data_obj:
                    current = int(data_obj["progress"])
                    delta = current - base_battery
                    energy_used = round(delta * energy_per_percent, 2)
                    bill = round(energy_used * RATE_PER_KWH, 2)
                    print(f"[Progress] Battery: {current}%, Energy: {energy_used} kWh, Bill: ₹{bill}")

                    response = {
                        "status": "in_progress",
                        "current_percent": current,
                        "energy_used": energy_used,
                        "bill_amount": bill,
                        "currency": "INR"
                    }
                    encrypted_msg = encrypt_response(aes_key, iv, response)
                    client_socket.send(encrypted_msg.encode() + b"\n")

                elif "final_battery" in data_obj:
                    final = int(data_obj["final_battery"])
                    delta = final - base_battery
                    energy_used = round(delta * energy_per_percent, 2)
                    bill = round(energy_used * RATE_PER_KWH, 2)
                    print(f"[Final] Battery: {final}%, Energy: {energy_used} kWh, Bill: ₹{bill}")

                    final_log = {
                        **payload,
                        "final_battery": final,
                        "energy_used": energy_used,
                        "bill_amount": bill,
                        "currency": "INR"
                    }
                    log_session(final_log)

                    response = {
                        "status": "session_complete",
                        "final_percent": final,
                        "energy_used": energy_used,
                        "bill_amount": bill,
                        "currency": "INR"
                    }
                    encrypted_msg = encrypt_response(aes_key, iv, response)
                    client_socket.send(encrypted_msg.encode() + b"\n")
                    break

                else:
                    print("[SERVER] Unknown message.")
                    continue

            except Exception as e:
                print("[PARSE ERROR]", e)
                client_socket.send(b"REJECT: Invalid format\n")
                continue

    except Exception as e:
        print("[SERVER ERROR]", e)
    finally:
        client_socket.close()

 
