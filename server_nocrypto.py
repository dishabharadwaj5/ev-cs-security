import socket
import json
import os
from datetime import datetime

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999
RATE_PER_KWH = 8
MAX_KWH = 75
LOG_FILE = "cs_sessions.json"

# Ensure log file exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)

# Load certificate dictionaries
def load_cert_dict(path):
    with open(path) as f:
        return {entry['station_id']: {'certificate': entry} for entry in json.load(f)}

legitimate = load_cert_dict("legitimate_charging_stations_expanded.json")
compromised = load_cert_dict("expanded_compromised_expired_stations.json")
fake = load_cert_dict("expanded_attacker_fake_stations.json")
all_stations = {**legitimate, **compromised, **fake}

# Load EV pinned certificates
ev_pins = {}
with open("expanded_ev_pinned_certificates.json") as f:
    for ev in json.load(f):
        ev_pins[ev['ev_id']] = {
            'pinned_stations': {p['station_id']: p['fingerprint'] for p in ev['pinned_stations']}
        }


def log_session(entry):
    try:
        with open(LOG_FILE, "r") as f:
            sessions = json.load(f)
    except:
        sessions = []

    sessions.append(entry)

    with open(LOG_FILE, "w") as f:
        json.dump(sessions, f, indent=4)

# Start server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(5)
print(f"[CS]  Charging Station running on port {SERVER_PORT}")

while True:
    client_socket, addr = server_socket.accept()
    print(f"\n [Connection] From {addr[0]}")

    try:
        # Receive initial request
        buffer = b""
        while not buffer.endswith(b"\n"):
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            buffer += chunk

        if not buffer:
            client_socket.close()
            continue

        payload = json.loads(buffer.decode().strip())
        print("[RECEIVED INIT PAYLOAD]:")
        print(json.dumps(payload, indent=2))

        ev_id = payload.get("ev_id", "UNKNOWN")
        location = payload.get("location", {})
        base_battery = int(payload.get("battery", 0))
        energy_per_percent = MAX_KWH / 100

        print(f" Location: {location.get('latitude')}, {location.get('longitude')}")
        print(f" Starting battery: {base_battery}%")

        # Acknowledge
        response = {
            "status": "charging_started",
            "message": "Session accepted. Send final battery to end."
        }
        client_socket.send(json.dumps(response).encode() + b"\n")

        # Handle progress updates or session end
        while True:
            cmd = client_socket.recv(2048)
            if not cmd:
                break

            try:
                message = json.loads(cmd.decode().strip())
                print("[RECEIVED]:", message)

                if "final_battery" in message:
                    final = int(message["final_battery"])
                    delta = final - base_battery
                    energy_used = round(delta * energy_per_percent, 2)
                    bill = round(energy_used * RATE_PER_KWH, 2)

                    print(f"[ Final] Battery: {final}%, Energy: {energy_used} kWh, Bill: ₹{bill}")

                    session_log = {
                        "timestamp": datetime.now().isoformat(),
                        "ev_id": ev_id,
                        "location": location,
                        "initial_battery": base_battery,
                        "final_battery": final,
                        "energy_used": energy_used,
                        "bill_amount": bill,
                        "currency": "INR"
                    }
                    log_session(session_log)

                    response = {
                        "status": "session_complete",
                        "final_percent": final,
                        "energy_used": energy_used,
                        "bill_amount": bill,
                        "currency": "INR"
                    }
                    client_socket.send(json.dumps(response).encode() + b"\n")
                    break

                else:
                    print("[⚠ SERVER] Unknown message.")
                    continue

            except Exception as e:
                print("[PARSE ERROR]", e)
                client_socket.send(b"REJECT: Invalid format\n")
                continue

    except Exception as e:
        print("[ SERVER ERROR]", e)
    finally:
        client_socket.close()
