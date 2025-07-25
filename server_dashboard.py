

import socket
import json
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode
from Crypto.Util.Padding import unpad, pad
from datetime import datetime
import hashlib
import threading
import time
from flask import Flask, jsonify, render_template_string
import queue

# ====== SERVER CONFIGURATION ======
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999
DASHBOARD_PORT = 5000
LOG_FILE = "cs_sessions.json"
RATE_PER_KWH = 8.0
MAX_KWH_CAPACITY = 75

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


# ====== GLOBAL SECURITY FLAGS ======
USE_CRYPTOGRAPHY = True

# ====== SERVER STATE ======
server_logs = queue.Queue(maxsize=1000)
active_sessions = {}
session_log_data = []
logged_replay_tokens = set()
attack_log = []

def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}"
    print(log_entry)
    try:
        server_logs.put_nowait(log_entry)
    except queue.Full:
        server_logs.get_nowait()
        server_logs.put_nowait(log_entry)

# --- Load/Create Session Log File ---
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)
    log_message(f"[CS] Created new log file: {LOG_FILE}", "INFO")
else:
    try:
        with open(LOG_FILE, "r") as f:
            session_log_data = json.load(f)
        log_message(f"[CS] Loaded existing log file: {LOG_FILE}", "INFO")
        for entry in session_log_data:
            if entry.get("status") == "rejected" and entry.get("reason") == "replay_attack":
                # Always include timestamp for cryptography, exclude for plain JSON
                token_fields = [
                    entry.get("ev_id", ""),
                    entry.get("station_id", ""),
                    entry.get("timestamp", "") if entry.get("use_cryptography", True) else "",
                    str(entry.get("location", {}).get("latitude", "")),
                    str(entry.get("location", {}).get("longitude", "")),
                    str(entry.get("battery", "")),
                    str(entry.get("request_power", "")),
                    str(entry.get("desired_percent", ""))
                ]
                token = hashlib.sha256("|".join(token_fields).encode('utf-8')).hexdigest()
                logged_replay_tokens.add(token)
            if entry.get("status") == "rejected":
                attack_log.append(entry)
    except Exception as e:
        log_message(f"[CS WARNING] Could not load log file: {e}. Starting empty.", "WARN")
        session_log_data = []

# --- RSA Key Generation/Loading ---
def generate_rsa_key_pair():
    log_message("[CS] Generating new RSA key pair...", "INFO")
    key = RSA.generate(2048)
    with open("cs_private_key.pem", "wb") as f:
        f.write(key.export_key())
    with open("cs_public_key.pem", "wb") as f:
        f.write(key.publickey().export_key())
    return key

try:
    if not os.path.exists("cs_private_key.pem") or not os.path.exists("cs_public_key.pem"):
        private_key = generate_rsa_key_pair()
    else:
        with open("cs_private_key.pem", "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
except Exception as e:
    log_message(f"[CS ERROR] RSA key error: {e}. Regenerating...", "ERROR")
    private_key = generate_rsa_key_pair()

# ====== CRYPTOGRAPHY FUNCTIONS ======
def decrypt_aes_key(encrypted_key_b64):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(b64decode(encrypted_key_b64))

def decrypt_payload(encrypted_key_b64, iv_b64, encrypted_data_b64):
    aes_key = decrypt_aes_key(encrypted_key_b64)
    iv = b64decode(iv_b64)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher_aes.decrypt(b64decode(encrypted_data_b64))
    decrypted_unpadded = unpad(decrypted_padded, AES.block_size)
    payload = json.loads(decrypted_unpadded.decode('utf-8'))
    return payload, aes_key, iv

def encrypt_response(aes_key, iv, response_dict):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = pad(json.dumps(response_dict).encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return b64encode(encrypted).decode('utf-8')

def generate_token(payload, use_cryptography=USE_CRYPTOGRAPHY):
    loc = payload.get("location", {})
    relevant_fields = [
        payload.get("ev_id", ""),
        payload.get("station_id", ""),
        payload.get("timestamp", "") if use_cryptography else "",
        str(loc.get("latitude", "")),
        str(loc.get("longitude", "")),
        str(payload.get("battery", "")),
        str(payload.get("request_power", "")),
        str(payload.get("desired_percent", ""))
    ]
    raw_string = "|".join(relevant_fields)
    return hashlib.sha256(raw_string.encode('utf-8')).hexdigest()

def is_replay(token):
    try:
        with open(LOG_FILE) as f:
            logs = json.load(f)
        return any(generate_token(entry, entry.get("use_cryptography", True)) == token for entry in logs)
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

def log_session_to_file(entry):
    session_log_data.append(entry)
    try:
        with open(LOG_FILE, "w") as f:
            json.dump(session_log_data, f, indent=2)
    except Exception as e:
        log_message(f"[CS ERROR] Could not write to log file: {e}", "ERROR")

# ====== CLIENT HANDLING ======
def handle_client(client_socket, addr):
    initial_battery_percent = 0
    current_battery_on_server = 0
    client_aes_key = None
    client_iv = None
    session_id = f"{addr[0]}-{time.time()}"

    try:
        log_message(f"\n[CS] New connection from {addr[0]}:{addr[1]}", "INFO")
        data = client_socket.recv(4096)
        if not data:
            log_message("[CS] No data received from client. Connection closed.", "INFO")
            return

        # Public key request
        if data.strip() == b'GET_PUBLIC_KEY':
            with open("cs_public_key.pem", "rb") as f:
                client_socket.sendall(f.read())
            return

        # Process Charging Request
        payload = {}
        use_cryptography = USE_CRYPTOGRAPHY
        if use_cryptography:
            try:
                encrypted_packet = json.loads(data.decode('utf-8'))
                payload, client_aes_key, client_iv = decrypt_payload(
                    encrypted_packet["key"],
                    encrypted_packet["iv"],
                    encrypted_packet["data"]
                )
            except Exception as e:
                log_message(f"[CS ERROR] Decryption failed: {e}", "ERROR")
                attack_entry = {
                    "status": "rejected",
                    "reason": "mitm_attack",
                    "details": "Decryption failed",
                    "ip": addr[0],
                    "timestamp": datetime.now().isoformat(),
                    "use_cryptography": True
                }
                log_session_to_file(attack_entry)
                attack_log.append(attack_entry)
                client_socket.sendall(b"REJECT: MITM attack or invalid encryption\n")
                return

            # Timestamp check ONLY for cryptography
            if is_stale(payload.get("timestamp", "")):
                log_message("[CS] REJECTED: Replay attack (stale timestamp)", "WARN")
                attack_entry = {
                    **payload,
                    "status": "rejected",
                    "reason": "replay_attack",
                    "ip": addr[0],
                    "timestamp": datetime.now().isoformat(),
                    "use_cryptography": True
                }
                log_session_to_file(attack_entry)
                attack_log.append(attack_entry)
                client_socket.sendall(b"REJECT: Replay attack (stale timestamp)\n")
                return

        else:
            try:
                payload = json.loads(data.decode('utf-8'))
            except Exception as e:
                log_message(f"[CS ERROR] Invalid JSON: {e}", "ERROR")
                attack_entry = {
                    "status": "rejected",
                    "reason": "invalid_json",
                    "details": "Invalid JSON",
                    "ip": addr[0],
                    "timestamp": datetime.now().isoformat(),
                    "use_cryptography": False
                }
                log_session_to_file(attack_entry)
                attack_log.append(attack_entry)
                client_socket.sendall(b"REJECT: Invalid JSON.\n")
                return
            # NO timestamp staleness check here for non-crypto branch

        session_id = payload.get("session_id", session_id)
        initial_battery_percent = payload.get("battery", 0)
        current_battery_on_server = initial_battery_percent

        # Replay attack: duplicate token
        token = generate_token(payload, use_cryptography)
        if token in logged_replay_tokens:
            log_message("[CS] REJECTED: Replay attack (duplicate token, already logged)", "WARN")
            attack_entry = {
                **payload,
                "status": "rejected",
                "reason": "replay_attack",
                "ip": addr[0],
                "timestamp": datetime.now().isoformat(),
                "use_cryptography": use_cryptography
            }
            attack_log.append(attack_entry)
            client_socket.sendall(b"REJECT: Replay attack (already logged)\n")
            return

        if is_replay(token):
            log_message("[CS] REJECTED: Replay attack (duplicate token)", "WARN")
            attack_entry = {
                **payload,
                "status": "rejected",
                "reason": "replay_attack",
                "ip": addr[0],
                "timestamp": datetime.now().isoformat(),
                "use_cryptography": use_cryptography
            }
            log_session_to_file(attack_entry)
            logged_replay_tokens.add(token)
            attack_log.append(attack_entry)
            client_socket.sendall(b"REJECT: Replay attack\n")
            return

        # Normal session logging
        active_sessions[session_id] = {
            "session_id": session_id,
            "ev_id": payload.get("ev_id", "N/A"),
            "status": "Charging",
            "initial_battery": initial_battery_percent,
            "current_battery": initial_battery_percent,
            "desired_percent": payload.get("desired_percent", 0),
            "energy_charged": 0.0,
            "bill_amount": 0.0,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "location": payload.get("location", ""),
            "stop_reason": "",
        }

        # Send initial response
        initial_response = {
            "status": "session_accepted",
            "message": "Session accepted. Please send progress updates.",
            "rate_per_kwh": RATE_PER_KWH,
            "bill_amount": 0.0,
            "energy": 0.0,
            "currency": "INR"
        }
        if use_cryptography:
            encrypted_msg = encrypt_response(client_aes_key, client_iv, initial_response)
            client_socket.sendall(encrypted_msg.encode('utf-8') + b"\n")
        else:
            client_socket.sendall(json.dumps(initial_response).encode('utf-8') + b"\n")

        charging_started_time = time.time()
        charging_active = True
        final_energy_charged = 0.0
        stop_reason = "timeout"

        while charging_active:
            try:
                client_socket.settimeout(10)
                cmd_raw = client_socket.recv(4096)
                if not cmd_raw:
                    break

                if cmd_raw.strip().startswith(b"stop_charging"):
                    try:
                        parts = cmd_raw.decode('utf-8').strip().split(':')
                        if len(parts) > 1:
                            current_battery_on_server = int(parts[1])
                    except:
                        pass
                    stop_reason = "user_stop"
                    charging_active = False
                    energy_consumed_percent = max(0, current_battery_on_server - initial_battery_percent)
                    final_energy_charged = round((energy_consumed_percent / 100) * MAX_KWH_CAPACITY, 2)
                    break

                if use_cryptography:
                    decoded_msg = cmd_raw.decode('utf-8').strip()
                    cipher = AES.new(client_aes_key, AES.MODE_CBC, client_iv)
                    decrypted_padded = cipher.decrypt(b64decode(decoded_msg))
                    client_msg = json.loads(unpad(decrypted_padded, AES.block_size).decode('utf-8'))
                else:
                    client_msg = json.loads(cmd_raw.decode('utf-8').strip())

                if "progress" in client_msg:
                    current_battery_on_server = int(client_msg["progress"])
                    energy_consumed_percent = max(0, current_battery_on_server - initial_battery_percent)
                    energy_used = round((energy_consumed_percent / 100) * MAX_KWH_CAPACITY, 2)
                    bill = round(energy_used * RATE_PER_KWH, 2)
                    response = {
                        "status": "in_progress",
                        "current_percent": current_battery_on_server,
                        "energy_used": energy_used,
                        "bill_amount": bill,
                        "currency": "INR"
                    }
                    if use_cryptography:
                        encrypted_resp = encrypt_response(client_aes_key, client_iv, response)
                        client_socket.sendall(encrypted_resp.encode('utf-8') + b"\n")
                    else:
                        client_socket.sendall(json.dumps(response).encode('utf-8') + b"\n")

                    if session_id in active_sessions:
                        active_sessions[session_id]["current_battery"] = current_battery_on_server
                        active_sessions[session_id]["energy_charged"] = energy_used
                        active_sessions[session_id]["bill_amount"] = bill

                elif "final_battery" in client_msg:
                    final_battery = int(client_msg["final_battery"])
                    current_battery_on_server = final_battery
                    stop_reason = "charging_complete"
                    energy_consumed_percent = max(0, final_battery - initial_battery_percent)
                    final_energy_charged = round((energy_consumed_percent / 100) * MAX_KWH_CAPACITY, 2)
                    charging_active = False
                    break

            except socket.timeout:
                if time.time() - charging_started_time > 30:
                    stop_reason = "timeout"
                    break
                continue
            except Exception:
                stop_reason = "server_error"
                break

        if stop_reason == "timeout" and final_energy_charged == 0.0:
            energy_consumed_percent = max(0, current_battery_on_server - initial_battery_percent)
            final_energy_charged = round((energy_consumed_percent / 100) * MAX_KWH_CAPACITY, 2)

        total_cost = round(final_energy_charged * RATE_PER_KWH, 2)

        if session_id in active_sessions:
            active_sessions[session_id].update({
                "status": "charging_complete",
                "current_battery": current_battery_on_server,
                "energy_charged": final_energy_charged,
                "bill_amount": total_cost,
                "stop_reason": stop_reason,
                "pending_remove_time": time.time() + 10,
                "final_bill": dict(active_sessions[session_id]),
            })

        loc = active_sessions[session_id].get("location", "")
        loc_str = ""
        if isinstance(loc, dict):
            lat = loc.get("latitude", "")
            lng = loc.get("longitude", "")
            loc_str = f"{lat}, {lng}" if lat and lng else ""
        else:
            loc_str = str(loc)

        final_bill_response = {
            "status": "charging_complete",
            "current_percent": current_battery_on_server,
            "energy": final_energy_charged,
            "rate_per_kwh": RATE_PER_KWH,
            "bill_amount": total_cost,
            "currency": "INR",
            "current_battery_at_start": initial_battery_percent,
            "current_battery_at_end": current_battery_on_server,
            "target_battery": payload.get("desired_percent"),
            "session_start": payload.get("timestamp"),
            "session_end": datetime.now().isoformat(),
            "stop_reason": stop_reason,
            "location": loc_str,
        }
        if use_cryptography:
            encrypted_bill = encrypt_response(client_aes_key, client_iv, final_bill_response)
            client_socket.sendall(encrypted_bill.encode('utf-8') + b"\n")
        else:
            client_socket.sendall(json.dumps(final_bill_response).encode('utf-8') + b"\n")
        client_socket.sendall(b"stop_charging\n")

    finally:
        try:
            client_socket.close()
        except:
            pass

def cleanup_finished_sessions():
    while True:
        now = time.time()
        to_remove = []
        for sid, sess in list(active_sessions.items()):
            if "pending_remove_time" in sess and now >= sess["pending_remove_time"]:
                log_session_to_file(sess["final_bill"])
                to_remove.append(sid)
        for sid in to_remove:
            del active_sessions[sid]
        time.sleep(1)

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/status")
def get_status():
    now = time.time()
    filtered = []
    for sid, sess in active_sessions.items():
        if "pending_remove_time" not in sess or now < sess["pending_remove_time"]:
            loc = sess.get("location", "")
            loc_str = ""
            if isinstance(loc, dict):
                lat = loc.get("latitude", "")
                lng = loc.get("longitude", "")
                loc_str = f"{lat}, {lng}" if lat and lng else ""
            else:
                loc_str = str(loc)
            filtered.append({
                "session_id": sess.get("session_id", sid),
                "ev_id": sess.get("ev_id", ""),
                "status": sess.get("status", ""),
                "initial_battery": f"{sess.get('initial_battery','')}%",
                "current_battery": f"{sess.get('current_battery','')}%",
                "desired_percent": f"{sess.get('desired_percent','')}%",
                "energy_charged": f"{sess.get('energy_charged','')} kWh",
                "bill_amount": f"₹{sess.get('bill_amount','')}",
                "start_time": sess.get("start_time", ""),
                "location": loc_str,
                "stop_reason": sess.get("stop_reason", ""),
            })
    return jsonify({
        "use_cryptography": USE_CRYPTOGRAPHY,
        "active_sessions": filtered,
        "rate_per_kwh": RATE_PER_KWH,
        "max_kwh_capacity": MAX_KWH_CAPACITY,
    })

@app.route("/api/session_history")
def get_session_history():
    try:
        with open(LOG_FILE, "r") as f:
            log_data = json.load(f)
        table_rows = []
        for sess in log_data:
            loc = sess.get("location", "")
            loc_str = ""
            if isinstance(loc, dict):
                lat = loc.get("latitude", "")
                lng = loc.get("longitude", "")
                loc_str = f"{lat}, {lng}" if lat and lng else ""
            else:
                loc_str = str(loc)
            table_rows.append({
                "session_id": sess.get("session_id", ""),
                "ev_id": sess.get("ev_id", ""),
                "status": sess.get("status", ""),
                "initial_battery": f"{sess.get('initial_battery','')}%",
                "current_battery": f"{sess.get('current_battery','')}%",
                "desired_percent": f"{sess.get('desired_percent','')}%",
                "energy_charged": f"{sess.get('energy_charged','')} kWh",
                "bill_amount": f"{sess.get('bill_amount','')}",
                "start_time": sess.get("start_time", ""),
                "location": loc_str,
                "stop_reason": sess.get("stop_reason", ""),
            })
        return jsonify(table_rows)
    except Exception:
        return jsonify([])

@app.route("/api/logs")
def get_logs():
    logs = []
    while not server_logs.empty():
        logs.append(server_logs.get())
    return jsonify(logs)

@app.route("/api/attacks")
def get_attacks():
    return jsonify(attack_log)

@app.route("/api/toggle_crypto", methods=["POST"])
def toggle_crypto():
    global USE_CRYPTOGRAPHY
    USE_CRYPTOGRAPHY = not USE_CRYPTOGRAPHY
    log_message(f"[CS] Toggled USE_CRYPTOGRAPHY to: {USE_CRYPTOGRAPHY}", "INFO")
    return jsonify({"success": True, "use_cryptography": USE_CRYPTOGRAPHY})


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title> Charging Station Server Dashboard</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">        
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@700;500&family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        html, body { background: #eaf1ff; font-family: 'Inter', 'Segoe UI', Arial, sans-serif; }
        .dashboard-title {
            font-family: 'Montserrat', 'Segoe UI', Arial, sans-serif;
            font-size: 2.4rem;
            letter-spacing: .02em;
            font-weight: 700;
            color: #131d36;
            background: #fafdff;
            border-radius: 20px;
            box-shadow: 0 4px 16px #303e8240;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 30px 38px 25px 36px;
            margin-bottom: 32px;
            margin-top: 24px;
        }
        .crypto-state-badge {
            margin-left: 10px;
            font-size: 1.035rem;
            font-weight: 600;
        }
        .metrics-row {
            margin: 0 -10px;
            margin-bottom: 20px;
        }
        .metric-card {
            background: linear-gradient(135deg,#cfe3fd 0,#eaf2ff 100%);
            border-radius: 18px;
            box-shadow: 0 2px 12px #a9bee540;
            text-align: center;
            padding: 26px 3px 18px 3px;
            margin: 0 10px 26px 10px;
        }
        .metric-card .metric-val {
            font-family: 'Montserrat',Arial,sans-serif;
            font-size: 2.07rem;
            color: #264170;
            font-weight: 700;
        }
        .metric-label {
            font-size: 1.09rem;
            margin-top: 3px;
            color: #304a7a;
        }
        .section {
            background: #fafdff;
            border-radius: 18px;
            box-shadow: 0 2px 8px #bac9ee30;
            padding: 27px 2vw 22px 2vw;
            margin-bottom: 25px;
        }
        .server-info-box {
            background: #f2f6fb;
            border-radius: 12px;
            color: #152554;
            padding: 1.5rem 2.3rem 1.2rem 2.3rem;
            font-size: 1.13rem;
            margin-bottom: 0;
        }
        .info-grid {
            display: flex; flex-wrap: wrap;
            justify-content: space-between; align-items: center;
            gap: 2rem;
        }
        .info-item strong { color:#05143e; font-weight:600;}
        .form-switch .form-check-input:checked {
            background-color: #0d6efd !important;
            border-color: #0d6efd !important;
        }
        #cryptoToggle:disabled { pointer-events:none; }
        .table-section {margin-top:30px;}
        .server-log-pre {
            background: #f4f5f7;
            padding: 9px 15px;
            border-radius: 8px;
            font-size: 1.06rem;
            box-shadow: 0 1px 5px #dbe2ed30;
            max-height:145px;
            overflow-y:auto;
        }
        .toggle-dark {
            position: fixed; top:26px; right:37px;
            z-index:17; background:#ecf2fa; border:1.5px solid #d0d7e7;
            border-radius: 20px; padding: 7px 18px; cursor:pointer;
            font-size:1.1rem; box-shadow:0 2px 7px #b3caec22;
            transition: background 0.2s,border 0.2s;
        }
        .toggle-dark:hover {background:#e5f0ff; }
        body.dark-mode {background: #19223a;}
        body.dark-mode .section,
        body.dark-mode .dashboard-title,
        body.dark-mode .metrics-row .metric-card,
        body.dark-mode .server-info-box {background:#202b43; color:#e3e6f2;}
        body.dark-mode .server-log-pre {background:#262d43;color:#c8e1ff;}
        body.dark-mode .table thead {background:#262d43;color:#c8e1ff;}
        body.dark-mode .metric-card {background:linear-gradient(115deg,#516885 0%,#252c54 100%)!important;}
        body.dark-mode #cryptoToggle~label {color:#e7eaf8;}
    </style>
</head>
<body>
<button class="toggle-dark" onclick="toggleDarkMode()">🌓 Toggle Dark Mode</button>
<div class="container">

  <div class="dashboard-title">
    <div>
      <span style="font-size:2.33rem;vertical-align:-4px;">🔌</span> Charging Station Server Dashboard
    </div>
    <span id="crypto_state_badge" class="crypto-state-badge badge bg-success">Cryptography ON</span>
  </div>

  <div class="row metrics-row g-4">
    <div class="col-12 col-md-3">
      <div class="metric-card">
        <div class="metric-val" id="card_total_sessions">-</div>
        <div class="metric-label">Total Sessions</div>
      </div>
    </div>
    <div class="col-12 col-md-3">
      <div class="metric-card">
        <div class="metric-val" id="card_active_sessions">-</div>
        <div class="metric-label">Active Sessions</div>
      </div>
    </div>
    <div class="col-12 col-md-3">
      <div class="metric-card">
        <div class="metric-val" id="card_attack_count">-</div>
        <div class="metric-label">Attack Events</div>
      </div>
    </div>
    <div class="col-12 col-md-3">
      <div class="metric-card">
        <div class="metric-val" id="card_crypto_state">-</div>
        <div class="metric-label">Cryptography</div>
      </div>
    </div>
  </div>

  <div class="section mb-4">
    <h4 class="mb-4" style="font-size:1.18rem;font-weight:600;">Security Controls</h4>
    <div class="form-check form-switch d-flex align-items-center justify-content-center mb-2" style="gap:1rem;">
      <input class="form-check-input" type="checkbox" id="cryptoToggle">
      <label class="form-check-label" for="cryptoToggle" style="font-weight:500;">Use Cryptography</label>
    </div>
  </div>

  <div class="section mb-4">
    <h4 class="mb-4" style="font-size:1.18rem;font-weight:600;">Server Information</h4>
    <div class="info-grid">
      <div class="info-item"><strong>Server IP</strong><br><span id="server_ip"></span></div>
      <div class="info-item"><strong>Server Port</strong><br><span id="server_port"></span></div>
      <div class="info-item"><strong>Dashboard Port</strong><br><span id="dashboard_port"></span></div>
      <div class="info-item"><strong>Rate per kWh</strong><br>₹<span id="rate_per_kwh"></span></div>
      <div class="info-item" style="flex:1"><strong>Max EV Capacity</strong><br><span id="max_kwh_capacity"></span> kWh</div>
    </div>
  </div>

  <div class="section">
    <h4 style="font-size:1.18rem;font-weight:600;">Server Log</h4>
    <pre id="logs" class="server-log-pre"></pre>
  </div>

  <div class="section table-section mb-4">
    <h4 style="font-size:1.15rem; font-weight:600;">Active Charging Sessions</h4>
    <div class="table-responsive">
      <table class="table table-bordered table-striped align-middle" id="active_sessions_table">
        <thead>
          <tr>
            <th>SESSION ID</th>
            <th>EV ID</th>
            <th>STATUS</th>
            <th>INITIAL BATTERY</th>
            <th>CURRENT BATTERY</th>
            <th>DESIRED</th>
            <th>ENERGY CHARGED</th>
            <th>BILL AMOUNT</th>
            <th>START TIME</th>
            <th>LOCATION</th>
            <th>STOP REASON</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="section table-section mb-4">
    <h4 style="font-size:1.15rem; font-weight:600;">Attack Log (Rejected Requests)</h4>
    <div class="table-responsive">
      <table class="table table-bordered table-striped align-middle" id="attack_log_table">
        <thead>
          <tr>
            <th>Time</th>
            <th>IP</th>
            <th>Reason</th>
            <th>EV ID</th>
            <th>Station ID</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="section table-section mb-4">
    <h4 style="font-size:1.15rem; font-weight:600;">Session History (Logged Sessions)</h4>
    <div class="table-responsive">
      <table class="table table-bordered table-striped align-middle" id="session_history_table">
        <thead>
          <tr>
            <th>SESSION ID</th>
            <th>EV ID</th>
            <th>STATUS</th>
            <th>INITIAL BATTERY</th>
            <th>CURRENT BATTERY</th>
            <th>DESIRED</th>
            <th>ENERGY CHARGED</th>
            <th>BILL AMOUNT</th>
            <th>START TIME</th>
            <th>LOCATION</th>
            <th>STOP REASON</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

</div>
<script>
function getIP() {
    return location.hostname;
}
function renderTable(tbody, data) {
    tbody.innerHTML = '';
    (data||[]).forEach(sess => {
        tbody.innerHTML += `<tr>
            <td>${sess.session_id||''}</td>
            <td>${sess.ev_id||''}</td>
            <td>${sess.status||''}</td>
            <td>${sess.initial_battery||''}</td>
            <td>${sess.current_battery||''}</td>
            <td>${sess.desired_percent||''}</td>
            <td>${sess.energy_charged||''}</td>
            <td>${sess.bill_amount||''}</td>
            <td>${sess.start_time||''}</td>
            <td>${sess.location||''}</td>
            <td>${sess.stop_reason||''}</td>
        </tr>`;
    });
}
function renderAttackTable(tbody, data) {
    tbody.innerHTML = '';
    (data||[]).forEach(row => {
        tbody.innerHTML += `<tr>
            <td>${row.timestamp||''}</td>
            <td>${row.ip||''}</td>
            <td>${row.reason||''}</td>
            <td>${row.ev_id||''}</td>
            <td>${row.station_id||''}</td>
            <td>${row.details||''}</td>
        </tr>`;
    });
}
function fetchStatus() {
    fetch('/api/status').then(r=>r.json()).then(data=>{
        // Crypto UI
        document.getElementById('cryptoToggle').checked = data.use_cryptography;
        document.getElementById('crypto_state_badge').textContent = data.use_cryptography ? 'Cryptography ON' : 'Cryptography OFF';
        document.getElementById('crypto_state_badge').className = data.use_cryptography ? 'crypto-state-badge badge bg-success' : 'crypto-state-badge badge bg-danger';
        document.getElementById('card_crypto_state').textContent = data.use_cryptography ? 'ON' : 'OFF';
        // Tables
        renderTable(document.querySelector('#active_sessions_table tbody'), data.active_sessions);
        document.getElementById('card_active_sessions').textContent = data.active_sessions.length;
        document.getElementById('rate_per_kwh').textContent = data.rate_per_kwh||'-';
        document.getElementById('max_kwh_capacity').textContent = data.max_kwh_capacity||'-';
        document.getElementById('server_ip').textContent = getIP();
        document.getElementById('server_port').textContent = 9999;
        document.getElementById('dashboard_port').textContent = 5000;
    });
}
function fetchHistory() {
    fetch('/api/session_history').then(r=>r.json()).then(data=>{
        renderTable(document.querySelector('#session_history_table tbody'), data);
        document.getElementById('card_total_sessions').textContent = data.length;
    });
}
function fetchAttacks() {
    fetch('/api/attacks').then(r=>r.json()).then(data=>{
        renderAttackTable(document.querySelector('#attack_log_table tbody'), data);
        document.getElementById('card_attack_count').textContent = data.length;
    });
}
function fetchLogs() {
    fetch('/api/logs').then(r=>r.json()).then(data=>{
        document.getElementById('logs').textContent = (data||[]).join('\\n');
    });
}
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('cryptoToggle').addEventListener('change', function() {
        fetch('/api/toggle_crypto', {method:'POST'}).then(()=>fetchStatus());
    });
    setInterval(fetchStatus, 1800);
    setInterval(fetchHistory, 3800);
    setInterval(fetchAttacks, 2600);
    setInterval(fetchLogs, 2400);
    fetchStatus(); fetchHistory(); fetchAttacks(); fetchLogs();
});
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
}
</script>
</body>
</html>
"""

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    log_message(f"[CS] Server listening on {SERVER_HOST}:{SERVER_PORT}", "INFO")
    while True:
        client_sock, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()

def start_dashboard():
    app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    threading.Thread(target=start_server, daemon=True).start()
    threading.Thread(target=cleanup_finished_sessions, daemon=True).start()
    start_dashboard()
