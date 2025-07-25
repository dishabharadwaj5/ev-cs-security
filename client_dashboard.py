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
from flask import Flask, jsonify, render_template_string, request
import threading
import time
import qrcode
import http.server
import socketserver
import webbrowser

# ====== CONFIG ======
EV_ID = "EV003"
STATION_ID = "CS124"
SERVER_IP = "192.168.87.85" # IMPORTANT: Changed to localhost for same-machine testing
SERVER_PORT = 9999
CS_PUBLIC_KEY_FILE = "cs_public_key.pem"
CERT_FILE = "expanded_ev_pinned_certificates.json"
LOCATION_FILE = "location.json"
FLASK_PORT = 5001
WEB_PORT = 8081
MAX_KWH = 75  # Maximum battery capacity in kWh

# Global variables for AES encryption/decryption
cipher_aes_iv = None
aes_key_global = None
charging_in_progress = False
stop_charging_requested = False
awaiting_server_final_response = False

# Initialize session data
def get_battery_percentage():
    """
    Attempts to get the current battery percentage using psutil.
    Returns a default of 60 if psutil fails or battery info is unavailable.
    """
    try:
        battery = psutil.sensors_battery()
        return int(battery.percent) if battery else 60
    except Exception as e:
        print(f"[EV] ⚠ Could not get battery percentage (using default 60%): {e}")
        return 60

def get_initial_session_data():
    """Returns a dictionary with initial session data."""
    return {
        "ev_id": EV_ID,
        "start_time": None,
        "end_time": None,
        "energy_kWh": 0,
        "rate_per_kWh": 0,
        "total_amount": 0,
        "status": "Ready",
        "battery_percent": get_battery_percentage(),
        "desired_percent": 0,
        "energy_needed": 0,
        "session_id": secrets.token_hex(8),
        "stop_request_time": 0,
        "client_use_cryptography": True # NEW: Moved CLIENT_USE_CRYPTOGRAPHY here
    }

session_data = get_initial_session_data()

# ====== Utility Functions ======
def fetch_public_key():
    """
    Connects to the server to fetch the public key and saves it to a file.
    Returns True on success, False on failure.
    This is only called if CLIENT_USE_CRYPTOGRAPHY is True.
    """
    if not session_data["client_use_cryptography"]: # Changed to session_data
        print("[EV] Skipping public key fetch: CLIENT_USE_CRYPTOGRAPHY is False.")
        return True # No public key needed if crypto is off

    print(f"[EV] Attempting to fetch public key from server at {SERVER_IP}:{SERVER_PORT}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((SERVER_IP, SERVER_PORT))
            print("[EV] Connected to server for public key fetch.")
            s.sendall(b'GET_PUBLIC_KEY\n')
            
            pubkey_data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                pubkey_data += chunk
        
        if not pubkey_data:
            print("[EV ERROR] Failed to receive public key data from server.")
            return False
        
        with open(CS_PUBLIC_KEY_FILE, "wb") as f:
            f.write(pubkey_data)
        print(f"[EV] Public key successfully saved to {CS_PUBLIC_KEY_FILE} ({len(pubkey_data)} bytes).")
        return True
    except socket.timeout:
        print(f"[EV ERROR] Timeout while fetching public key from {SERVER_IP}:{SERVER_PORT}. Is the server running and accessible?")
        return False
    except ConnectionRefusedError:
        print(f"[EV ERROR] Connection refused when fetching public key. Ensure server is running on {SERVER_IP}:{SERVER_PORT} and not blocked by a firewall.")
        return False
    except Exception as e:
        print(f"[EV ERROR] An unexpected error occurred while fetching public key: {e}")
        return False

def ensure_public_key():
    """
    Checks if the public key file exists and is valid. If not, attempts to fetch it.
    Returns True if a valid public key is available or if CLIENT_USE_CRYPTOGRAPHY is False, False otherwise.
    """
    if not session_data["client_use_cryptography"]: # Changed to session_data
        print("[EV] Public key not required as CLIENT_USE_CRYPTOGRAPHY is False.")
        return True

    if not os.path.exists(CS_PUBLIC_KEY_FILE):
        print(f"[EV] Public key file '{CS_PUBLIC_KEY_FILE}' not found. Attempting to fetch.")
        return fetch_public_key()
    else:
        try:
            with open(CS_PUBLIC_KEY_FILE, "rb") as f:
                data = f.read()
            if not data or b'PUBLIC KEY' not in data:
                print("[EV] Public key file is empty or invalid. Re-fetching...")
                return fetch_public_key()
            print(f"[EV] Public key found at '{CS_PUBLIC_KEY_FILE}'.")
            return True
        except Exception as e:
            print(f"[EV ERROR] Error reading public key file: {e}. Attempting to re-fetch.")
            return fetch_public_key()

def get_gps_location():
    """
    Reads GPS location from a local file.
    Returns (latitude, longitude) or default coordinates if the file is not found or invalid.
    """
    try:
        with open(LOCATION_FILE, 'r') as f:
            content = f.read().strip()
            if not content:
                raise ValueError("Empty location file")
            data = json.loads(content)
            lat = float(data["latitude"])
            lon = float(data["longitude"])
            print(f"[EV]  Location received from '{LOCATION_FILE}': lat={lat}, lon={lon}")
            return lat, lon
    except FileNotFoundError:
        print(f"[EV]  Location file '{LOCATION_FILE}' not found. Using default coordinates.")
        return 12.971891, 77.641151
    except json.JSONDecodeError:
        print(f"[EV]  Invalid JSON in '{LOCATION_FILE}'. Using default coordinates.")
        return 12.971891, 77.641151
    except Exception as e:
        print(f"[EV]  Failed to fetch GPS location: {e}. Using default coordinates.")
        return 12.971891, 77.641151

def load_fingerprint():
    """
    Loads the EV's pinned certificate fingerprint for the charging station.
    Raises an Exception if the fingerprint is not found.
    """
    try:
        with open(CERT_FILE) as f:
            data = json.load(f)
            for ev in data:
                if ev["ev_id"] == EV_ID:
                    for station in ev["pinned_stations"]:
                        if station["station_id"] == STATION_ID:
                            print(f"[EV] Using fingerprint: {station['fingerprint']}")
                            return station["fingerprint"]
            raise Exception(f"Fingerprint for EV_ID '{EV_ID}' and STATION_ID '{STATION_ID}' not found in '{CERT_FILE}'")
    except FileNotFoundError:
        raise Exception(f"Certificate file '{CERT_FILE}' not found. Please ensure it exists.")
    except json.JSONDecodeError:
        raise Exception(f"Invalid JSON in certificate file '{CERT_FILE}'.")
    except Exception as e:
        raise Exception(f"Error loading fingerprint: {e}")

def encrypt_payload(payload_dict):
    """
    Encrypts the payload dictionary using AES (symmetric encryption)
    and encrypts the AES key using RSA (asymmetric encryption) with the CS public key.
    If CLIENT_USE_CRYPTOGRAPHY is False, returns plain JSON.
    """
    global cipher_aes_iv, aes_key_global

    if not session_data["client_use_cryptography"]: # Changed to session_data
        print("[EV] CLIENT_USE_CRYPTOGRAPHY is False. Sending plaintext payload.")
        return json.dumps(payload_dict).encode('utf-8') + b"\n"

    try:
        # Generate a new AES key for each session
        aes_key = secrets.token_bytes(16) # 128-bit key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        
        # Encrypt the payload
        padded_data = pad(json.dumps(payload_dict).encode('utf-8'), AES.block_size)
        ciphertext = cipher_aes.encrypt(padded_data)
        
        # Store IV and AES key globally for decryption of server responses
        cipher_aes_iv = cipher_aes.iv
        aes_key_global = aes_key

        # Load the CS public key
        with open(CS_PUBLIC_KEY_FILE, "rb") as f:
            key_data = f.read()
            cs_pub = RSA.import_key(key_data)

        # Encrypt the AES key with the CS public key
        cipher_rsa = PKCS1_OAEP.new(cs_pub)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Prepare the final encrypted message
        encrypted_message = {
            "key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(cipher_aes.iv).decode('utf-8'),
            "data": base64.b64encode(ciphertext).decode('utf-8')
        }
        return json.dumps(encrypted_message).encode('utf-8') + b"\n"

    except FileNotFoundError:
        print(f"[EV ERROR] Public key file '{CS_PUBLIC_KEY_FILE}' not found during encryption.")
        return None
    except ValueError as ve:
        print(f"[EV ERROR] Invalid public key format in '{CS_PUBLIC_KEY_FILE}': {ve}")
        return None
    except Exception as e:
        print(f"[EV ERROR] Payload encryption failed: {e}")
        return None

def decrypt_response(encrypted_data_str):
    """
    Decrypts the server's AES-encrypted response using the globally stored AES key and IV.
    If CLIENT_USE_CRYPTOGRAPHY is False, attempts to parse as plaintext JSON directly.
    """
    global aes_key_global, cipher_aes_iv

    if not session_data["client_use_cryptography"]: # Changed to session_data
        print("[EV] CLIENT_USE_CRYPTOGRAPHY is False. Attempting to parse response as plaintext JSON.")
        try:
            return json.loads(encrypted_data_str)
        except json.JSONDecodeError:
            print(f"[EV ERROR] Failed to parse plaintext JSON: {encrypted_data_str[:100]}...")
            return None
        except Exception as e:
            print(f"[EV ERROR] Unexpected error parsing plaintext JSON: {e}")
            return None

    if aes_key_global is None or cipher_aes_iv is None:
        print("[EV ERROR] AES key or IV not set for decryption. Cannot decrypt response.")
        return None
    
    try:
        decoded_data = base64.b64decode(encrypted_data_str)
        cipher = AES.new(aes_key_global, AES.MODE_CBC, cipher_aes_iv)
        decrypted_padded = cipher.decrypt(decoded_data)
        decrypted_unpadded = unpad(decrypted_padded, AES.block_size)
        return json.loads(decrypted_unpadded.decode('utf-8'))
    except Exception as e:
        print(f"[EV ERROR] Failed to decrypt server response: {e}. Raw data: {encrypted_data_str[:100]}...")
        return None

def encrypt_response(aes_key, iv, response_dict):
    """
    Encrypts a response dictionary using the provided AES key and IV.
    This function is used by the client to send encrypted progress updates and final battery.
    If CLIENT_USE_CRYPTOGRAPHY is False, returns plain JSON.
    """
    if not session_data["client_use_cryptography"]: # Changed to session_data
        return json.dumps(response_dict).encode('utf-8') + b"\n"

    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = pad(json.dumps(response_dict).encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"[EV ERROR] Failed to encrypt client response: {e}")
        return None

def generate_qr():
    """Generates a QR code pointing to the EV's Flask web interface."""
    ev_client_ip = "192.168.87.142" # This should be the IP of the machine running this client script
    url = f"http://{ev_client_ip}:{FLASK_PORT}" 
    qr = qrcode.make(url)
    qr.save("ev_qr_code.png")
    print(f"[EV] QR code saved to ev_qr_code.png pointing to {url}")

# ====== Flask Web Interface ======
app = Flask(_name_)

@app.route("/")
def home():
    """Renders the main EV charging interface HTML page."""
    return render_template_string(INTERFACE_HTML, 
                                  ev_id=session_data["ev_id"],
                                  battery_percent=session_data["battery_percent"],
                                  client_use_cryptography=session_data["client_use_cryptography"]) # Pass crypto state

@app.route("/session")
def get_session():
    """Returns the current session data as JSON."""
    if not charging_in_progress:
        session_data["battery_percent"] = get_battery_percentage()
    return jsonify(session_data)

@app.route("/reset_session", methods=["POST"])
def reset_session_endpoint():
    """Resets the charging session and related global variables."""
    global session_data, charging_in_progress, cipher_aes_iv, aes_key_global, stop_charging_requested, awaiting_server_final_response
    
    if charging_in_progress:
        print("[EV DEBUG] Attempted to reset session while charging is in progress.")
        return jsonify({"success": False, "error": "Cannot reset while charging is in progress"})
    
    # Reset all global variables
    charging_in_progress = False
    stop_charging_requested = False
    awaiting_server_final_response = False
    cipher_aes_iv = None
    aes_key_global = None
    
    # Preserve the client_use_cryptography setting
    current_crypto_setting = session_data["client_use_cryptography"]
    session_data = get_initial_session_data()
    session_data["client_use_cryptography"] = current_crypto_setting

    print("[EV] Session reset successfully via web endpoint.")
    return jsonify({"success": True, "message": "Session reset successfully"})

@app.route("/toggle_encryption", methods=["POST"])
def toggle_encryption_endpoint():
    """Toggles the CLIENT_USE_CRYPTOGRAPHY setting."""
    global session_data
    if charging_in_progress:
        return jsonify({"success": False, "error": "Cannot change encryption setting while charging is in progress."})
    
    try:
        data = request.get_json()
        enable_encryption = data.get("enable")
        
        if isinstance(enable_encryption, bool):
            session_data["client_use_cryptography"] = enable_encryption
            print(f"[EV] CLIENT_USE_CRYPTOGRAPHY set to: {session_data['client_use_cryptography']}")
            return jsonify({"success": True, "client_use_cryptography": session_data["client_use_cryptography"]})
        else:
            return jsonify({"success": False, "error": "Invalid 'enable' value. Must be true or false."})
    except Exception as e:
        print(f"[EV ERROR] Error toggling encryption: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.route("/start_charging", methods=["POST"])
def start_charging_endpoint():
    """
    Handles the request to start charging from the web interface.
    Initiates the charging process in a separate thread.
    """
    global charging_in_progress, stop_charging_requested, awaiting_server_final_response
    
    print("[EV DEBUG] Received /start_charging request from web UI.")
    
    if charging_in_progress:
        print("[EV DEBUG] Charging already in progress, rejecting new start request.")
        return jsonify({"success": False, "error": "Charging already in progress."})
    
    if session_data["status"] not in ["Ready", "Charging Complete", "Error: Could not connect to server", "Error: Authentication Failed", "Error: Communication failed", "Error: Encryption failed", "Charging Stopped by User."]:
        print(f"[EV DEBUG] Cannot start charging in current state: {session_data['status']}")
        return jsonify({"success": False, "error": f"Cannot start charging in current state: {session_data['status']}"})
    
    try:
        data = request.get_json()
        desired_percent = data.get("desired_percent")
        current_battery = get_battery_percentage()
        
        if not desired_percent or not (1 <= desired_percent <= 100):
            print(f"[EV DEBUG] Invalid desired_percent: {desired_percent}")
            return jsonify({"success": False, "error": "Please enter a valid desired charge level between 1 and 100."})
        
        if desired_percent <= current_battery:
            print(f"[EV DEBUG] Desired percent ({desired_percent}) not higher than current ({current_battery}).")
            return jsonify({"success": False, "error": f"Desired charge level ({desired_percent}%) must be higher than current battery ({current_battery}%)."})
        
        energy_needed = round((desired_percent - current_battery) * MAX_KWH / 100, 2)
        
        session_data["battery_percent"] = current_battery
        session_data["desired_percent"] = desired_percent
        session_data["energy_needed"] = energy_needed
        session_data["rate_per_kWh"] = 0
        session_data["total_amount"] = 0
        session_data["status"] = "Initiating..."
        session_data["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session_data["end_time"] = None
        session_data["session_id"] = secrets.token_hex(8)
        
        stop_charging_requested = False
        awaiting_server_final_response = False

        print(f"[EV] Starting charging process for desired {desired_percent}% (estimated {energy_needed} kWh)...")
        threading.Thread(target=run_ev_client_with_params, args=(desired_percent,), daemon=True).start()
        
        print("[EV DEBUG] Successfully initiated charging thread.")
        return jsonify({"success": True})
        
    except Exception as e:
        print(f"[EV ERROR] Error in start_charging_endpoint: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/stop_charging", methods=["POST"])
def stop_charging_endpoint():
    """
    Handles the request to stop charging from the web interface.
    Sets a flag to stop the charging thread and sends a stop command to the server.
    """
    global stop_charging_requested, charging_in_progress, awaiting_server_final_response
    print("[EV DEBUG] Received /stop_charging request from web UI.")
    if not charging_in_progress:
        print("[EV DEBUG] No charging in progress, rejecting stop request.")
        return jsonify({"success": False, "error": "No charging session in progress."})

    print("[EV] Stop charging requested by user via web UI.")
    stop_charging_requested = True
    session_data["status"] = "Stopping Charging..."
    # Record the time when stop was requested to handle potential server unresponsiveness
    session_data["stop_request_time"] = time.time() 
    
    # The run_ev_client_with_params thread will handle sending "stop_charging" to server
    # and then wait for the final bill.
    awaiting_server_final_response = True # Set this flag
    print("[EV DEBUG] stop_charging_requested flag set and awaiting_server_final_response set to True.")
    return jsonify({"success": True, "message": "Stop request sent."})


def start_flask_server():
    """Starts the Flask web server."""
    print(f"[EV] Starting Flask web server on http://0.0.0.0:{FLASK_PORT}")
    try:
        app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, use_reloader=False) # use_reloader=False for threading
    except OSError as e:
        print(f"[EV CRITICAL] Failed to bind Flask server to 0.0.0.0:{FLASK_PORT}: {e}. Is the port already in use or requires admin privileges?", "CRITICAL")
        sys.exit(1) # Exit if Flask server cannot start

# ====== EV Client Logic (Socket Communication) ======
def run_ev_client_with_params(desired_percent):
    """
    Handles the core logic of connecting to the charging station server,
    authenticating, requesting power, receiving billing information,
    and simulating charging progress.
    """
    print("[EV DEBUG] run_ev_client_with_params function started.")
    global charging_in_progress, session_data, cipher_aes_iv, aes_key_global, stop_charging_requested, awaiting_server_final_response
    
    current_battery_at_start = get_battery_percentage()
    energy_needed = round((desired_percent - current_battery_at_start) * MAX_KWH / 100, 2)

    sock = None
    try:
        charging_in_progress = True
        session_data["status"] = "Connecting to Charging Station..."
        print(f"[EV] Attempting to connect to charging station at {SERVER_IP}:{SERVER_PORT}")

        # Ensure public key is available before attempting connection
        # This function is now conditional on session_data["client_use_cryptography"]
        if not ensure_public_key():
            session_data["status"] = "Error: Failed to get CS Public Key. Check server and network."
            print("[EV] Aborting charging due to public key issue.")
            return
        
        lat, lon = get_gps_location()
        
        try:
            fingerprint = load_fingerprint()
        except Exception as e:
            session_data["status"] = f"Error: Fingerprint loading failed - {str(e)}"
            print(f"[EV] Aborting charging: {e}")
            return

        timestamp = datetime.now().isoformat()
        nonce = secrets.token_hex(16)

        # Prepare the initial authentication payload
        payload = {
            "ev_id": EV_ID,
            "station_id": STATION_ID,
            "presented_fingerprint": fingerprint,
            "location": {"latitude": lat, "longitude": lon},
            "battery": current_battery_at_start,
            "desired_percent": desired_percent,
            "request_power": energy_needed,
            "timestamp": timestamp,
            "nonce": nonce,
            "session_id": session_data["session_id"]
        }

        # Encrypt payload is now conditional on session_data["client_use_cryptography"]
        encrypted_payload = encrypt_payload(payload)
        if encrypted_payload is None:
            session_data["status"] = "Error: Payload encryption failed."
            print("[EV] Aborting charging due to encryption failure.")
            return

        session_data["status"] = "Authenticating with Charging Station..."
        print(f"[EV] Attempting socket connection to {SERVER_IP}:{SERVER_PORT}...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        
        try:
            sock.connect((SERVER_IP, SERVER_PORT))
            print(f"[EV] Successfully connected to {SERVER_IP}:{SERVER_PORT}")
        except socket.timeout:
            session_data["status"] = "Error: Connection timeout. Server not responding or network issue."
            print(f"[EV ERROR] Socket connection timed out to {SERVER_IP}:{SERVER_PORT}.")
            return
        except ConnectionRefusedError:
            session_data["status"] = "Error: Connection refused. Server might not be running or firewall blocked."
            print(f"[EV ERROR] Connection refused to {SERVER_IP}:{SERVER_PORT}. Ensure server is running on {SERVER_IP}:{SERVER_PORT} and not blocked by a firewall.")
            return
        except socket.gaierror:
            session_data["status"] = "Error: Invalid server IP address or hostname."
            print(f"[EV ERROR] Could not resolve server IP '{SERVER_IP}'. Check IP address.")
            return
        except Exception as e:
            session_data["status"] = f"Error: Socket connection failed - {str(e)}"
            print(f"[EV ERROR] An unexpected error occurred during socket connection: {e}")
            return
            
        try:
            print("[EV] Sending encrypted authentication payload...")
            sock.sendall(encrypted_payload)
            
            # --- Server Communication Loop ---
            buffer = b""
            while True:
                if stop_charging_requested and not awaiting_server_final_response:
                    print(f"[EV] User requested stop. Sending 'stop_charging:{session_data['battery_percent']}' to server.")
                    # If client is configured to NOT use crypto, send plaintext stop command.
                    # Otherwise, the server should be expecting an encrypted stop message, but the original code sent plaintext here.
                    # To align with session_data["client_use_cryptography"], we would encrypt this.
                    # For now, keeping it as plaintext as it was a special case in the original client.
                    sock.sendall(f"stop_charging:{session_data['battery_percent']}\n".encode()) 
                    session_data["status"] = "Stopping Charging..."
                    session_data["stop_request_time"] = time.time()
                    awaiting_server_final_response = True
                
                try:
                    current_timeout = 1 if not awaiting_server_final_response else 15
                    sock.settimeout(current_timeout) 
                    data = sock.recv(4096) 
                    if not data:
                        print("[EV] Server closed connection unexpectedly.")
                        session_data["status"] = "Error: Server disconnected."
                        break
                    buffer += data
                except socket.timeout:
                    if awaiting_server_final_response and (time.time() - session_data.get("stop_request_time", 0) > 20):
                        print("[EV ERROR] Server did not send final bill after stop request within timeout.")
                        session_data["status"] = "Error: Server unresponsive after stop."
                        break
                    continue
                except Exception as e:
                    print(f"[EV ERROR] Error receiving data from server: {e}")
                    session_data["status"] = f"Error: Communication issue - {str(e)}"
                    break

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    msg = line.decode('utf-8').strip()
                    print(f"[EV]  Received message from server: '{msg}'")

                    if msg.startswith("REJECT"):
                        session_data["status"] = f"Authentication Failed: {msg}"
                        print(f"[EV] Authentication rejected: {msg}")
                        global cipher_aes_iv, aes_key_global
                        cipher_aes_iv = None
                        aes_key_global = None
                        return
                    elif msg == "stop_charging":
                        session_data["status"] = "Charging Complete"
                        session_data["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        print(f"\n[EV] {msg}. Charging session ended by server.")
                        break
                    else:
                        processed_message = None
                        # Attempt to decrypt only if session_data["client_use_cryptography"] is True and keys are set
                        if session_data["client_use_cryptography"] and aes_key_global and cipher_aes_iv:
                            processed_message = decrypt_response(msg)
                            if processed_message:
                                print(f"[EV] Decrypted server message: {processed_message}")
                            else:
                                print(f"[EV WARNING] Decryption failed. Attempting to parse as plaintext JSON. Raw: {msg[:100]}...")
                        
                        # If decryption failed (or not attempted due to session_data["client_use_cryptography"]=False), try plaintext
                        if not processed_message:
                            try:
                                processed_message = json.loads(msg)
                                print(f"[EV] Parsed plaintext server message: {processed_message}")
                            except json.JSONDecodeError:
                                print(f"[EV ERROR] Received unhandled and undecryptable/unparsable message from server: {msg}")
                                session_data["status"] = "Error: Unrecognized server message format."
                                break
                            except Exception as e:
                                print(f"[EV ERROR] Error parsing plaintext message: {e}. Raw: {msg[:100]}...")
                                session_data["status"] = f"Error: Corrupted plaintext message - {str(e)}"
                                break

                        if processed_message:
                            if processed_message.get("status") == "session_accepted":
                                session_data["status"] = "Charging"
                                print("[EV] Server accepted session. Charging in progress.")
                                session_data["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
                                session_data["rate_per_kWh"] = processed_message.get("rate_per_kwh", 0)
                                
                                current_battery = session_data["battery_percent"]
                                target_battery = session_data["desired_percent"]
                                while current_battery < target_battery and not stop_charging_requested:
                                    current_battery = min(current_battery + 1, target_battery)
                                    session_data["battery_percent"] = current_battery
                                    print(f"\r[EV] Simulating charge: {current_battery}%", end='', flush=True)
                                    time.sleep(0.5)
                                    
                                    progress_payload = {"progress": current_battery}
                                    # Encrypt progress update only if session_data["client_use_cryptography"] is True
                                    if session_data["client_use_cryptography"] and aes_key_global and cipher_aes_iv:
                                        encrypted_progress = encrypt_response(aes_key_global, cipher_aes_iv, progress_payload)
                                        if encrypted_progress:
                                            sock.sendall(encrypted_progress.encode('utf-8') + b"\n")
                                        else:
                                            print("[EV ERROR] Failed to encrypt progress update.")
                                    else: # Send plaintext if client crypto is off
                                        sock.sendall(json.dumps(progress_payload).encode('utf-8') + b"\n")
                                    
                                    if current_battery >= target_battery:
                                        print("\n[EV] Local battery simulation reached target.")
                                        final_battery_payload = {"final_battery": current_battery}
                                        # Encrypt final battery only if session_data["client_use_cryptography"] is True
                                        if session_data["client_use_cryptography"] and aes_key_global and cipher_aes_iv:
                                            encrypted_final_battery = encrypt_response(aes_key_global, cipher_aes_iv, final_battery_payload)
                                            if encrypted_final_battery:
                                                sock.sendall(encrypted_final_battery.encode('utf-8') + b"\n")
                                                print("[EV] Sent final battery level to server.")
                                            else:
                                                print("[EV ERROR] Failed to encrypt final battery level.")
                                        else: # Send plaintext if client crypto is off
                                            sock.sendall(json.dumps(final_battery_payload).encode('utf-8') + b"\n")
                                        break
                                
                                if not stop_charging_requested:
                                    session_data["status"] = "Waiting for server to stop charging..."
                            elif processed_message.get("status") == "in_progress":
                                session_data["rate_per_kWh"] = processed_message.get("rate_per_kwh", 0)
                                session_data["total_amount"] = processed_message.get("bill_amount", 0)
                                session_data["energy_kWh"] = processed_message.get("energy_used", 0)
                                print(f"[EV] Received progress update: Battery {processed_message.get('current_percent', 'N/A')}%, Bill ₹{session_data['total_amount']}")
                            elif processed_message.get("status") == "charging_complete":
                                session_data["status"] = "Charging Complete"
                                session_data["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                session_data["rate_per_kWh"] = processed_message.get("rate_per_kwh", 0)
                                session_data["total_amount"] = processed_message.get("bill_amount", 0)
                                session_data["energy_kWh"] = processed_message.get("energy", 0)
                                session_data["battery_percent"] = processed_message.get("current_battery_at_end", session_data["battery_percent"])
                                print(f"\n[EV] Charging session complete. Final Bill: ₹{session_data['total_amount']} for {session_data['energy_kWh']} kWh.")
                                break
                            else:
                                print(f"[EV ERROR] Unrecognized JSON message from server: {processed_message}")
                                session_data["status"] = "Error: Unrecognized server message."
                                break
                        else:
                            print(f"[EV ERROR] Message could not be processed after decryption/plaintext attempts: {msg}")
                            session_data["status"] = "Error: Unprocessable server message."
                            break


        except socket.timeout:
            session_data["status"] = "Error: Server communication timed out during session."
            print("[EV ERROR] Socket communication timed out.")
        except Exception as e:
            session_data["status"] = f"Error: Communication failed during charging - {str(e)}"
            print(f"[EV ERROR] An error occurred during socket communication: {e}")
        finally:
            if sock:
                sock.close()
                print("[EV] Socket closed.")

    except Exception as e:
        print(f"[EV ERROR] An unhandled error occurred in run_ev_client_with_params: {e}")
        session_data["status"] = f"Error: Unhandled exception - {str(e)}"
    finally:
        charging_in_progress = False
        awaiting_server_final_response = False
        if session_data["status"] in ["Charging Complete", "Authentication Failed", "Charging Stopped by User.", "Error: Server unresponsive after stop."] or "Error" in session_data["status"]:
            def auto_reset_session_after_delay():
                time.sleep(30)
                global session_data, cipher_aes_iv, aes_key_global, stop_charging_requested
                if not charging_in_progress and not stop_charging_requested: 
                    # Preserve crypto setting on auto-reset as well
                    current_crypto_setting = session_data["client_use_cryptography"]
                    session_data = get_initial_session_data()
                    session_data["client_use_cryptography"] = current_crypto_setting
                    cipher_aes_iv = None
                    aes_key_global = None
                    print("[EV] Session auto-reset after 30 seconds of completion/error.")
                stop_charging_requested = False
            
            threading.Thread(target=auto_reset_session_after_delay, daemon=True).start()

# ====== Web Server for Location (Simple HTTP Server) ======
class CustomHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler for saving location data.
    """
    def do_POST(self):
        if self.path == "/save_location":
            content_len = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_len)
            try:
                data = json.loads(post_data.decode('utf-8'))
                with open(LOCATION_FILE, 'w') as f:
                    json.dump(data, f, indent=2)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Location saved successfully")
                print(f"[Server] 📍 Location saved to {LOCATION_FILE}: {data}")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Failed to save location")
                print(f"[Server] ❌ Error saving location: {e}")
        else:
            self.send_error(404)

def start_web_server():
    os.chdir(".")
    webbrowser.open(f"http://localhost:{WEB_PORT}")
    with socketserver.TCPServer(("", WEB_PORT), CustomHandler) as httpd:
        print(f"🌐 Web server running at http://localhost:{WEB_PORT}")
        httpd.serve_forever()


# ====== Web Interface HTML Template ======
INTERFACE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>EV Charging Session</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            padding: 1rem; 
            margin: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .card { 
            background: rgba(255, 255, 255, 0.9);
            padding: 2rem; 
            border-radius: 15px; 
            box-shadow: 0 8px 32px rgba(0,0,0,0.1); 
            max-width: 450px; 
            width: 90%;
            margin: auto; 
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
            text-align: center;
        }
        h2 { 
            margin-bottom: 1.5rem; 
            color: #333;
            text-align: center;
            font-size: 1.8rem;
        }
        .input-group {
            margin-bottom: 1rem;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
            color: #555;
        }
        input, button {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
            outline: none;
        }
        input:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            cursor: pointer;
            margin-top: 1rem;
            font-weight: bold;
            transition: transform 0.2s ease, background 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
        button:hover {
            transform: translateY(-3px);
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid #eee;
            font-size: 0.95rem;
            color: #444;
        }
        .info-row strong {
            color: #333;
        }
        .status {
            text-align: center;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            font-weight: bold;
            font-size: 1.1rem;
        }
        .status.ready { background: #e8f5e8; color: #2e7d32; }
        .status.connecting, .status.authenticating, .status.initiating, .status.charging, .status.stopping { 
            background: #fff3e0; 
            color: #f57c00;
            animation: pulse 1.5s infinite alternate;
        }
        .status.complete { background: #e3f2fd; color: #1976d2; }
        .status.error { background: #ffebee; color: #c62828; }

        .battery-bar {
            width: 100%;
            height: 25px;
            background: #eee;
            border-radius: 12px;
            overflow: hidden;
            margin: 1rem 0;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
        }
        .battery-fill {
            height: 100%;
            background: linear-gradient(90deg, #4caf50, #8bc34a);
            transition: width 0.5s ease;
            border-radius: 12px;
        }
        .error-details {
            background: #ffebee;
            color: #c62828;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            font-size: 0.9em;
            border-left: 4px solid #c62828;
            text-align: left;
            word-wrap: break-word;
        }

        .toggle-switch {
            position: relative;
            display: inline-block;
            width: 60px;
            height: 34px;
            margin: 10px;
        }

        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            -webkit-transition: .4s;
            transition: .4s;
            border-radius: 34px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 26px;
            width: 26px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            -webkit-transition: .4s;
            transition: .4s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: #667eea;
        }

        input:focus + .slider {
            box-shadow: 0 0 1px #667eea;
        }

        input:checked + .slider:before {
            -webkit-transform: translateX(26px);
            -ms-transform: translateX(26px);
            transform: translateX(26px);
        }
        .crypto-setting {
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: 1.5rem;
            margin-bottom: 1rem;
            padding-top: 1rem;
            border-top: 1px dashed #eee;
        }
        .crypto-setting label {
            margin-right: 15px;
            margin-bottom: 0; /* Override default label margin-bottom */
            font-weight: bold;
            color: #555;
            display: inline-block; /* To align with switch */
        }
        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            100% { transform: scale(1.02); opacity: 0.9; }
        }
    </style>
</head>
<body>
    <div class="card">
        <h2> EV Charging Station</h2>
        <div id="interface">
            <div class="status ready" id="status">Ready to Charge</div>
            
            <div class="info-row">
                <span><strong>EV ID:</strong></span>
                <span id="ev-id">{{ ev_id }}</span>
            </div>
            
            <div class="info-row">
                <span><strong>Current Battery:</strong></span>
                <span id="battery">{{ battery_percent }}%</span>
            </div>
            
            <div class="battery-bar">
                <div class="battery-fill" id="battery-fill" style="width: {{ battery_percent }}%"></div>
            </div>
            
            <div class="input-group" id="charge-controls">
                <label for="desired-percent">Desired Charge Level (%):</label>
                <input type="number" id="desired-percent" min="1" max="100" placeholder="e.g., 80">
                
                <button onclick="startCharging()" id="start-btn">Start Charging</button>
            </div>
            
            <div id="charging-info" style="display: none;">
                <div class="info-row">
                    <span><strong>Energy Needed:</strong></span>
                    <span id="energy-needed">0 kWh</span>
                </div>
                <div class="info-row">
                    <span><strong>Rate:</strong></span>
                    <span>₹<span id="rate">-</span> per kWh</span>
                </div>
                <div class="info-row">
                    <span><strong>Total Cost:</strong></span>
                    <span>₹<span id="total-cost">-</span></span>
                </div>
                <div class="info-row">
                    <span><strong>Start Time:</strong></span>
                    <span id="start-time">-</span>
                </div>
                <div class="info-row">
                    <span><strong>End Time:</strong></span>
                    <span id="end-time">-</span>
                </div>
                <button onclick="stopCharging()" id="stop-btn" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">Stop Charging</button>
            </div>
            
            <div id="error-details" class="error-details" style="display: none;">
                <strong>Error Details:</strong><br>
                <span id="error-message"></span>
            </div>

            <div class="crypto-setting">
                <label for="encryption-toggle">Encryption Enabled:</label>
                <label class="toggle-switch">
                    <input type="checkbox" id="encryption-toggle" {{ 'checked' if client_use_cryptography else '' }} onchange="toggleEncryption()">
                    <span class="slider"></span>
                </label>
            </div>
        </div>
    </div>

    <script>
        let sessionData = {};
        
        function updateInterface() {
            fetch("/session")
                .then(r => r.json())
                .then(data => {
                    sessionData = data;
                    
                    const statusEl = document.getElementById("status");
                    const statusText = data.status;
                    let statusClass = statusText.toLowerCase().replace(/[^a-z]/g, '');
                    
                    if (statusText.includes("Error") || statusText.includes("Failed")) {
                        statusClass = "error";
                        document.getElementById("error-details").style.display = "block";
                        document.getElementById("error-message").textContent = statusText;
                    } else {
                        document.getElementById("error-details").style.display = "none";
                    }

                    if (statusText.includes("Connecting") || statusText.includes("Authenticating") || statusText.includes("Initiating") || statusText.includes("Charging")) {
                         statusClass = "charging";
                    } else if (statusText.includes("Stopping")) {
                         statusClass = "stopping";
                    } else if (statusText.includes("Complete")) {
                         statusClass = "complete";
                    } else if (statusText.includes("Ready")) {
                         statusClass = "ready";
                    }
                    
                    statusEl.className = status ${statusClass};
                    statusEl.textContent = statusText;
                    
                    document.getElementById("battery").textContent = data.battery_percent + "%";
                    document.getElementById("battery-fill").style.width = data.battery_percent + "%";
                    
                    const chargeControls = document.getElementById("charge-controls");
                    const chargingInfo = document.getElementById("charging-info");
                    const startBtn = document.getElementById("start-btn");
                    const stopBtn = document.getElementById("stop-btn");
                    const encryptionToggle = document.getElementById("encryption-toggle");


                    if (data.status === "Ready" || data.status.includes("Complete") || data.status.includes("Error") || data.status.includes("Stopped")) {
                        chargeControls.style.display = "block";
                        chargingInfo.style.display = "none";
                        startBtn.disabled = false;
                        startBtn.textContent = "Start Charging";
                        encryptionToggle.disabled = false; // Enable toggle when not charging
                    } else {
                        chargeControls.style.display = "none";
                        chargingInfo.style.display = "block";
                        startBtn.disabled = true;
                        startBtn.textContent = "Charging...";
                        encryptionToggle.disabled = true; // Disable toggle when charging
                        
                        document.getElementById("energy-needed").textContent = data.energy_needed + " kWh";
                        document.getElementById("rate").textContent = data.rate_per_kWh ? data.rate_per_kWh.toFixed(2) : "-";
                        document.getElementById("total-cost").textContent = data.total_amount ? data.total_amount.toFixed(2) : "-";
                        document.getElementById("start-time").textContent = data.start_time || "-";
                        document.getElementById("end-time").textContent = data.end_time || "-";

                        if (data.status === "Charging" || data.status.includes("Waiting") || data.status.includes("Stopping")) {
                            stopBtn.disabled = false;
                        } else {
                            stopBtn.disabled = true;
                        }
                    }
                    // Set the toggle switch state based on the fetched session data
                    encryptionToggle.checked = data.client_use_cryptography;

                })
                .catch(err => {
                    console.error("Error fetching session data:", err);
                    const statusEl = document.getElementById("status");
                    statusEl.className = "status error";
                    statusEl.textContent = "Error: Could not fetch session data from Flask server.";
                    document.getElementById("error-details").style.display = "block";
                    document.getElementById("error-message").textContent = "Failed to connect to local Flask server. Ensure the Python script is running.";
                });
        }
        
        function startCharging() {
            const desiredPercentInput = document.getElementById("desired-percent");
            const desiredPercent = parseInt(desiredPercentInput.value);
            
            if (isNaN(desiredPercent) || desiredPercent < 1 || desiredPercent > 100) {
                alert("Please enter a valid desired charge level between 1 and 100.");
                return;
            }

            if (desiredPercent <= sessionData.battery_percent) {
                alert("Desired charge level must be higher than current battery percentage.");
                return;
            }
            
            document.getElementById("start-btn").disabled = true;
            document.getElementById("start-btn").textContent = "Starting...";
            
            fetch("/start_charging", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({desired_percent: desiredPercent})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    updateInterface();
                } else {
                    alert("Failed to start charging: " + data.error);
                    document.getElementById("start-btn").disabled = false;
                    document.getElementById("start-btn").textContent = "Start Charging";
                    sessionData.status = "Error: " + data.error;
                    updateInterface(); 
                }
            })
            .catch(err => {
                console.error("Error sending start charging request:", err);
                alert("Error sending start charging request. Please check console for details.");
                document.getElementById("start-btn").disabled = false;
                document.getElementById("start-btn").textContent = "Start Charging";
                sessionData.status = "Error: Network issue sending start request.";
                updateInterface();
            });
        }

        function stopCharging() {
            document.getElementById("stop-btn").disabled = true;
            document.getElementById("stop-btn").textContent = "Stopping...";

            fetch("/stop_charging", {
                method: "POST",
                headers: {"Content-Type": "application/json"}
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    updateInterface();
                } else {
                    alert("Failed to stop charging: " + data.error);
                    document.getElementById("stop-btn").disabled = false;
                    document.getElementById("stop-btn").textContent = "Stop Charging";
                    sessionData.status = "Error: " + data.error;
                    updateInterface();
                }
            })
            .catch(err => {
                console.error("Error sending stop charging request:", err);
                alert("Error sending stop charging request. Please check console for details.");
                document.getElementById("stop-btn").disabled = false;
                document.getElementById("stop-btn").textContent = "Stop Charging";
                sessionData.status = "Error: Network issue sending stop request.";
                updateInterface();
            });
        }

        function toggleEncryption() {
            const encryptionToggle = document.getElementById("encryption-toggle");
            const enable = encryptionToggle.checked;

            fetch("/toggle_encryption", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({ enable: enable })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert("Failed to toggle encryption: " + data.error);
                    // Revert the toggle visually if the server-side update failed
                    encryptionToggle.checked = !enable; 
                } else {
                    console.log("Encryption toggled to:", data.client_use_cryptography);
                }
            })
            .catch(err => {
                console.error("Error toggling encryption:", err);
                alert("Error toggling encryption. Please check console for details.");
                // Revert the toggle visually on network error
                encryptionToggle.checked = !enable;
            });
        }
        
        updateInterface();
        setInterval(updateInterface, 2000);
    </script>
</body>
</html>
"""

if _name_ == '_main_':
    print("-" * 40)
    print("EV Client Dashboard & Server Options")
    print("-" * 40)
    print("1. Start location web server (for setting GPS coordinates via a browser)")
    print("2. Start QR charging interface (the main EV client UI)")
    print("3. Generate QR code (points to the EV client UI)")
    print("-" * 40)
    
    choice = input("Enter your choice (1/2/3): ").strip()
    
    if choice == "1":
        print("\n--- Starting Location Web Server ---")
        print("This server allows you to save location data to 'location.json'.")
        print("You might need a separate client (e.g., a simple HTML form or mobile app) to POST data to it.")
        start_web_server()
    elif choice == "2":
        print("\n--- Starting EV Charging Interface ---")
        print(f"Access the charging interface via your web browser at: http://localhost:{FLASK_PORT}")
        print(f"Ensure your server (charging station) is running at {SERVER_IP}:{SERVER_PORT}")
        print("Sessions will auto-reset 30 seconds after completion or error for a new session.")
        start_flask_server()
    elif choice == "3":
        print("\n--- Generating QR Code ---")
        generate_qr()
        print("QR code 'ev_qr_code.png' generated. Scan this with your phone to access the EV client interface.")
        print(f"REMEMBER: The QR code URL (127.0.0.1:{FLASK_PORT}) must be the actual IP of this machine for external access.")
    else:
        print(" Invalid choice. Please run the script again and select 1, 2, or 3.")
