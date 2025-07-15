import socket
import json
from datetime import datetime
import secrets
import os
import sys
import psutil
import http.server
import socketserver

EV_ID = "EV003"
STATION_ID = "CS124"
SERVER_IP = "10.20.201.39"  # Change to your server IP
SERVER_PORT = 9999
CERT_FILE = "expanded_ev_pinned_certificates.json"
LOCATION_FILE = "location.json"
WEB_PORT = 8081
MAX_KWH = 75  # Maximum battery capacity

def get_battery_percentage():
    try:
        battery = psutil.sensors_battery()
        return int(battery.percent) if battery else 60
    except Exception as e:
        print(f"[EV] ⚠ Could not get battery percentage: {e}")
        return 60

def get_gps_location():
    try:
        with open(LOCATION_FILE, 'r') as f:
            content = f.read().strip()
            if not content:
                raise ValueError("Empty location file")
            data = json.loads(content)
            lat = float(data["latitude"])
            lon = float(data["longitude"])
            print(f"[EV]  Location received: lat={lat}, lon={lon}")
            return lat, lon
    except Exception as e:
        print(f"[EV]  Failed to fetch GPS: {e}")
        return 12.971891, 77.641151

def load_fingerprint():
    with open(CERT_FILE) as f:
        data = json.load(f)
        for ev in data:
            if ev["ev_id"] == EV_ID:
                for station in ev["pinned_stations"]:
                    if station["station_id"] == STATION_ID:
                        print(f"[EV] Using fingerprint: {station['fingerprint']}")
                        return station["fingerprint"]
    raise Exception("[EV]  Fingerprint not found")

# ====== EV Client Logic ======
def run_ev_client():
    try:
        lat, lon = get_gps_location()
        battery = get_battery_percentage()
        fingerprint = load_fingerprint()

        print(f"[EV]  Current Battery: {battery}%")
        print(f"[EV]  Max battery capacity: {MAX_KWH} kWh")

        desired_percent = int(input(" Enter % of charge you want (e.g., 80): ").strip())
        if not (0 <= desired_percent <= 100):
            print("[EV ERROR] Invalid percentage. Please enter between 0 and 100.")
            return

        energy_needed = round((desired_percent - battery) * MAX_KWH / 100, 2)
        if energy_needed <= 0:
            print("[EV]  No additional charge needed.")
            return

        print(f"[EV]  Energy required to reach {desired_percent}%: {energy_needed} kWh")

        timestamp = datetime.now().isoformat()
        nonce = secrets.token_hex(16)

        payload = {
            "ev_id": EV_ID,
            "station_id": STATION_ID,
            "presented_fingerprint": fingerprint,
            "location": {"latitude": lat, "longitude": lon},
            "battery": battery,
            "request_power": energy_needed,
            "timestamp": timestamp,
            "nonce": nonce
        }

        # Send plain JSON payload
        sock = socket.socket()
        sock.connect((SERVER_IP, SERVER_PORT))
        sock.sendall((json.dumps(payload) + "\n").encode())

        while True:
            data = sock.recv(2048)
            if not data:
                break
            msg = data.decode().strip()
            print(f"[EV]  Received: {msg}")

            if msg.startswith("REJECT"):
                break
            elif msg.startswith("ACCEPT"):
                continue
            elif msg == "start_charging":
                continue
            elif msg == "POWER_REQUEST":
                sock.send(f"{energy_needed}\n".encode())
            elif msg.startswith("CHARGING_STARTED") or msg == "stop_charging":
                print(f"[EV] {msg}")
                if msg == "stop_charging":
                    break
            else:
                try:
                    billing = json.loads(msg)
                    print("[EV]  Billing Info:")
                    for key, val in billing.items():
                        print(f"   {key}: {val}")
                except:
                    print("[EV] ⚠ Received unknown message format.")

        sock.close()

    except Exception as e:
        print(f"[EV ERROR] {e}")

# ====== Web Server for Location ======
class CustomHandler(http.server.SimpleHTTPRequestHandler):
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
                self.wfile.write(b"Location saved")
                print(f"[Server]  Location saved to location.json: {data}")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Failed to save location")
                print(f"[Server]  Error saving location: {e}")
        else:
            self.send_error(404)

def start_web_server():
    os.chdir(".")
    with socketserver.TCPServer(("", WEB_PORT), CustomHandler) as httpd:
        print(f" Serving on http://localhost:{WEB_PORT}")
        httpd.serve_forever()

# ====== Main ======
if _name_ == "_main_":
    print("1. Start web server")
    print("2. Run EV client (after getting location)")
    choice = input("Choose (1/2): ").strip()
    if choice == "1":
        start_web_server()
    elif choice == "2":
        run_ev_client()
    else:
        print(" Invalid option")
