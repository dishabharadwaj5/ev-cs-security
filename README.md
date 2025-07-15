# 🔐 EV ↔ Charging Station Secure Communication Simulation

A full-stack simulation of a secure communication protocol between an Electric Vehicle (EV) and a Charging Station (CS), built to **demonstrate, detect, and defend** against **Man-in-the-Middle (MITM)** and **Replay** attacks in real-time.

> ⚠️ This simulation targets **wireless EV ↔ Charging Station systems**, such as those using Wi-Fi, Bluetooth, or V2G protocols — where security risks are significantly higher due to open networks.

---

## ⚡️ Core Features

- 🛡️ **Hybrid Encryption**:
  - RSA for secure key exchange.
  - AES for fast, encrypted message transmission.
- 🧠 **Replay Attack Prevention** using:
  - Nonce validation
  - Timestamp verification
  - Context-aware hash tokening (`GPS + battery + timestamp + power`)
- 🕵️ **MITM Module** with:
  - Real-time socket-level interception
  - Payload modification
  - Session replaying
- 📊 **Charging Station Dashboard**:
  - Live EV request display
  - Attack detection logging
  - Charging progress bar
  - Billing calculation based on kWh and time
- 🧪 **Security toggle**: Run with or without encryption to visualize attack impact.

---

## 🔍 What Makes This Unique

This isn’t your basic “replay the same packet” toy example. Here's what makes this simulation different:

- 🔄 **Protocol-Level Simulation**: Built on **Python socket programming** instead of network sniffing or packet injection.
- 🔐 **Actual Cryptography**: Uses **RSA + AES**, not placeholder functions or mock security.
- 📍 **Context-Bound Validation**: Even valid requests get rejected if context (location, battery, etc.) doesn’t match.
- 🧩 **Modular Actor Design**: EV, CS, and Attacker are separate programs with clear roles and lifecycle control.
- 🧪 **Full Attack Lifecycle**: Capture → Modify → Replay → Detect — all within one system.
- 📈 **Real-Time Dashboard**: Visualize the full communication flow, status, and security verdicts live.

---

## 🧰 Components

| File / Folder          | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `ev_client.py`         | Simulates the Electric Vehicle — sends encrypted auth + power requests      |
| `charging_station_server.py` | Validates requests, decrypts payloads, and detects attacks           |
| `attacker_mitm.py`     | Socket-level MITM proxy for interception and payload tampering              |
| `attacker_replay.py`   | Replays previously captured sessions (from log) to simulate replay attacks |
| `replay_log.json`      | Stores recorded sessions captured by MITM for future replay                |
| `dashboard/`           | Streamlit dashboard for request monitoring and attack detection             |
| `certs/`               | Contains digital certificates and RSA keys for EV and CS                    |
| `crypto/`              | AES and RSA helper modules for secure encryption & decryption               |

---

## 🚀 How to Run the Simulation

### 1. Clone the Repository

```bash
git clone https://github.com/dishabharadwaj5/ev-cs-secure-sim.git
cd ev-cs-secure-sim

<pre lang="bash"> # 🚀 How to Run the Simulation # 1. Clone the Repository git clone https://github.com/dishabharadwaj5/ev-cs-secure-sim.git cd ev-cs-secure-sim # 2. Install Requirements pip install -r requirements.txt # 3. Start the Charging Station Server python charging_station_server.py # 4. Run the EV Client python ev_client.py # 5. (Optional) Launch the MITM Attacker python attacker_mitm.py # 6. (Optional) Launch the Replay Attacker python attacker_replay.py # 7. (Optional) Start the Real-Time Dashboard streamlit run dashboard/app.py </pre>
