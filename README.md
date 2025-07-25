# 🔐 EV ↔ Charging Station Secure Communication Simulation

A full-stack simulation of a secure communication protocol between an Electric Vehicle (EV) and a Charging Station (CS), built to **demonstrate, detect, and defend** against **Man-in-the-Middle (MITM)** and **Replay** attacks in real-time.

> ⚠️ This simulation targets **wireless EV ↔ Charging Station systems**, such as those using Wi-Fi, Bluetooth, or V2G protocols — where security risks are significantly higher due to open networks.

---

## ⚡️ Core Features

- 🛡️ **Hybrid Encryption**:
  - RSA for secure key exchange.
  - AES for fast, encrypted message transmission.
- 🧠 **Replay Attack Prevention** using:
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
- 🔐 **Actual Cryptography**: Uses **RSA + AES**.
- 📍 **Context-Bound Validation**: Even valid requests get rejected if context (location, battery,timestamp, etc.) doesn’t match.
- 🧩 **Modular Actor Design**: EV, CS, and Attacker are separate programs with clear roles and lifecycle control.
- 🧪 **Full Attack Lifecycle**: Capture → Modify → Replay → Detect — all within one system.
- 📈 **Real-Time Dashboard**: Visualize the full communication flow, status, and security verdicts live.

---## 🧰 Components

| File / Folder                             | Description                                                                 |
|------------------------------------------|-----------------------------------------------------------------------------|
| `server_nocrypto.py`                     | Charging Station (CS) server code without cryptography                      |
| `server_crypto.py`                       | Charging Station (CS) server code with hybrid cryptography (RSA + AES)      |
| `client_nocrypto.py`                     | EV client code without cryptography (sends plain messages)                  |
| `client_crypto.py`                       | EV client code with hybrid cryptography (RSA + AES)                         |
| `attacker.py`                            | Socket-level MITM proxy for intercepting, modifying, and replaying sessions |
| `replay_log.json`                        | Stores recorded EV–CS sessions captured by MITM for replay attacks          |
| `server_dashboard.py`                    | Flask dashboard for real-time request monitoring and attack detection       |
| `generate_key.py`                        | Generates RSA key pairs for server and client                               |
| `legitimate_charging_stations_expanded.json` | Contains pinned data of all legitimate Charging Stations (CS)              |
| `expanded_compromised_expired_stations.json` | Contains details of expired or compromised stations                        |
| `expanded_attacker_fake_stations.json`   | Contains spoofed/fake station data used by attacker                         |

---


## 🚀 How to Run the Simulation

### 1. Clone the Repository

```bash
git clone https://github.com/dishabharadwaj5/ev-cs-secure-sim.git
cd ev-cs-secure-sim
```

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

### 3. Start the Charging Station Server

```bash
python charging_station_server.py
```

### 4. Run the EV Client

```bash
python ev_client.py
```

### 5. (Optional) Launch the MITM Attacker

```bash
python attacker_mitm.py
```

### 6. (Optional) Launch the Replay Attacker

```bash
python attacker_replay.py
```

### 7. (Optional) Start the Real-Time Dashboard

```bash
streamlit run dashboard/app.py
```

---

🙌 Authors
Disha Bharadwaj
Nandani Prasad
Dhvani Amit Banker
T G Sanjana
