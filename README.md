# ev-cs-security
🔍 *Problem Statement (Cybersecurity in V2G Communication)*

As Electric Vehicles (EVs) increasingly integrate with the power grid through *Vehicle-to-Grid (V2G)* systems, secure communication between EVs and charging stations becomes critical. However, current V2G protocols (like ISO 15118) are vulnerable to *cyberattacks* such as:

* *Man-in-the-Middle (MITM) attacks*, where an attacker intercepts and modifies messages between the EV and the charging station.
* *Replay attacks*, where old valid messages are resent to trigger unauthorized charging or disrupt service.

These attacks can lead to *energy theft, billing fraud, denial of service, or unsafe charging behavior*, making V2G systems a significant cybersecurity risk.

✅ *Proposed Solution (Simulation + Attack + Defense Framework)*

We propose a *software-based simulation of the V2G communication protocol* using Python, where we:

1. *Simulate a simplified V2G handshake* between an EV and a Charging Station (CS).
2. *Introduce MITM and replay attacks* by placing a proxy attacker between the EV and CS.
3. *Implement and evaluate defense mechanisms*, such as:

   * Nonce-based challenge-response* to prevent replay
   * Message integrity checking* using hashing or HMAC
   * Certificate pinning* to block fake charging stations
