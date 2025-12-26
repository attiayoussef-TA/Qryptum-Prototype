# Qryptum-Prototype

🚀 **Presented at the Wave-Particle Nexus Forum 2K25**  
**Date:** 23 December 2025  
**Venue:** National School of Engineering  

**Qryptum-Prototype** is a **hands-on demonstration of hybrid quantum communication technologies**, combining **Quantum Key Distribution** with **Post-Quantum Cryptography**.  
This project was showcased at the student-focused forum to highlight **cutting-edge secure communication concepts** for embedded and IoT networks.

---

## 🔹 Features
- Hybrid **Quantum + Post-Quantum secure multi-hop key distribution**  
- Simulation of **quantum channels with noise & eavesdropping**  
- **Cascade reconciliation and privacy amplification** for secure keys  
- Multi-hop **secure messaging** using **AES-GCM + PQC signatures**  
- **AI-assisted monitoring** with animated network visualization and dashboards  
- Export of **metrics** for analysis (CSV, dashboards, circuit images)  

---

## 🛠 Tech Stack
- **Python 3.10+** – main language for simulation and analysis  
- **Quantum Computing:** Qiskit, qiskit-aer – for BB84 QKD simulations  
- **Post-Quantum Cryptography:** oqs (McEliece, Dilithium) – secure multi-hop communication  
- **Visualization & Animation:** matplotlib, NetworkX, imageio – dashboards, animated networks, circuit diagrams  
- **Data Analysis & Processing:** numpy, pandas – key metrics, simulations, and logging  
- **Cryptography & Security:** AES-GCM, HKDF, cryptography library – hybrid encryption & key derivation  

---

### ⚙️ Configuration / Environment Variables

You can tweak the simulation with the following variables:

- **NUM_BITS_PER_RUN** (256) – Number of bits prepared per run (raw, before corrections)  
- **QBER_ABORT_THRESHOLD** (0.11) – Error threshold beyond which the key is considered compromised and rejected  
- **CHANNEL_ERROR_RATE** (0.01) – Channel noise error rate (realistic modeling)  
- **EAVESDROP_DEFAULT_FRACTION** (0.0) – Fraction of bits intercepted by an eavesdropper (attack simulation)  
- **SEC_PARAM_BITS** (40) – Security parameter subtracted during Privacy Amplification  
- **PA_OUT_BITS_MIN** (64) – Minimum number of usable final key bits  
- **MIN_KEY_FOR_MSG** (32) – Minimum key length required to encrypt a message  
- **ANIMATION_FRAMES** (30) – Number of frames for network animations  
- **PRINT_KEYS / MAX_KEY_PRINT_BITS** (256) – Partial key display for readability  
- **OUTPUT_DIR** (`presentation_outputs/`) – Folder for saving outputs, dashboards, GIFs, and metrics  

### 🧩 Backend (Quantum Simulator)

- **AerSimulator (stabilizer)** – Fast Qiskit simulator optimized for Clifford-type circuits  
- **MAX_SIM_QUBITS** – 14 (practical qubit limit to avoid simulator capacity issues)  

### 🌐 Graph (Multi-User Network)

- **Nodes:** Alice, Bob, Charlie, David, Eve  
- **Edges:** Represent quantum channels (key sharing, possible eavesdropping)  
- **Each edge stores:**  
  - Shared key before/after Privacy Amplification  
  - QBER (Quantum Bit Error Rate)  
  - Bits lost during reconciliation  
  - PQC metrics (signature, verification time)  
  - AES metrics (encryption/decryption time)  
---

## ⚡ Usage / Run Instructions
1. Install dependencies:
```bash
pip install -r requirements.txt
```
### 2. Run the simulation
```bash
python PANTHEON.py
```


