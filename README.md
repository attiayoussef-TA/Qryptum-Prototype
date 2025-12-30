# Qryptum-Prototype

🚀 **Conceived, Engineered & Presented by Youssef Attia | Wave-Particle Nexus Forum 2K25**
**Date:** 23 December 2025  
**Venue:** National School of Engineering  

**Qryptum-Prototype** is a **hands-on demonstration of hybrid quantum communication technologies**, combining **Quantum Key Distribution** with **Post-Quantum Cryptography**.  
This project was showcased at the student-focused forum to highlight **cutting-edge secure communication concepts** for embedded and IoT networks.

---
![Quantum](https://img.shields.io/badge/Quantum-BB84-5e60ce?style=for-the-badge)
![PQC](https://img.shields.io/badge/PQC-Dilithium%20%7C%20McEliece-f77f00?style=for-the-badge)
![Entropy](https://img.shields.io/badge/Entropy-Binary%20Entropy-7400b8?style=for-the-badge)
![Network](https://img.shields.io/badge/Network-Multi--Hop%20QKD-16a085?style=for-the-badge&logo=cloudflare&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)

---


## 🔹 Features
- Hybrid **Quantum + Post-Quantum secure multi-hop key distribution**  
- Simulation of **quantum channels with noise & eavesdropping**  
- **Cascade reconciliation and privacy amplification** for secure keys :
  Privacy amplification length is bounded using the **Binary entropy** function: **m ≤ n · (1 − 2·h₂(QBER)) − leaked_bits − security_parameter**
  where h₂(p) is the binary entropy function. This ensures that the final key length is provably secure against an adversary under the observed QBER.
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

### 4. Results  🧪

The simulations were performed on a graph consisting of five nodes (Alice, Bob, Charlie, David, and Eve), connected by edges representing quantum communication channels. For each run, a total of 4096 bits is generated and processed in successive batches (292 circuits of 14 qubits each). Background channel noise is modeled with an error rate of 0.01, which can be increased by interference from Eve according to a configurable eavesdropping fraction (e.g., 10% of the qubits). Key integrity is monitored through the Quantum Bit Error Rate (QBER), and any key is discarded if it exceeds the threshold of 11%.
Key lengths before and after Privacy Amplification are recorded, with a minimum key size fixed at 64 bits for this scenario.

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


