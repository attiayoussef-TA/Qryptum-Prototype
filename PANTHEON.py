#!/usr/bin/env python3
"""
Run (CMD):
  set NUM_BITS_PER_RUN=4096
  set EAVESDROP_FRACTION=0.1
  set QBER_ABORT_THRESHOLD=0.11
  set CHANNEL_ERROR_RATE=0.01
  set PRINT_KEYS=1
  python PANTHEON.py
Dependencies: qiskit, qiskit-aer, oqs, matplotlib, networkx, numpy, cryptography, tqdm, pandas, imageio
"""

import os
import time
import random
import math
import hashlib
import concurrent.futures
from collections import defaultdict
from tqdm import tqdm
import csv
import imageio

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import numpy as np
import pandas as pd
import base64

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

import oqs

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import networkx as nx

# ---------------------- Config ----------------------
NUM_BITS_PER_RUN = int(os.getenv("NUM_BITS_PER_RUN", 256))  
QBER_ABORT_THRESHOLD = float(os.getenv("QBER_ABORT_THRESHOLD", 0.11))
CHANNEL_ERROR_RATE = float(os.getenv("CHANNEL_ERROR_RATE", 0.01))  
EAVESDROP_DEFAULT_FRACTION = float(os.getenv("EAVESDROP_FRACTION", 0.0))
SEC_PARAM_BITS = int(os.getenv("SEC_PARAM_BITS", 40))  
PA_OUT_BITS_MIN = int(os.getenv("PA_OUT_BITS_MIN", 64)) 
MIN_KEY_FOR_MSG = int(os.getenv("MIN_KEY_FOR_MSG", 32))
ANIMATION_FRAMES = int(os.getenv("ANIMATION_FRAMES", 30))
PRINT_KEYS = bool(int(os.getenv("PRINT_KEYS", "1")))                    
MAX_KEY_PRINT_BITS = int(os.getenv("MAX_KEY_PRINT_BITS", "256"))        
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "presentation_outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------- Backend ----------------------
backend = AerSimulator(method='stabilizer')

# Practical per-circuit cap to avoid "'Number of qubits ... is greater than maximum (14) in the coupling_map'"
bk_max = getattr(backend.configuration(), "n_qubits", 32)
MAX_SIM_QUBITS = int(os.getenv("MAX_SIM_QUBITS", min(14, bk_max)))  # safe default: 14

# ---------------------- Graph ----------------------
G = nx.Graph()
G.add_nodes_from(["Alice", "Bob", "Charlie", "David", "Eve"])  
edges = [
    ("Alice", "Eve"),
    ("Eve", "Bob"),
    ("Alice", "Charlie"),
    ("Bob", "David"),
    ("Charlie", "David"),
]
G.add_edges_from(edges)

for u, v in G.edges():
    G[u][v]["shared_key"] = None
    G[u][v]["eavesdropped"] = False
    G[u][v]["error_rate"] = 1.0
    G[u][v]["circuit"] = None
    G[u][v]["metrics"] = {
        "key_len_before_pa": 0,
        "key_len_after_pa": 0,
        "qber_sample": None,
        "reconciliation_leaked_bits": 0,
        "pa_out_bits": 0,
        "pqc_sign_time": 0.0,
        "pqc_verify_time": 0.0,
        "aes_enc_time": 0.0,
        "aes_dec_time": 0.0,
        "timestamp": None,
        "establish_time": None,
    }

# ---------------------- Utilities / Logging ----------------------
CSI = "\x1B["
FG_RED = CSI + "31m"
FG_GREEN = CSI + "32m"
FG_YELLOW = CSI + "33m"
FG_CYAN = CSI + "36m"
RESET = CSI + "0m"

def log_info(msg):
    print(FG_CYAN + "[INFO] " + RESET + msg)

def log_good(msg):
    print(FG_GREEN + "[OK]   " + RESET + msg)

def log_warn(msg):
    print(FG_YELLOW + "[WARN] " + RESET + msg)

def log_err(msg):
    print(FG_RED + "[FAIL] " + RESET + msg)

# ---------------------- Helpers ----------------------

def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        bits = bits + [0] * (8 - len(bits) % 8)
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        b.append(byte)
    return bytes(b)

def derive_aes_key_from_bits(bits, length_bytes=32, salt=None):
    ikm = bits_to_bytes(bits)
    if salt is None:
        salt = hashlib.sha256(b"default-qkd-salt").digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length_bytes,
        salt=salt,
        info=b"qkd-hybrid-aes-key",
        backend=default_backend(),
    )
    return hkdf.derive(ikm)

def aes_gcm_encrypt(key_bytes, plaintext_bytes, aad=b""):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key_bytes), modes.GCM(iv), backend=default_backend()).encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def aes_gcm_decrypt(key_bytes, iv, ciphertext, tag, aad=b""):
    decryptor = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    if aad:
        decryptor.authenticate_additional_data(aad)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# ---------------------- Information-theoretic helpers ----------------------

def h2(p: float) -> float:
    """Binary entropy in bits."""
    if p <= 0.0 or p >= 1.0:
        return 0.0 if p in (0.0, 1.0) else 1.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)

# ---------------------- BB84 / QKD functions ----------------------

def bb84_run(num_bits: int):
    
    # num_bits qubits (must be <= MAX_SIM_QUBITS!)
    bits = [random.randint(0, 1) for _ in range(num_bits)]
    sender_bases = [random.choice(['Z', 'X']) for _ in range(num_bits)]
    receiver_bases = [random.choice(['Z', 'X']) for _ in range(num_bits)]

    qc = QuantumCircuit(num_bits, num_bits)
    for i in range(num_bits):
        if bits[i] == 1:
            qc.x(i)
        if sender_bases[i] == 'X':
            qc.h(i)
        if receiver_bases[i] == 'X':
            qc.h(i)
    qc.measure(range(num_bits), range(num_bits))

    compiled_qc = transpile(qc, backend=backend, optimization_level=0, layout_method='trivial')
    job = backend.run(compiled_qc, shots=1, memory=True)
    result = job.result()
    measured_bits = list(map(int, result.get_memory()[0]))[::-1]

    
    sifted_sender, sifted_receiver = [], []
    for i in range(num_bits):
        if sender_bases[i] == receiver_bases[i]:
            sifted_sender.append(bits[i])
            sifted_receiver.append(measured_bits[i])

    return sifted_sender, sifted_receiver, qc

def bb84_run_chunked(num_bits_total: int):
    total_A, total_B = [], []
    last_qc = None
    remaining = num_bits_total
    while remaining > 0:
        chunk = min(MAX_SIM_QUBITS, remaining)
        sA, sB, qc = bb84_run(chunk)
        total_A.extend(sA)
        total_B.extend(sB)
        last_qc = qc
        remaining -= chunk
    return total_A, total_B, last_qc

def inject_channel_and_eve_errors(receiver_bits, eavesdrop_fraction=0.0, channel_error_rate=CHANNEL_ERROR_RATE):
    """Flip receiver bits with probability p = channel_error + 0.25*eavesdrop_fraction
    to approximate intercept-resend disturbance + background noise."""
    p_flip = min(1.0, channel_error_rate + 0.25 * max(0.0, eavesdrop_fraction))
    out = []
    for b in receiver_bits:
        if random.random() < p_flip:
            out.append(1 - b)
        else:
            out.append(b)
    return out

# ---------------------- Reconciliation & PA ----------------------

def cascade_reconciliation(kA, kB, max_passes=4, initial_block_size=32):
    if len(kA) != len(kB):
        raise ValueError("Keys must be same length for cascade_reconciliation")
    n = len(kA)
    A = kA[:]
    B = kB[:]
    leaked = 0
    block_size = max(2, min(initial_block_size, n))

    for p in range(max_passes):
        if block_size < 2:
            break
        offset = (p * 3) % block_size
        for start in range(offset, n, block_size):
            end = min(start + block_size, n)
            parityA = sum(A[start:end]) % 2
            parityB = sum(B[start:end]) % 2
            leaked += 1
            if parityA != parityB:
                l, r = start, end
                while r - l > 1:
                    mid = (l + r) // 2
                    parityA_half = sum(A[l:mid]) % 2
                    parityB_half = sum(B[l:mid]) % 2
                    leaked += 1
                    if parityA_half != parityB_half:
                        r = mid
                    else:
                        l = mid
                B[l] = 1 - B[l]
        block_size = max(2, block_size // 2)

    return A, B, leaked

def privacy_amplification(key_bits, qber_est, leaked_bits, sec_param_bits=SEC_PARAM_BITS, min_out=PA_OUT_BITS_MIN):
    """
    Bound: m <= n * (1 - 2*h2(QBER)) - leaked_bits - sec_param_bits.
    Also never exceed n - leaked_bits - sec_param_bits and never be negative.
    """
    n = len(key_bits)
    bound = math.floor(n * max(0.0, (1.0 - 2.0 * h2(min(0.5, qber_est)))))
    m = min(bound - leaked_bits - sec_param_bits, n - leaked_bits - sec_param_bits)
    m = max(0, m)
    out_len_bits = min(max(min_out, 0) if m >= min_out else m, m)

    key_bytes = bits_to_bytes(key_bits)
    digest = hashlib.sha256(key_bytes).digest()
    out_bytes = digest[: (out_len_bits + 7)//8]
    out_bits = []
    for b in out_bytes:
        for i in reversed(range(8)):
            out_bits.append((b >> i) & 1)
    return out_bits[:out_len_bits]

# ---------------------- Establish QKD Link ----------------------

def establish_qkd_link(graph, node_a, node_b, num_bits=NUM_BITS_PER_RUN, eavesdrop=False, eavesdrop_fraction=EAVESDROP_DEFAULT_FRACTION):
    t0 = time.time()

    # Chunked BB84: concatenate sifted keys across small circuits
    sA_total, sB_total, last_qc = bb84_run_chunked(num_bits_total=num_bits)

    # Inject errors 
    sB_noisy = inject_channel_and_eve_errors(
        sB_total,
        eavesdrop_fraction=eavesdrop_fraction if eavesdrop else 0.0,
        channel_error_rate=CHANNEL_ERROR_RATE
    )

    
    if len(sA_total) < 16:
        m = graph[node_a][node_b]["metrics"]
        m.update({
            "key_len_before_pa": 0,
            "key_len_after_pa": 0,
            "qber_sample": 1.0,
            "reconciliation_leaked_bits": 0,
            "pa_out_bits": 0,
            "timestamp": time.time(),
            "establish_time": time.time() - t0,
        })
        graph[node_a][node_b]["shared_key"] = None
        graph[node_a][node_b]["eavesdropped"] = eavesdrop
        graph[node_a][node_b]["error_rate"] = 1.0
        graph[node_a][node_b]["circuit"] = last_qc
        log_warn(f"Edge {node_a}-{node_b}: insufficient sifted bits ({len(sA_total)})")
        return None

    # Estimate QBER on a larger sample (20% of bits, at least 32)
    sample_size = max(32, int(0.2 * len(sA_total)))
    sample_size = min(sample_size, len(sA_total))
    sample_indices = random.sample(range(len(sA_total)), sample_size)
    mismatches = sum(1 for idx in sample_indices if sA_total[idx] != sB_noisy[idx])
    qber_est = mismatches / sample_size if sample_size > 0 else 1.0

    # Abort rule
    if qber_est > QBER_ABORT_THRESHOLD:
        m = graph[node_a][node_b]["metrics"]
        m.update({
            "key_len_before_pa": 0,
            "key_len_after_pa": 0,
            "qber_sample": qber_est,
            "reconciliation_leaked_bits": 0,
            "pa_out_bits": 0,
            "timestamp": time.time(),
            "establish_time": time.time() - t0,
        })
        graph[node_a][node_b]["shared_key"] = None
        graph[node_a][node_b]["eavesdropped"] = eavesdrop
        graph[node_a][node_b]["error_rate"] = qber_est
        graph[node_a][node_b]["circuit"] = last_qc
        log_warn(f"Edge {node_a}-{node_b}: ABORT due to high QBER={qber_est:.3f}")
        return None

    # Remove sample from the keys
    keep_mask = [True] * len(sA_total)
    for i in sample_indices:
        keep_mask[i] = False
    kA = [sA_total[i] for i in range(len(sA_total)) if keep_mask[i]]
    kB = [sB_noisy[i] for i in range(len(sA_total)) if keep_mask[i]]

    # Cascade reconciliation
    A_after, B_after, leaked_bits = cascade_reconciliation(kA, kB)

    # PA length bound and PA application
    pa_bits = privacy_amplification(A_after, qber_est, leaked_bits)

    # Populate graph
    graph[node_a][node_b]["shared_key"] = pa_bits if len(pa_bits) > 0 else None
    graph[node_a][node_b]["eavesdropped"] = eavesdrop
    graph[node_a][node_b]["error_rate"] = qber_est
    graph[node_a][node_b]["circuit"] = last_qc

    m = graph[node_a][node_b]["metrics"]
    m.update({
        "key_len_before_pa": len(A_after),
        "key_len_after_pa": len(pa_bits),
        "qber_sample": qber_est,
        "reconciliation_leaked_bits": leaked_bits,
        "pa_out_bits": len(pa_bits),
        "timestamp": time.time(),
        "establish_time": time.time() - t0,
    })

    status = "OK" if len(pa_bits) > 0 else "EMPTY"
    log_info(f"Edge {node_a}-{node_b}: {status} | sifted={len(sA_total)} qber={qber_est:.3f} leaked={leaked_bits} pa={len(pa_bits)}")
    return pa_bits if len(pa_bits) > 0 else None

# ---------------------- Multi-hop key distribution ----------------------

def distribute_key_via_path(graph, path):
    if len(path) < 2:
        return None
    keys = []
    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        if graph.has_edge(a, b):
            k = graph[a][b].get("shared_key")
            if k is None:
                return None
            keys.append(k)
        else:
            return None
    L = min(len(k) for k in keys)
    combined = []
    for i in range(L):
        bit = 0
        for k in keys:
            bit ^= k[i]
        combined.append(bit)
    return combined

# ---------------------- Secure messaging (PQC-sign ) ----------------------

def send_secure_message(sender, receiver, plaintext, graph, signature_obj, pk_obj, use_aes=True, aad=b""):
    try:
        shortest_path = nx.shortest_path(graph, sender, receiver)
    except nx.NetworkXNoPath:
        log_err(f"No path between {sender} and {receiver}")
        return False

    current_data = plaintext.encode()

    for i in range(len(shortest_path) - 1):
        a, b = shortest_path[i], shortest_path[i + 1]

        # Get edge's QKD key
        key_bits = graph[a][b].get("shared_key")
        if not key_bits or len(key_bits) < MIN_KEY_FOR_MSG:
            log_warn(f"Insufficient key length on hop {a}-{b} (len={0 if not key_bits else len(key_bits)})")
            return False

        # Derive AES key for this hop
        salt = hashlib.sha256(f"{a}-{b}-salt".encode()).digest()
        key_bytes = derive_aes_key_from_bits(key_bits, length_bytes=32, salt=salt)

        # AES encryption time
        enc_time = dec_time = 0.0
        if use_aes:
            t0 = time.time()
            iv, ct, tag = aes_gcm_encrypt(key_bytes, current_data, aad=aad)
            enc_time = time.time() - t0
        else:
            ct = current_data

        # PQC sign
        t0 = time.time()
        signature = signature_obj.sign(ct)
        sign_time = time.time() - t0

        # PQC verify
        t0 = time.time()
        ok = signature_obj.verify(ct, signature, pk_obj)
        verify_time = time.time() - t0
        if not ok:
            log_err(f"Signature verify failed on hop {a}-{b}")
            return False

        # AES decryption time
        if use_aes:
            t0 = time.time()
            current_data = aes_gcm_decrypt(key_bytes, iv, ct, tag, aad=aad)
            dec_time = time.time() - t0
        else:
            current_data = ct

        # Store metrics per hop
        m = graph[a][b]["metrics"]
        m["pqc_sign_time"] = sign_time
        m["pqc_verify_time"] = verify_time
        m["aes_enc_time"] = enc_time
        m["aes_dec_time"] = dec_time

    log_good(f"[{receiver}] Received message from {sender}: {current_data.decode()}")
    return True

# ---------------------- Drawing, Animation & Dashboard ----------------------

def draw_circuits(graph, out_dir=os.path.join(OUTPUT_DIR, "circuits")):
    os.makedirs(out_dir, exist_ok=True)
    for u, v in graph.edges():
        circ = graph[u][v].get("circuit")
        if circ is None:
            continue
        try:
            fig = circ.draw(output='mpl', fold=-1)
            fig.suptitle(f"Circuit {u}<->{v}", fontsize=10, color='#0ff')
            fig.savefig(os.path.join(out_dir, f"{u}_{v}_circ.png"), dpi=150)
            plt.close(fig)
        except Exception as e:
            log_warn(f"Failed to draw circuit for edge {u}-{v}: {e}")

def plot_dashboard(graph, out_file=os.path.join(OUTPUT_DIR, "dashboard.png")):
    edges = list(graph.edges())
    labels = [f"{u}-{v}" for u, v in edges]
    key_lens = [graph[u][v]["metrics"]["key_len_after_pa"] for u, v in edges]
    qbers = [graph[u][v]["metrics"]["qber_sample"] or 0 for u, v in edges]
    leaked = [graph[u][v]["metrics"]["reconciliation_leaked_bits"] for u, v in edges]

    x = np.arange(len(edges))
    width = 0.25

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - width, key_lens, width, label='Key len (after PA)')
    ax.bar(x, np.array(qbers) * 100, width, label='QBER (%)')
    ax.bar(x + width, leaked, width, label='Leaked bits (recon)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30)
    ax.set_ylabel('Value')
    ax.set_title('Per-edge QKD metrics')
    ax.legend()
    plt.tight_layout()
    fig.savefig(out_file)
    plt.close(fig)
    log_info(f"Saved dashboard to {out_file}")

def animate_network(graph, out_file=os.path.join(OUTPUT_DIR, "network_anim.gif"), frames=ANIMATION_FRAMES):
    pos = nx.spring_layout(graph, seed=42)
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.set_facecolor('#001122')
    ax.axis('off')

    max_key = max((graph[u][v]['metrics']['key_len_after_pa'] for u, v in graph.edges()), default=1)

    def draw_frame(frame_idx):
        ax.clear()
        ax.set_facecolor('#001122')
        ax.axis('off')
        edge_colors, widths = [], []
        for u, v in graph.edges():
            m = graph[u][v]['metrics']
            q = m['qber_sample'] if m['qber_sample'] is not None else 1.0
            if q > QBER_ABORT_THRESHOLD:
                edge_colors.append('#FF4136')
            elif q > 0.05:
                edge_colors.append('#FF851B')
            else:
                edge_colors.append('#7FDBFF')
            wbase = max(1, (m['key_len_after_pa'] / (max_key or 1)) * 6)
            widths.append(wbase * (0.8 + 0.4 * np.sin(2 * np.pi * (frame_idx / frames))))
        nx.draw_networkx_nodes(graph, pos, node_color=['#FF4136' if n == 'Eve' else '#0ff' for n in graph.nodes()], node_size=700)
        nx.draw_networkx_labels(graph, pos, font_color='black')
        nx.draw_networkx_edges(graph, pos, edge_color=edge_colors, width=widths)
        ax.set_title('Cyber-Quantum Network (animated)', color='#0ff')

    
    temp_pngs = []
    for i in range(frames):
        draw_frame(i)
        fname = os.path.join(OUTPUT_DIR, f"frame_{i:03d}.png")
        plt.savefig(fname, dpi=120, facecolor=fig.get_facecolor())
        temp_pngs.append(fname)
    import imageio.v2 as iio
    imgs = [iio.imread(p) for p in temp_pngs]
    iio.mimsave(out_file, imgs, duration=0.12)
    for p in temp_pngs:
        try:
            os.remove(p)
        except Exception:
            pass
    log_info(f"Saved animation to {out_file}")

# ---------------------- Metrics export ----------------------

def export_metrics_csv(graph, out_file=os.path.join(OUTPUT_DIR, 'metrics.csv')):
    rows = []
    for u, v in graph.edges():
        m = graph[u][v]['metrics']
        rows.append({
            'edge': f"{u}-{v}",
            'key_before_pa': m['key_len_before_pa'],
            'key_after_pa': m['key_len_after_pa'],
            'qber_sample': m['qber_sample'],
            'recon_leaked': m['reconciliation_leaked_bits'],
            'pa_out_bits': m['pa_out_bits'],
            'pqc_sign_time': m['pqc_sign_time'],
            'pqc_verify_time': m['pqc_verify_time'],
            'aes_enc_time': m['aes_enc_time'],
            'aes_dec_time': m['aes_dec_time'],
            'establish_time': m.get('establish_time'),
            'timestamp': m.get('timestamp'),
        })
    df = pd.DataFrame(rows)
    df.to_csv(out_file, index=False)
    log_info(f"Exported metrics CSV to {out_file}")

# ---------------------- Printing of keys ----------------------

def _bitstr(bits, maxbits=None):
    s = ''.join(str(b) for b in bits)
    if maxbits and len(s) > maxbits:
        return s[:maxbits] + f"... ({len(bits)} bits total)"
    return s

def print_edge_keys(graph, maxbits=MAX_KEY_PRINT_BITS):
    log_info("Per-edge PA keys:")
    for u, v in graph.edges():
        k = graph[u][v].get("shared_key")
        if k:
            bit_s = _bitstr(k, maxbits)
            hex_s = bits_to_bytes(k).hex()
            print(f"  {u}-{v}: len={len(k)} bits | bits={bit_s} | hex={hex_s}")
        else:
            print(f"  {u}-{v}: NO KEY")

def print_path_key(graph, path, maxbits=MAX_KEY_PRINT_BITS):
    k = distribute_key_via_path(graph, path)
    label = "->".join(path)
    if k:
        bit_s = _bitstr(k, maxbits)
        hex_s = bits_to_bytes(k).hex()
        print(f"  Path {label} XOR key: len={len(k)} bits | bits={bit_s} | hex={hex_s}")
    else:
        print(f"  Path {label} XOR key: NO KEY (one or more hops missing)")

# ---------------------- Runner / main ----------------------

def run_qkd_for_all_edges(graph, eavesdrop_edges, num_bits=NUM_BITS_PER_RUN, eavesdrop_fraction=EAVESDROP_DEFAULT_FRACTION):
    all_edges = list(graph.edges())
    log_info("Starting parallel QKD runs on edges...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for u, v in all_edges:
            eav = (u, v) in eavesdrop_edges or (v, u) in eavesdrop_edges
            futures.append(executor.submit(
                establish_qkd_link, graph, u, v, num_bits,
                eavesdrop=eav,
                eavesdrop_fraction=eavesdrop_fraction if eav else 0.0,
            ))
        for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
            try:
                f.result()
            except Exception as e:
                log_err(f"Error in QKD edge simulation: {e}")

def main():
    log_info("Bootstrapping PQC...")
    
    kem = oqs.KeyEncapsulation('Classic-McEliece-8192128')
    pk_kem = kem.generate_keypair()

    sig = oqs.Signature('Dilithium2')
    pk_sig = sig.generate_keypair()

    
    eavesdrop_edges = {("Alice", "Eve"), ("Eve", "Bob")}  

    # Run QKD on all edges
    run_qkd_for_all_edges(G, eavesdrop_edges, num_bits=NUM_BITS_PER_RUN, eavesdrop_fraction=EAVESDROP_DEFAULT_FRACTION)

    
    if PRINT_KEYS:
        print()
        print_edge_keys(G)
        print()
        print_path_key(G, ["Alice", "Charlie", "David"])
        print_path_key(G, ["Charlie", "David", "Bob"])
        print()

    
    draw_circuits(G)
    plot_dashboard(G)
    animate_network(G)
    
    log_info('\nDemo: Alice -> David (multi-hop)')
    send_secure_message('Alice', 'David', 'Hello David! Hybrid QKD+PQC.', G, sig, pk_sig, use_aes=True, aad=b"demo-A2D")

    log_info('\nDemo: Charlie -> Bob (multi-hop)')
    send_secure_message('Charlie', 'Bob', 'Hey Bob, secure quantum vibes!', G, sig, pk_sig, use_aes=True, aad=b"demo-C2B")

    export_metrics_csv(G)

    log_good('\nAll done. Check the presentation_outputs/ folder for visuals, circuits, metrics.csv and animation GIF.')

if __name__ == '__main__':
    main()
