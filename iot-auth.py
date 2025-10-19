import socket, threading, time, os, struct, sys
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------
# Configuration
# -------------------------
HOST = '127.0.0.1'
PORT = 55000

# 256-bit master key. In real deployments provision securely.
K_MASTER = b'\x01' * 32

DEVICE_ID = b'DEV01'   # 5 bytes
GW_ID = b'GW01'        # 4 bytes

MSG_BUFFER = 2048

# Timeout / TTL (seconds)
TIMESTAMP_TTL = 60

# -------------------------
# Utility helpers
# -------------------------
def hkdf_derive(master, salt, info=b'', length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master)

def hmac_sha256(key, msg):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()

def pack_msg(parts):
    """Simple length-prefixed packer for variable parts"""
    out = b''
    for p in parts:
        out += struct.pack('!H', len(p)) + p
    return out

def unpack_msg(b):
    i = 0
    parts = []
    while i < len(b):
        if i + 2 > len(b): break
        l = struct.unpack_from('!H', b, i)[0]; i += 2
        parts.append(b[i:i+l]); i += l
    return parts

# Gateway (Server)

class Gateway(threading.Thread):
    def __init__(self, metrics, port=PORT):
        super().__init__()
        self.port = port
        self.metrics = metrics
        self.last_nonceD = None
        self.saved_session = None

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST, self.port))
        s.listen(1)
        print("[GW] Listening on {}:{}".format(HOST, self.port))
        conn, _ = s.accept()
        print("[GW] Connected")
        start_time = time.perf_counter()
        data = conn.recv(MSG_BUFFER)
        t_recv_init = time.perf_counter()
        parts = unpack_msg(data)
        if len(parts) < 3:
            print("[GW] malformed init")
            conn.close(); return
        idD, nonceD, tsD = parts
        self.last_nonceD = nonceD
        ts = struct.unpack('!I', tsD)[0]
        print("[GW] INIT from", idD, "nonceD", nonceD.hex(), "ts", ts)

        # timestamp check
        if abs(time.perf_counter() - ts) > TIMESTAMP_TTL:
            print("[GW] timestamp outside TTL")
            conn.close(); return

        # prepare GW nonce & derive session
        nonceG = os.urandom(12)
        info = idD + nonceG
        K_sess = hkdf_derive(K_MASTER, salt=nonceD, info=info, length=32)
        K_enc = K_sess[:16]; K_mac = K_sess[16:]
        aesgcm = AESGCM(K_enc)

        plaintext = b'GW_OK|' + GW_ID
        aad = nonceD
        t_before_enc = time.perf_counter()
        ct = aesgcm.encrypt(nonceG, plaintext, aad)
        t_after_enc = time.perf_counter()
        mac = hmac_sha256(K_mac, nonceG + GW_ID + nonceD)

        # record metrics
        self.metrics['gw_enc_time_ms'] = (t_after_enc - t_before_enc) * 1000
        msg1 = pack_msg([nonceG, ct, mac])
        self.metrics['gw_msg1_size'] = len(msg1)
        conn.send(msg1)
        t_sent1 = time.perf_counter()

        # wait for device response
        resp = conn.recv(MSG_BUFFER)
        t_recv2 = time.perf_counter()
        parts2 = unpack_msg(resp)
        if len(parts2) < 2:
            print("[GW] malformed response")
            conn.close(); return
        ct2, mac2 = parts2
        # verify MAC of ct2 (we used MAC over ciphertext for demonstration)
        # decrypt
        try:
            pt2 = aesgcm.decrypt(nonceG, ct2, aad)
            # pt2 format: b'DEV_OK|ID_D|nonceG'
            tokens = pt2.split(b'|')
            if len(tokens) < 3 or tokens[0] != b'DEV_OK':
                print("[GW] device reported not OK or malformed")
                conn.close(); return
            idd = tokens[1]
            # Verify mac (simple check): ensure mac2 matches HMAC(K_mac, ct2)
            if hmac_sha256(K_mac, ct2) != mac2:
                print("[GW] MAC mismatch on device response")
                conn.close(); return
            print("[GW] Mutual auth OK with device", idd)
            self.metrics['round_trip_ms'] = (t_recv2 - start_time) * 1000
            self.metrics['gw_msg2_size'] = len(resp)
            # save session (for demonstration)
            self.saved_session = {'id': idd, 'K_enc': K_enc, 'K_mac': K_mac, 'nonceG': nonceG}
        except Exception as e:
            print("[GW] decrypt/verify failed:", e)
        conn.close()

# Device (Client)

class Device(threading.Thread):
    def __init__(self, metrics, device_id=DEVICE_ID, port=PORT, do_replay=False, replay_capture=None):
        super().__init__()
        self.device_id = device_id
        self.port = port
        self.metrics = metrics
        self.do_replay = do_replay
        self.replay_capture = replay_capture

    def run(self):
        time.sleep(0.3)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, self.port))
        nonceD = os.urandom(12)
        ts = struct.pack('!I', int(time.perf_counter()))  # Note: This might need adjustment
        init = pack_msg([self.device_id, nonceD, ts])
        self.metrics['dev_msg1_size'] = len(init)
        t_start = time.perf_counter()
        s.send(init)
        # receive GW response
        data = s.recv(MSG_BUFFER)
        t_recv = time.perf_counter()
        parts = unpack_msg(data)
        if len(parts) < 3:
            print("[DEV] malformed response")
            s.close(); return
        nonceG, ct, mac = parts
        # derive session
        info = self.device_id + nonceG
        K_sess = hkdf_derive(K_MASTER, salt=nonceD, info=info, length=32)
        K_enc = K_sess[:16]; K_mac = K_sess[16:]
        aesgcm = AESGCM(K_enc)
        aad = nonceD

        # measure decrypt time
        t_before_dec = time.perf_counter()
        try:
            pt = aesgcm.decrypt(nonceG, ct, aad)
            t_after_dec = time.perf_counter()
            self.metrics['dev_dec_time_ms'] = (t_after_dec - t_before_dec) * 1000
            if not pt.startswith(b'GW_OK'):
                print("[DEV] GW did not say OK")
                s.close(); return
            # verify mac
            expected_mac = hmac_sha256(K_mac, nonceG + GW_ID + nonceD)
            if expected_mac != mac:
                print("[DEV] MAC mismatch (GW -> DEV)")
                s.close(); return
            # prepare final message
            pt2 = b'DEV_OK|' + self.device_id + b'|' + nonceG
            t_bef_enc2 = time.perf_counter()
            ct2 = aesgcm.encrypt(nonceG, pt2, aad)
            t_aft_enc2 = time.perf_counter()
            mac2 = hmac_sha256(K_mac, ct2)
            resp = pack_msg([ct2, mac2])
            self.metrics['dev_enc_time_ms'] = (t_aft_enc2 - t_bef_enc2) * 1000
            self.metrics['dev_msg2_size'] = len(resp)
            s.send(resp)
            self.metrics['round_trip_ms'] = (time.perf_counter() - t_start) * 1000
            print("[DEV] Mutual auth finished")
            # save capture for replay if requested
            if self.do_replay and self.replay_capture is not None:
                self.replay_capture['init'] = init
                self.replay_capture['resp1'] = data
                self.replay_capture['resp2'] = resp
        except Exception as e:
            print("[DEV] decrypt failed:", e)
        s.close()


# Replay test

def run_replay_test():
    metrics = {}
    capture = {}
    gw = Gateway(metrics, port=PORT)
    dev = Device(metrics, device_id=DEVICE_ID, port=PORT, do_replay=True, replay_capture=capture)
    gw.start(); dev.start()
    gw.join(); dev.join()

    print("\n[REPLAY] Captured messages sizes:", {k: v for k, v in metrics.items() if 'size' in k})
    print("[REPLAY] Attempting to replay INIT (Device -> GW) now (should be rejected by timestamp/nonce logic)...")
    # replay captured init after delaying > TTL to simulate replay
    time.sleep(2)
    if 'init' not in capture:
        print("[REPLAY] No capture found; abort")
        return
    # Connect again, send old init
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    try:
        s.send(capture['init'])
        data = s.recv(MSG_BUFFER)
        print("[REPLAY] GW responded to replay (unexpected):", data)
    except Exception as e:
        print("[REPLAY] replay attempt closed or failed (expected):", e)
    s.close()

# Main runner

def run_demo(do_replay=False):
    metrics = {}
    gw = Gateway(metrics, port=PORT)
    dev = Device(metrics, device_id=DEVICE_ID, port=PORT)
    gw.start(); dev.start()
    gw.join(); dev.join()
    # print metrics & sizes
    print("\n--- Metrics & sizes ---")
    for k, v in metrics.items():
        print(f"{k}: {v}")
    print("-----------------------\n")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'replay':
        # For replay test we need a fresh listening gateway. We'll run in same process: start gateway thread that accepts 2 connections.
        # To avoid socket reuse issues, we will run a short gateway instance that accepts one connection; for the replay check we start a second gateway instance.
        # Simpler: run demo then attempt to connect and send captured init to a separate gateway instance.
        # Start a gateway server in background
        print("Starting replay test. First run normal session and capture messages, then attempt replay.")
        # Start a server in a separate thread that will accept connections for both runs
        # For simplicity, reuse the same Gateway implementation twice.
        # Run first capture-run
        metrics = {}
        capture = {}
        gw1 = Gateway(metrics, port=PORT)
        gw1.start()
        dev1 = Device(metrics, device_id=DEVICE_ID, port=PORT, do_replay=True, replay_capture=capture)
        dev1.start()
        gw1.join(); dev1.join()
        print("\nCaptured init length:", len(capture.get('init', b'')))
        # Now start a fresh Gateway and replay captured init
        print("Starting fresh gateway to test replay...")
        gw2 = Gateway({}, port=PORT)
        gw2.start()
        # small delay
        time.sleep(0.2)
        if 'init' in capture:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            s.send(capture['init'])
            try:
                rsp = s.recv(MSG_BUFFER)
                print("[REPLAY] Received response to replayed init (unexpected):", rsp)
            except Exception as e:
                print("[REPLAY] Nothing received (likely closed):", e)
            s.close()
        gw2.join()
    else:
        run_demo()