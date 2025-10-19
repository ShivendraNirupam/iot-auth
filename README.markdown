# IoT Authentication System for Cloud-Edge Environments

This repository contains a lightweight authentication system designed for Internet of Things (IoT) devices operating in cloud-edge environments. The implementation, written in Python, facilitates secure mutual authentication between IoT devices and an edge gateway using cryptographic techniques. It is optimized for resource-constrained devices, making it suitable for real-world IoT deployments.

## Overview

The `iot-auth.py` script implements a protocol that ensures secure communication between an IoT device and a gateway. Key features include:

- **Mutual Authentication**: Both the device and gateway verify each other's identity.
- **Cryptographic Security**: Utilizes HMAC-SHA256 for message integrity, AES-GCM for encryption, and HKDF for secure key derivation.
- **Replay Protection**: Incorporates a timestamp-based mechanism with a 60-second TTL to prevent replay attacks.
- **Lightweight Design**: Minimizes computational overhead and message sizes for efficiency.

The system uses a TCP-based communication model over localhost (`127.0.0.1:55000`) and includes a demo mode to test normal authentication and a replay test mode to verify security against replay attacks.

## Prerequisites

- **Python 3.13**: Ensure Python is installed.
- **Cryptography Library**: Install the required dependency:
  ```bash
  pip install cryptography
  ```
- **Operating System**: Tested on Windows (PowerShell), but compatible with Linux/macOS with adjustments.

## Installation

1. Clone this repository or copy `iot-auth.py` to your working directory (e.g., `C:\Users\user-name\OneDrive\Desktop\My Files\auth-system\`).
2. Navigate to the directory in your terminal:
   ```bash
   cd C:\Users\user-name\OneDrive\Desktop\My Files\auth-system
   ```
3. Activate your virtual environment (if using one):
   ```bash
   .\venv\Scripts\activate
   ```
4. Install the cryptography library:
   ```bash
   pip install cryptography
   ```

## Usage

### Running the Normal Authentication Test

To test the basic authentication process:

```bash
python .\iot-auth.py
```

This starts a gateway thread and a device thread, performing mutual authentication. The output includes logs and performance metrics.

### Running the Replay Attack Test

To test the system's replay protection:

```bash
python .\iot-auth.py replay
```

This first runs a normal authentication to capture messages, then attempts to replay the device's initial message to a new gateway instance. The gateway should reject the replayed message due to the timestamp TTL.

## Implementation Details

The code is structured into two main classes:

- **Gateway**: Listens for device connections, verifies authentication messages, and computes responses using AES-GCM and HMAC-SHA256.
- **Device**: Initiates the authentication process, sends initial messages, and verifies gateway responses.

Key functions include:
- `hkdf_derive`: Derives a session key using HKDF with SHA256.
- `pack_msg` and `unpack_msg`: Handle variable-length message packing/unpacking with length prefixes.
- Timestamp checks: Ensure messages are within a 60-second TTL to prevent replay attacks.

The system uses a hardcoded 256-bit master key (`K_MASTER`) for simplicity, though in production, this should be securely provisioned.

## Output Example

Below is a sample output from running `python .\iot-auth.py` on October 19, 2025, at 11:21 PM IST:

```
[GW] Listening on 127.0.0.1:55000
[GW] Connected
[GW] INIT from b'DEV01' nonceD 8f32db229f500d88983eb408 ts 1760896254
[GW] Mutual auth OK with device b'DEV01'
[DEV] Mutual auth finished

--- Metrics & sizes ---
dev_msg1_size: 27
gw_enc_time_ms: 0.0
gw_msg1_size: 76
dev_dec_time_ms: 0.0
dev_enc_time_ms: 0.0
dev_msg2_size: 77
round_trip_ms: 2.234935760498047
gw_msg2_size: 77
-----------------------
```

### Explanation of Output
- **[GW] Listening on 127.0.0.1:55000**: The gateway is ready to accept connections.
- **[GW] Connected**: The device establishes a connection.
- **[GW] INIT from b'DEV01' nonceD ... ts 1760896254**: The gateway receives the device's initial message (ID: `DEV01`, nonce, timestamp: October 19, 2025, 11:24:14 UTC).
- **[GW] Mutual auth OK with device b'DEV01'**: The gateway confirms successful authentication.
- **[DEV] Mutual auth finished**: The device completes its verification.
- **Metrics**:
  - `dev_msg1_size: 27 bytes`: Size of the initial device message.
  - `gw_msg1_size: 76 bytes`: Size of the gateway's response.
  - `dev_msg2_size/gw_msg2_size: 77 bytes`: Size of the device's final message.
  - `round_trip_ms: 2.234935760498047 ms`: Total authentication time.
  - `gw_enc_time_ms`, `dev_dec_time_ms`, `dev_enc_time_ms: 0.0 ms`: Encryption/decryption times (likely inaccurate due to low-resolution timing; see Improvements).



## Performance Metrics
- **Round-Trip Latency**: ~2.23 ms (local test, highly efficient).
- **Message Sizes**: 27–77 bytes (compact for IoT networks).
- **Encryption/Decryption Times**: Reported as 0.0 ms (to be refined with higher-resolution timing).

## Improvements
- **Timing Accuracy**: The current implementation uses `time.time()`, which has low resolution on some systems, resulting in 0.0 ms for encryption/decryption times. Update to `time.perf_counter()` for precise measurements.
  - Example change in `Gateway.run`:
    ```python
    t_before_enc = time.perf_counter()
    ct = aesgcm.encrypt(nonceG, plaintext, aad)
    t_after_enc = time.perf_counter()
    self.metrics['gw_enc_time_ms'] = (t_after_enc - t_before_enc) * 1000
    ```
- **Secure Key Management**: Replace the hardcoded `K_MASTER` with a secure provisioning mechanism.
- **Multi-Device Support**: Enhance the gateway to handle multiple concurrent connections.

## Contributing
Feel free to fork this repository, submit issues, or propose enhancements. Contributions to improve scalability, security, or documentation are welcome.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.