# Dual-Layer Secure Covert Communication System

> RSA + AES Dual Encryption • Diffie-Hellman Key Exchange • LSB Steganography • Chunked TCP Transfer • SHA-256 Integrity • Live Frontend Visualizer

---

## Table of Contents

- [Project Overview](#project-overview)
- [Final Architecture](#final-architecture)
- [Tech Stack](#tech-stack)
- [File Structure](#file-structure)
- [Phase 0 — Environment Setup](#phase-0--environment-setup)
- [Phase 1 — Crypto Utilities](#phase-1--crypto-utilities)
- [Phase 2 — LSB Steganography](#phase-2--lsb-steganography)
- [Phase 3 — Prepare & Extract Scripts](#phase-3--prepare--extract-scripts)
- [Phase 4 — C Socket Programs](#phase-4--c-socket-programs)
- [Phase 5 — Flask API Middleware](#phase-5--flask-api-middleware)
- [Phase 6 — Frontend UI](#phase-6--frontend-ui)
- [Phase 7 — Full System Run](#phase-7--full-system-run)
- [Phase 8 — Dual Frontend UX Plan](#phase-8--dual-frontend-ux-plan)
- [Protocol Specification](#protocol-specification)
- [Troubleshooting](#troubleshooting)

---

## Project Overview

A secure covert communication system built in two layers:

- **Transport Layer (C)** — Raw POSIX TCP sockets with Diffie-Hellman key exchange, RSA public key exchange, and chunked image transfer using a custom binary protocol
- **Security Layer (Python)** — Dual encryption (RSA + AES-256), LSB image steganography, and SHA-256 integrity verification
- **Presentation Layer (HTML + Flask)** — Live frontend visualizer showing encryption steps, pixel-level steganography diff, socket transfer progress, and hash verification

---

## Final Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SENDER MACHINE                                 │
│                                                                         │
│   ┌─────────────┐    ┌──────────────┐    ┌────────────────────────┐   │
│   │  Frontend   │───▶│  Flask API   │───▶│      prepare.py        │   │
│   │  (HTML/JS)  │    │   (app.py)   │    │  - DH shared secret    │   │
│   └─────────────┘    └──────┬───────┘    │  - RSA encrypt         │   │
│                             │            │  - AES encrypt         │   │
│                             ▼            │  - LSB embed           │   │
│                      ┌──────────────┐    │  - SHA-256 hash        │   │
│                      │  sender.c    │    └────────────────────────┘   │
│                      │  TCP Client  │                                  │
│                      │  - DH exch   │                                  │
│                      │  - RSA exch  │                                  │
│                      │  - Chunked   │                                  │
│                      │    send      │                                  │
│                      └──────┬───────┘                                  │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
                   TCP Socket │ localhost:8080
                              │
                    ┌─────────┴──────────────────────────────────────────┐
                    │  CUSTOM PACKET HEADER (per chunk)                  │
                    │  [ magic(4) | version(1) | type(1) |               │
                    │    chunk_id(4) | total_chunks(4) |                 │
                    │    payload_size(4) | checksum(1) ]                 │
                    └─────────┬──────────────────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────────────────┐
│                          RECEIVER MACHINE                               │
│                             │                                           │
│                      ┌──────▼───────┐                                  │
│                      │  receiver.c  │                                  │
│                      │  TCP Server  │                                  │
│                      │  - DH exch   │                                  │
│                      │  - RSA exch  │                                  │
│                      │  - Chunked   │                                  │
│                      │    recv      │                                  │
│                      └──────┬───────┘                                  │
│                             │                                           │
│                             ▼                                           │
│                    ┌─────────────────────┐                             │
│                    │     extract.py      │                             │
│                    │  - SHA-256 verify   │                             │
│                    │  - LSB extract      │                             │
│                    │  - AES decrypt      │                             │
│                    │  - RSA decrypt      │                             │
│                    │  - Print message    │                             │
│                    └─────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Communication Flow

```
Step 0   Receiver starts, listens on port 8080
Step 1   Sender connects
Step 2   DH Key Exchange over socket
           Receiver sends DH public value (y_R)
           Sender sends DH public value (y_S)
           Both derive shared AES-256 key via HKDF
Step 3   RSA Key Exchange over socket
           Receiver generates RSA keypair
           Receiver sends public.pem over socket
           Sender stores it for encryption
Step 4   prepare.py runs on sender side
           Message encrypted with RSA public key
           RSA ciphertext encrypted again with AES (shared secret)
           Final ciphertext embedded in image via LSB
           SHA-256 hash of stego image computed
Step 5   Chunked Transfer over socket
           Sender splits stego.png into 4KB chunks
           Each chunk sent with custom protocol header
           Receiver reassembles and saves stego.png
           Sender sends hash.txt
Step 6   extract.py runs on receiver side
           SHA-256 hash verified
           LSB extraction of ciphertext
           AES decrypt → RSA decrypt → plaintext
           Message displayed
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Transport | C, POSIX Sockets (`sys/socket.h`) | TCP client & server |
| Key Exchange | C + Python (`cryptography`) | DH + RSA over socket |
| Encryption | Python (`cryptography`) | RSA-2048 + AES-256-CBC |
| Steganography | Python (`Pillow`) | LSB embed & extract |
| Integrity | Python (`hashlib`) | SHA-256 |
| API | Python (`Flask`) | Bridge frontend to backend |
| Frontend | HTML + CSS + JavaScript | Live visualizer UI |
| Build | Makefile | Compile C programs |

---

## File Structure

```
project/
│
├── sender.c                  # TCP socket client (DH + RSA exchange + chunked send)
├── receiver.c                # TCP socket server (DH + RSA exchange + chunked recv)
├── dh_helper.py              # Called by C programs to handle DH/RSA key operations
├── Makefile                  # Compiles sender.c and receiver.c
│
├── crypto_utils.py           # RSA, AES, DH, SHA-256 utilities
├── steg.py                   # LSB steganography (embed + extract + diff data)
├── prepare.py                # Sender pre-processing pipeline
├── extract.py                # Receiver post-processing pipeline
├── app.py                    # Flask API middleware
│
├── frontend/
│   ├── index.html            # Main UI
│   ├── style.css             # Styles
│   └── script.js             # API calls, animations, visualizations
│
├── keys/
│   ├── public.pem            # RSA public key (generated at runtime via DH exchange)
│   └── private.pem           # RSA private key (generated at runtime)
│
├── images/
│   └── cover.png             # Cover image for steganography
│
├── output/
│   ├── stego.png             # Generated stego image (sender side)
│   └── hash.txt              # SHA-256 hash of stego image
│
├── received/
│   ├── stego.png             # Received stego image (receiver side)
│   └── hash.txt              # Received hash for verification
│
└── dh_state/
    ├── receiver_dh_pub.txt   # Receiver DH public value (integer as string)
    ├── sender_dh_pub.txt     # Sender DH public value (integer as string)
    ├── receiver_dh_priv.bin  # Serialized receiver DH private key
    ├── sender_dh_priv.bin    # Serialized sender DH private key
    └── aes_key.bin           # Derived AES-256 key (32 raw bytes)
```

---

## Phase 0 — Environment Setup

### Install system dependencies

```bash
sudo apt update && sudo apt install gcc make python3 python3-pip -y
```

### Create project directories

```bash
mkdir -p keys images output received dh_state frontend
```

### Install Python dependencies

```bash
pip install cryptography Pillow Flask flask-cors
```

### Add a cover image

```bash
# Copy any PNG image you have
cp /path/to/any/image.png images/cover.png
```

### Verify everything is installed

```bash
gcc --version
python3 --version
python3 -c "from cryptography.hazmat.primitives.asymmetric import rsa, dh; from PIL import Image; import flask; print('All deps OK')"
```

**Expected:**
```
gcc (Ubuntu ...) x.x.x
Python 3.x.x
All deps OK
```

---

## Phase 1 — Crypto Utilities

**File:** `crypto_utils.py`

**What it does:**
- RSA-2048 key generation, encryption, decryption (OAEP padding)
- Diffie-Hellman using RFC 3526 2048-bit MODP Group — same hardcoded params on both sides
- HKDF to derive AES-256 key from DH shared secret
- AES-256-CBC encryption and decryption
- Dual encryption: RSA encrypt first, then AES wraps it — returns all intermediate values for frontend
- SHA-256 for files and raw bytes
- Key serialization and PEM file helpers

### Claude Code Prompt

```
Create a file called crypto_utils.py with the following:

1. RSA-2048 key generation using the `cryptography` library with OAEP padding for
   encrypt/decrypt. Include functions: generate_rsa_keypair(), serialize_private_key(),
   serialize_public_key(), load_private_key(), load_public_key(), rsa_encrypt(),
   rsa_decrypt(), save_keys(), load_keys()

2. Diffie-Hellman key exchange using the standard RFC 3526 2048-bit MODP Group
   (hardcode the prime and generator=2 so both sides use the same params without
   negotiation). Functions: generate_dh_private_key(), get_dh_public_value(),
   compute_dh_shared_secret() — the last one derives a 32-byte AES-256 key from
   the raw DH shared secret using HKDF-SHA256

3. AES-256-CBC encryption and decryption. Prepend IV to ciphertext. Use PKCS7
   padding manually. Functions: aes_encrypt(aes_key, plaintext_bytes),
   aes_decrypt(aes_key, iv_and_ciphertext)

4. Dual encryption: dual_encrypt(message_str, rsa_public_key, aes_key) that first
   RSA-encrypts the message then AES-encrypts the RSA ciphertext. Return a dict with
   keys: original, rsa_ciphertext_b64, aes_ciphertext_b64, aes_ciphertext_bytes.
   Also dual_decrypt(aes_ciphertext_bytes, rsa_private_key, aes_key) to reverse it.

5. sha256_file(filepath) and sha256_bytes(data) using hashlib

6. A self-test block under if __name__ == "__main__" that tests all of the above
   and prints a clear pass/fail for each step

Use the cryptography library (not rsa or pycryptodome).
```

### Test

```bash
python3 crypto_utils.py
```

**Expected:**
```
[1] RSA Key Generation...        ✅ RSA keygen OK
[2] Diffie-Hellman Key Exchange  ✅ DH shared secret match confirmed
[3] AES-256-CBC...               ✅ AES encrypt/decrypt OK
[4] Dual Encryption...           ✅ Dual encryption/decryption OK
[5] SHA-256...                   ✅ SHA-256 OK
All tests passed! ✅
```

---

## Phase 2 — LSB Steganography

**File:** `steg.py`

**What it does:**
- Embeds arbitrary bytes into PNG by modifying the LSB of each R, G, B channel per pixel
- Prepends a 4-byte length header so extraction knows exactly how many bytes to read
- Extracts hidden bytes back out from a stego image
- Returns pixel diff data for the frontend visualizer (before/after binary strings per channel)
- Reports image capacity

### Claude Code Prompt

```
Create a file called steg.py with the following:

1. embed(image_path, data_bytes, output_path) — embeds data_bytes into the image
   using LSB steganography. Modify only the least significant bit of each R, G, B
   channel of each pixel (do not touch the alpha channel). Prepend a 4-byte
   big-endian integer header indicating the length of data_bytes so extraction knows
   when to stop. Save result to output_path as PNG. Raise a clear error if the image
   is too small to hold the data.

2. extract(image_path) — extracts and returns the hidden bytes from a stego image.
   Read the 4-byte length header first, then extract exactly that many bytes.

3. get_pixel_diff(original_path, stego_path, sample_count=8) — returns a list of
   dicts for sample_count pixels that were actually modified. Each dict contains:
   pixel_index, channel ("R"/"G"/"B"), original_bits (8-char binary string),
   stego_bits (8-char binary string), original_value (int), stego_value (int).
   This is used by the frontend to visualize LSB changes.

4. get_capacity(image_path) — returns max bytes that can be hidden in the image

5. A self-test under if __name__ == "__main__" that loads images/cover.png, embeds
   a test message, extracts it, verifies it matches, and prints the pixel diff for
   4 sample pixels

Use Pillow (PIL) only. Do not use any steganography libraries.
```

### Test

```bash
python3 steg.py
```

**Expected:**
```
[1] Capacity check...  ✅ Can hold XXXXX bytes
[2] Embed...           ✅ Embedded 42 bytes into output/stego_test.png
[3] Extract...         ✅ Extracted: "Test message for LSB steganography!"
[4] Pixel diff:
    Pixel 0  R: 11001010 → 11001011  (202 → 203)
    Pixel 0  G: 10110100 → 10110100  (180 → 180)
    ...
All tests passed! ✅
```

---

## Phase 3 — Prepare & Extract Scripts

**Files:** `prepare.py`, `extract.py`

### prepare.py — Sender Pre-processing

Orchestrates the full sender pipeline:
1. Reads message from `--message` CLI arg
2. Loads RSA public key from `keys/public.pem`
3. Loads AES key from `dh_state/aes_key.bin`
4. Dual encrypts the message (RSA then AES)
5. Embeds ciphertext into `images/cover.png` via LSB
6. Saves stego image to `output/stego.png`
7. Computes SHA-256 hash and saves to `output/hash.txt`
8. Prints a JSON result to stdout for Flask to read

### extract.py — Receiver Post-processing

Orchestrates the full receiver pipeline:
1. Loads `received/stego.png` and `received/hash.txt`
2. Recomputes SHA-256 and compares
3. Extracts ciphertext bytes via LSB
4. Loads AES key from `dh_state/aes_key.bin`
5. Loads RSA private key from `keys/private.pem`
6. Dual decrypts to recover plaintext
7. Prints a JSON result to stdout for Flask to read

### Claude Code Prompt

```
Create two files: prepare.py and extract.py. Both import from crypto_utils.py
and steg.py.

prepare.py:
- Accept a --message CLI argument
- Load RSA public key from keys/public.pem
- Load AES key (32 raw bytes) from dh_state/aes_key.bin
- Call dual_encrypt() from crypto_utils
- Call embed() from steg to hide aes_ciphertext_bytes into images/cover.png,
  save to output/stego.png
- Compute SHA-256 of output/stego.png and save hex to output/hash.txt
- Print a single JSON object to stdout with keys: status, original_message,
  rsa_ciphertext_b64, aes_ciphertext_b64, sha256_hash, stego_image_path,
  pixel_diff (call get_pixel_diff() with sample_count=8)
- On any error print JSON with status: "error" and a message key

extract.py:
- Load received/stego.png and received/hash.txt
- Recompute SHA-256 of received/stego.png
- If hash mismatch print JSON with status: "tampered" and exit
- Call extract() from steg to get ciphertext bytes
- Load AES key from dh_state/aes_key.bin
- Load RSA private key from keys/private.pem
- Call dual_decrypt() from crypto_utils
- Print a single JSON object with keys: status, hash_verified (bool),
  decrypted_message, sha256_expected, sha256_actual
- On any error print JSON with status: "error" and a message key
```

### Test

```bash
# Generate keys and dummy AES key for isolated testing
python3 -c "
from crypto_utils import generate_rsa_keypair, save_keys
import os
os.makedirs('keys', exist_ok=True)
os.makedirs('dh_state', exist_ok=True)
priv, pub = generate_rsa_keypair()
save_keys(priv, pub)
open('dh_state/aes_key.bin','wb').write(os.urandom(32))
print('Keys ready')
"

python3 prepare.py --message "Hello this is secret"

cp output/stego.png received/stego.png
cp output/hash.txt received/hash.txt

python3 extract.py
```

**Expected:**
```json
{"status": "success", "hash_verified": true, "decrypted_message": "Hello this is secret", ...}
```

---

## Phase 4 — C Socket Programs

**Files:** `sender.c`, `receiver.c`, `dh_helper.py`, `Makefile`

### Why dh_helper.py?

The DH math (2048-bit modular exponentiation) is handled in Python via `dh_helper.py`. The C programs call it using `popen()` / `system()`. This keeps the C code clean and focused purely on socket programming — which is the point of the subject.

### Custom Protocol Header (19 bytes)

```c
typedef struct {
    uint32_t magic;         // 0xDEADBEEF — protocol identifier
    uint8_t  version;       // 0x01
    uint8_t  msg_type;      // 0x00=DH_KEY  0x01=RSA_PUBKEY
                            // 0x02=IMAGE_CHUNK  0x03=HASH_FILE  0x04=ACK
    uint32_t chunk_id;      // chunk sequence number (0-indexed)
    uint32_t total_chunks;  // total chunks for this transfer
    uint32_t payload_size;  // bytes of payload after this header
    uint8_t  checksum;      // XOR of all header bytes except this field
} PacketHeader;             // 19 bytes total
```

### Chunked Transfer

Image is split into **4096-byte chunks**. Each chunk is sent as a separate packet. The receiver reassembles them in order using `chunk_id`.

### Claude Code Prompt

```
Create sender.c, receiver.c, dh_helper.py, and a Makefile.

PacketHeader struct (all multi-byte fields in network byte order / big-endian):
  uint32_t magic (0xDEADBEEF), uint8_t version (0x01), uint8_t msg_type,
  uint32_t chunk_id, uint32_t total_chunks, uint32_t payload_size, uint8_t checksum
msg_type: 0x00=DH_KEY, 0x01=RSA_PUBKEY, 0x02=IMAGE_CHUNK, 0x03=HASH_FILE, 0x04=ACK
checksum = XOR of bytes 0 through 17 of the packed header.
Use htonl/ntohl for uint32_t fields.

receiver.c (TCP server, port 8080):
1. socket(), bind(), listen(), accept() — print each step
2. Call system("python3 dh_helper.py gen_receiver") to generate DH values
3. Read receiver DH public value from dh_state/receiver_dh_pub.txt
4. Send it as DH_KEY packet (chunk_id=0, total_chunks=1, payload = ascii digits of the number)
5. Receive sender's DH_KEY packet, write payload to dh_state/sender_dh_pub.txt
6. Call system("python3 dh_helper.py compute_receiver") to derive AES key
7. Call system("python3 dh_helper.py gen_rsa") to generate RSA keypair
8. Read keys/public.pem, send as RSA_PUBKEY packet
9. Receive IMAGE_CHUNK packets in a loop until chunk_id == total_chunks-1.
   Write each payload to a buffer, reassemble to received/stego.png when done.
   Print "[receiver] Chunk X/Y received (N bytes)" for each chunk.
10. Receive HASH_FILE packet, save payload to received/hash.txt
11. Send ACK packet
12. Record start/end time, print: total bytes, elapsed seconds, KB/s
13. Call system("python3 extract.py") and print its stdout output

sender.c (TCP client, usage: ./sender "message here"):
1. socket(), connect() to 127.0.0.1:8080 — print each step
2. Receive DH_KEY packet from receiver, write payload to dh_state/receiver_dh_pub.txt
3. Call system("python3 dh_helper.py gen_sender") to generate DH values + derive AES key
4. Read sender DH public value from dh_state/sender_dh_pub.txt, send as DH_KEY packet
5. Receive RSA_PUBKEY packet, write payload to keys/public.pem
6. Build command "python3 prepare.py --message \"<argv[1]>\"", run with popen(),
   print each line of output as it comes
7. Read output/stego.png into a buffer
8. Split into 4096-byte chunks, send each as IMAGE_CHUNK packet with correct
   chunk_id (0-indexed) and total_chunks. Print "[sender] Chunk X/Y (N bytes)"
9. Read output/hash.txt, send as HASH_FILE packet
10. Wait for ACK packet
11. Record start/end time, print: total bytes, elapsed seconds, KB/s

dh_helper.py (called by C programs, takes one CLI arg):
- gen_receiver: generate DH private key, save serialized to dh_state/receiver_dh_priv.bin,
  save public value integer as string to dh_state/receiver_dh_pub.txt
- gen_sender: generate DH private key, save to dh_state/sender_dh_priv.bin,
  save public value to dh_state/sender_dh_pub.txt, then immediately call compute_sender logic
- compute_receiver: load dh_state/receiver_dh_priv.bin + read dh_state/sender_dh_pub.txt,
  compute shared secret, save 32-byte AES key to dh_state/aes_key.bin
- compute_sender: load dh_state/sender_dh_priv.bin + read dh_state/receiver_dh_pub.txt,
  compute shared secret, save 32-byte AES key to dh_state/aes_key.bin
- gen_rsa: generate RSA keypair and save to keys/private.pem and keys/public.pem
Import from crypto_utils.py for all crypto operations.

Makefile: compile sender.c and receiver.c with gcc -Wall, add a clean target.
Use only POSIX headers: sys/socket.h, netinet/in.h, arpa/inet.h, unistd.h,
stdio.h, stdlib.h, string.h, stdint.h, time.h.
```

### Test

```bash
make

# Terminal 1
./receiver

# Terminal 2
./sender "This is my secret message"
```

**Expected (Receiver):**
```
[receiver] Listening on port 8080...
[receiver] Connection accepted from 127.0.0.1
[receiver] DH exchange complete
[receiver] RSA keypair generated, public key sent
[receiver] Chunk 1/12 received (4096 bytes)
...
[receiver] Transfer complete — 49152 bytes in 0.03s (1638 KB/s)
[receiver] Hash verified ✅  Message: "This is my secret message"
```

**Expected (Sender):**
```
[sender] Connected to 127.0.0.1:8080
[sender] DH exchange complete. AES key derived.
[sender] RSA public key received and saved
[sender] Running prepare.py...
[sender] Sending chunk 1/12...
...
[sender] ACK received. Transfer complete.
[sender] 49152 bytes sent in 0.03s (1638 KB/s)
```

---

## Phase 5 — Flask API Middleware

**File:** `app.py`

**What it does:** Bridges the frontend to the C and Python backend via HTTP. Manages pipeline state and streams live socket logs to the frontend via Server-Sent Events (SSE).

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/send` | Trigger pipeline: saves image, runs `./sender` |
| `GET` | `/api/status` | Returns pipeline status + socket log + chunk progress |
| `GET` | `/api/result` | Returns decrypted message, hash result, pixel diff, ciphertext steps |
| `GET` | `/api/stego-image` | Returns stego image as base64 |
| `GET` | `/api/original-image` | Returns cover image as base64 |
| `GET` | `/api/stream` | SSE — streams live socket log lines as they appear |

### Claude Code Prompt

```
Create app.py as a Flask API server with CORS enabled on all routes.

Use a global dict called state to track: pipeline_status ("idle"/"running"/
"complete"/"error"), socket_log (list of strings), prepare_result (dict),
chunks_sent (int), total_chunks (int).

Endpoints:

POST /api/send — accepts JSON {message: string, image_base64: string (optional)}
  - If image_base64 provided, decode and save to images/cover.png
  - Set pipeline_status to "running", clear socket_log
  - In a background thread: run ./sender "{message}" as subprocess,
    capture stdout line by line, append each line to socket_log,
    parse "Chunk X/Y" lines to update chunks_sent/total_chunks,
    set pipeline_status to "complete" when done or "error" on failure
  - Return immediately: {status: "started"}

GET /api/status
  - Return: {pipeline_status, socket_log, progress: {chunks_sent, total_chunks}}

GET /api/result
  - Run python3 extract.py as subprocess, parse its JSON stdout
  - Also include prepare_result fields: rsa_ciphertext_b64, aes_ciphertext_b64,
    pixel_diff, sha256_hash
  - Return combined JSON

GET /api/stego-image
  - Read output/stego.png, base64 encode, return {image_base64: "..."}

GET /api/original-image
  - Read images/cover.png, base64 encode, return {image_base64: "..."}

GET /api/stream
  - Server-Sent Events endpoint. Use a generator that yields new socket_log
    lines as they appear (poll every 200ms). Format: "data: <line>\n\n"
  - Return with mimetype text/event-stream and Cache-Control no-cache

Run on host 0.0.0.0 port 5000, debug=True.
```

### Test

```bash
python3 app.py

# In another terminal (receiver must also be running)
curl -X POST http://localhost:5000/api/send \
  -H "Content-Type: application/json" \
  -d '{"message": "test message"}'

curl http://localhost:5000/api/status
curl http://localhost:5000/api/result
```

---

## Phase 6 — Frontend UI

**Files:** `frontend/index.html`, `frontend/style.css`, `frontend/script.js`

### Layout

```
┌──────────────────────────────────────────────────────────────┐
│            SECURE COVERT COMMS  —  HEADER                    │
│     DH Key Exchange • RSA-2048 • AES-256 • LSB • SHA-256     │
├───────────────────────────┬──────────────────────────────────┤
│      SENDER PANEL         │       RECEIVER PANEL             │
│  [ Message textarea  ]    │  [ Stego image display ]         │
│  [ Image upload+prev ]    │  [ SHA-256 hash row    ]         │
│  [ TRANSMIT button   ]    │  [ ✅ HASH VERIFIED    ]         │
│                           │  [ Decrypted message   ]         │
├───────────────────────────┴──────────────────────────────────┤
│               ENCRYPTION VISUALIZER                          │
│  PLAINTEXT  ──▶  RSA CIPHERTEXT  ──▶  AES CIPHERTEXT        │
│  (animate each box lighting up in sequence)                  │
├──────────────────────────────────────────────────────────────┤
│               STEGANOGRAPHY VISUALIZER                       │
│  [ Original Image ]  vs  [ Stego Image ]  (side by side)    │
│  [ Pixel bit grid — 8 rows showing LSB changes ]            │
├──────────────────────────────────────────────────────────────┤
│               SOCKET LIVE FEED                               │
│  [ Terminal dark box — green text — scrolling log ]          │
│  [ Progress bar: Chunk 7/12  ██████░░░░  58%      ]         │
│  [ Stats: 49152 bytes · 1638 KB/s · 0.03s         ]         │
└──────────────────────────────────────────────────────────────┘
```

### Claude Code Prompt

```
Create frontend/index.html, frontend/style.css, and frontend/script.js.
All in one page, dark security-tool theme, vanilla JS only (no frameworks).

Color scheme: background #0a0a0a, primary text #e0e0e0, accent green #00ff88,
error red #ff4444, panel bg #111111, border #222222. Monospace font for
terminal/crypto sections (use 'Courier New' or 'monospace').

Sections:

1. HEADER
   - Title "SECURE COVERT COMMS" in large green text
   - Subtitle: "Diffie-Hellman • RSA-2048 • AES-256-CBC • LSB Steganography • SHA-256"

2. SENDER / RECEIVER PANELS (CSS grid, side by side)
   Sender panel:
   - Textarea for secret message (placeholder: "Enter your secret message...")
   - File input for cover image with inline preview (show thumbnail)
   - "TRANSMIT" button — on click POST to /api/send with message and image_base64,
     then start EventSource on /api/stream, then poll /api/result every 2s until complete
   Receiver panel:
   - Initially shows placeholder "Awaiting transmission..."
   - After transfer: show received stego image (from /api/stego-image)
   - SHA-256 section: two rows showing "Expected: <hash>" and "Actual: <hash>"
     with a green ✅ VERIFIED or red ❌ TAMPERED badge
   - Decrypted message box with typewriter character-by-character reveal animation

3. ENCRYPTION VISUALIZER
   - Three boxes in a row connected by "▶" arrows
   - Box 1 "PLAINTEXT" — shows original message
   - Box 2 "RSA ENCRYPTED" — shows truncated base64 of RSA ciphertext
   - Box 3 "AES ENCRYPTED" — shows truncated base64 of AES ciphertext
   - Each box has a "COPY" button for the full value
   - Boxes start dimmed, light up in sequence (300ms delay between each)
     when encryption results arrive from /api/result

4. STEGANOGRAPHY VISUALIZER
   - Two canvas elements side by side: "ORIGINAL" and "STEGO"
   - On load fetch /api/original-image and draw to original canvas
   - After transfer fetch /api/stego-image and draw to stego canvas
   - Below canvases: a table with columns: Pixel # | Channel | Original bits | Stego bits | Change
     Populate from pixel_diff in /api/result response.
     Highlight the last bit (LSB) of each binary string in a different color (green if changed).
   - Caption: "LSB steganography changes pixel values by ±1 — visually identical to human eye"

5. SOCKET LIVE FEED
   - Dark terminal box (#000 background, #00ff88 text, monospace)
   - Connect to /api/stream via EventSource on page load, append each line as a new div
   - Auto-scroll to bottom as new lines arrive
   - Progress bar below terminal: reads chunks_sent/total_chunks from /api/status
     (poll every 500ms while running), updates a CSS width percentage bar
   - Stats row below bar: "X bytes transferred · Y KB/s · Z seconds"
     Parse these values from the socket_log lines

All sections start dimmed (opacity 0.3) and transition to full opacity when they
receive data. Use CSS transitions (0.5s ease) for all state changes.
On page load, fetch /api/original-image to populate the original canvas.
```

### Test

```bash
# Make sure receiver.c is running and Flask is running
./receiver &
python3 app.py &

cd frontend && python3 -m http.server 3000
# Open http://localhost:3000
```

---

## Phase 7 — Full System Run

Open **2 terminals** and a **browser.**

**Terminal 1 — Start the receiver:**
```bash
./receiver
```

**Terminal 2 — Start Flask:**
```bash
python3 app.py
```

**Terminal 3 (optional) — Serve frontend:**
```bash
cd frontend && python3 -m http.server 3000
```

**Browser:** open `http://localhost:3000`

**Steps in the UI:**
1. Type a secret message in the sender panel
2. Optionally upload a cover image
3. Click **TRANSMIT**
4. Watch the socket live feed: DH handshake → RSA key exchange → chunks transferring
5. Watch the encryption visualizer animate: plaintext → RSA cipher → AES cipher
6. Watch the steganography visualizer: original vs stego image + pixel bit grid
7. Watch the receiver panel: hash verified ✅ + decrypted message typewriter reveal

---

## Phase 8 — Dual Frontend UX Plan

This phase is a **planning-only phase**. No core backend logic changes are required in this step.
The goal is to deliver a high-quality demo experience with **two polished frontends**:
- Sender Dashboard (control + encryption flow)
- Receiver Dashboard (live receive + verify + decrypt)

### Goals

1. Add richer transfer progress phases in UI:
   - Handshake → Encrypt → Embed → Transfer → Verify → Decrypt
2. Show live transfer ETA and speed chart instead of only final speed text.
3. Add pixel-diff mode toggle:
   - Sample view (existing table)
   - Full summary view (total changed channels/pixels, max delta, mean delta)
4. Add a before/after image slider for Cover vs Stego comparison.
5. Add export actions:
   - Download stego image
   - Export full run report as JSON
6. Add a separate receiver-only frontend page to open in another browser window for teaching/demo.
7. Add chunk-by-chunk image arrival visualization in the receiver view.
8. Keep sender and receiver views synchronized from the same backend state.

### Scope and Deliverables

#### Deliverable A: Progress Timeline + Transfer Telemetry

- Add a horizontal phase timeline with six states: pending, active, complete, error.
- Parse logs/status to move phase state in real-time.
- Add rolling transfer speed chart (last N samples, e.g., 60 points).
- Show ETA derived from:
  - bytes_sent / elapsed_time = throughput
  - remaining_bytes / throughput = ETA

#### Deliverable B: Receiver Chunk-by-Chunk Visual Arrival

- Show incoming chunk progression in receiver dashboard in real time.
- Render a chunk heatmap/grid for total_chunks where each block changes state:
  - pending
  - received
  - error/retry (if implemented later)
- Add a progressive image reveal mode so stego preview appears as transfer advances.
- Show receiver-side counters clearly:
  - current_chunk / total_chunks
  - received_bytes / total_bytes
  - live throughput and ETA

#### Deliverable C: Pixel-Diff Modes

- Keep existing sample table as default for readability.
- Add mode toggle buttons:
  - Sample
  - Full Summary
- Full Summary should display:
  - changed_channels
  - total_channels
  - changed_pixels
  - total_pixels
  - max_delta (expected to stay 1 for LSB)
  - mean_delta
- Compute summary in backend endpoint to avoid heavy client-side image loops.

#### Deliverable D: Before/After Slider

- Replace or complement side-by-side canvases with an overlay slider component.
- Base layer: original cover image.
- Top layer: stego image with adjustable reveal handle.
- Keep side-by-side mode as fallback for small screens.

#### Deliverable E: Export Tools

- Add button: Download Stego PNG.
- Add button: Export Report JSON.
- Report JSON fields:
  - timestamp
  - original_message (or masked version if desired)
  - sha256_expected
  - sha256_actual
  - hash_verified
  - chunks_sent
  - total_chunks
  - elapsed_seconds
  - kb_per_second
  - changed_channels
  - changed_pixels

#### Deliverable F: Receiver-Only Frontend (New Window)

- Create a separate receiver view page for demonstration in a new browser tab/window.
- Sender controls are excluded from this view.
- Receiver view should include:
  - live socket log feed
  - progress bar + phases
  - chunk heatmap/grid and progressive arrival visualization
  - hash verification block
  - decrypted message panel
  - stego image and pixel-diff summary
- Suggested files:
  - frontend/receiver.html
  - frontend/receiver.js
  - shared styles reused from existing style.css where possible

#### Deliverable G: Sender Dashboard Polish

- Keep sender page focused on authoring and transmission controls.
- Add clear transmit lifecycle states:
  - ready
  - transmitting
  - completed
  - error
- Keep encryption visualization and cover-image controls on sender page only.
- Add quick action buttons:
  - retransmit last payload
  - copy diagnostics
  - export report JSON

### API Additions Planned (Non-breaking)

Add optional fields to existing API responses without changing current behavior:

1. GET /api/status
   - phase
   - bytes_sent
   - total_bytes
   - elapsed_seconds
   - kb_per_second
   - eta_seconds
  - current_chunk
  - total_chunks
  - receiver_chunk_map (optional compact representation)
2. GET /api/result
   - pixel_diff_summary object:
     - changed_channels
     - total_channels
     - changed_pixels
     - total_pixels
     - max_delta
     - mean_delta

### Implementation Order

1. Add API telemetry fields and pixel summary fields.
2. Implement timeline + live speed chart + ETA in existing frontend.
3. Implement receiver chunk-map + progressive image arrival visualization.
4. Build receiver-only frontend page and validate in separate window.
5. Add pixel-diff mode toggle and full summary cards.
6. Add before/after slider component.
7. Add download/export buttons and report export.
8. Polish sender dashboard interactions and state messaging.

### Acceptance Criteria

1. Existing sender flow remains fully functional.
2. All new fields are additive and do not break current endpoints.
3. Receiver-only page can be opened directly in a separate window and updates live.
4. Receiver dashboard visibly shows chunk-by-chunk receive progress and completion.
5. Exported JSON report matches displayed values.
6. Large-image transfer still works with responsive UI updates.
7. One end-to-end run demonstrates all new UI elements successfully.

---

## Protocol Specification

### Packet Header (19 bytes)

```
Offset  Size  Field          Description
──────  ────  ─────          ───────────
0       4     magic          0xDEADBEEF
4       1     version        0x01
5       1     msg_type       See table below
6       4     chunk_id       Chunk sequence number (0-indexed)
10      4     total_chunks   Total chunks in this transfer
14      4     payload_size   Bytes of payload following this header
18      1     checksum       XOR of header bytes 0 through 17
```

### Message Types

```
0x00  DH_KEY        Diffie-Hellman public value (receiver → sender, then sender → receiver)
0x01  RSA_PUBKEY    RSA public key PEM file (receiver → sender)
0x02  IMAGE_CHUNK   Stego image chunk (sender → receiver)
0x03  HASH_FILE     SHA-256 hash file (sender → receiver)
0x04  ACK           Transfer acknowledgement (receiver → sender)
```

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| `Connection refused` | Receiver not started | Run `./receiver` before `./sender` |
| `SHA-256 FAILED ❌` | Image corrupted in transit | Check chunk reassembly in receiver.c |
| `Decryption error` | AES key mismatch between sides | Check dh_state/aes_key.bin — re-run from scratch |
| `Image too small` | Cover image can't hold message | Use a larger PNG or a shorter message |
| `gcc: command not found` | GCC not installed | `sudo apt install gcc` |
| `ModuleNotFoundError` | Python deps missing | `pip install cryptography Pillow Flask flask-cors` |
| `Port 8080 in use` | Old receiver process | `kill $(lsof -t -i:8080)` |
| `Port 5000 in use` | Old Flask process | `kill $(lsof -t -i:5000)` |
| Frontend shows nothing | Flask not running | Start `python3 app.py` first |
| `make: Nothing to do` | Already compiled | `make clean && make` |
| DH key mismatch | dh_state files from old run | `rm -rf dh_state/* && ./receiver` again |