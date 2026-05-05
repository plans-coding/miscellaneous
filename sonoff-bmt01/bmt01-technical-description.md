# Sonoff BMT01 Introduction

## Features
* Set temperature target alarm per probe
* Set temperature range alarm per probe
* Disable/acknowledge temperature target/range alarm
* Battery level info
* Set temperature unit (C or F)
* Temperature calibration per probe

## Find your device key
1. Create an account in the ewelink app and pair BMT01
2. Identify the device key
3. The secret key is MD5(devicekey)

## Where do you find the ewelink core logic
The bundled APK includes a file named base.apk (it’s a ZIP archive—extract its contents). Locate the file assets/index.android.bundle (this is React Native Hermes bytecode) and decompile it using an appropriate tool. The decompiled output contains all the logic used by eWeLink.

# Sonoff BMT01 BLE Protocol Summary

## Encryption

### Auth Channel (AES)

```text
secretKey = MD5(device.apikey).hexdigest() → bytes
iv        = b'0000000000000000'

pad       = PKCS7(plaintext)
cipher    = AES-128-CBC(padded, secretKey, iv)
output    = base64(ciphertext)
```

---

### Control Channel (XOR)

```text
xorKey = MD5(device.apikey).digest()  // 16 raw bytes

for each 16-byte block:
    encrypted[i] = data[i] XOR xorKey[i]
```

---

## Frame Structure

### Standard Control Frame

```text
flags     = (source_bit) | (needResponse << 1)
tsn       = incrementing byte (or token-derived)

payload   = [flags, tsn] + payload_content
encrypted = XOR(payload)

frame     = uint16_le(command)
          + uint16_le(len(encrypted))
          + encrypted
```

---

### Ticket-Based Frame (Raw, No XOR)

```text
payload = [0x89, ticket] + payload_content

frame   = uint16_le(command)
        + uint16_le(len(payload))
        + payload
```

---

### Output.js Control Frame (Hybrid)

```text
token_tsn = ticket XOR xorKey[1]

→ build standard XOR control frame using:
   tsn = token_tsn
```

---

## Auth Handshake Frame

```text
body   = AES_encrypt(data)

header = [msg_type, 0x00]
       + uint16_le(len(body))

frame  = header + body
```

---

## Incoming Frame Parsing

```text
command   = uint16_le(data[0:2])
length    = uint16_le(data[2:4])

decrypted = XOR(data[4:])

flags     = decrypted[0]
tsn       = decrypted[1]
payload   = decrypted[2:]
```

---

## Flags Bit Layout

```text
bit0 = source        (0 = APP, 1 = DEVICE)
bit1 = needResponse  (0 = false, 1 = true)
```

---

## Payload: Temperature Format

```text
payload_content = [lo, hi] * N probes
value           = uint16_le → °C
```

### Special Values

```text
0xFFFF = NOT_ACTIVE
0xFFFE = TOO_HIGH
0xFFFD = TOO_LOW
0x0FFF = INVALID
```

---

## Key Concepts

* Two distinct encryption layers:

  * **AES-128-CBC + Base64** → authentication only
  * **XOR (MD5 raw bytes)** → all control communication

* All frames follow:

```text
[command (2 bytes)] + [length (2 bytes)] + [payload]
```

* **TSN (Transaction Sequence Number)** is used to match requests/responses

* **Ticket system**:

  * Used in raw frames
  * Mapped into TSN via:

```text
tsn = ticket XOR xorKey[1]
```
