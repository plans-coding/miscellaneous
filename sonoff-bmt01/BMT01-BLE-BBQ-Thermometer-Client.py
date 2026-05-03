"""
eWeLink BMT01 BLE BBQ Thermometer Client version 2026-05-03
===========================================================
Re-implemented from the eWeLink JS bundle (output.js, Hermes bytecode).

Auth channel:
  AES-128-CBC, key=MD5(apikey).hexdigest() → bytes, IV=b'0000000000000000'

Control channel:
  Inbound/outbound frame format:
    [cmd_lo, cmd_hi, len_lo, len_hi, ...XOR-encrypted-payload...]
  XOR key:    MD5(apikey) as 16 raw bytes, applied per 16-byte block
              → encryptUtils.encrypt/decrypt in output.js (line 5384648)
              → convertMD5ToBytes(MD5(apikey).toString()) in output.js
  Payload:    [flags_byte, rx_tsn, ...payloadContent...]
  flags byte: bit0 = source (0=APP, 1=DEVICE)
              bit1 = needResponse (0=False, 1=True)
              (byteToBits LSB-first, output.js line 638586)

Temperature (PUSH, source=DEVICE, byte5=0xD4):
  payload_content = [lo1,hi1, lo2,hi2, lo3,hi3, lo4,hi4]
  uint16 LE = °C directly.  Sentinels: 0xFFFF NOT_ACTIVE, 0xFFFE TOO_HIGH,
  0xFFFD TOO_LOW, 0x0FFF INVALID.

Temperature (RESP, source=APP, byte5=0x3D):
  Same uint16-LE °C values but each probe's two bytes are XOR'd with a
  per-probe 2-byte mask before embedding in the payload.  The masks are
  device-specific (derived empirically from one captured frame):
    P1: BD 72   P2: 11 02   P3: 13 DE   P4: 6A 94
  Derivation: mask[i] = resp_decoded_bytes[i] XOR push_decoded_bytes[i]
  (verified: all NOT_ACTIVE probes → FF FF, P2 @ 22°C → 16 00 ✓)

GATT:
  bbb0 = WRITE (TX)   bbb1 = NOTIFY (RX)   bbb3 = NOTIFY2 (RX, secondary)

Source bit semantics:
  source=DEVICE (bit0=1) → autonomous periodic push (byte5=0xD4)
  source=APP    (bit0=0) → device response after button press (byte5=0x3D)
"""

import asyncio
import base64
import hashlib
import struct
import uuid
from datetime import datetime

from bleak import BleakClient, BleakError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Device config ────────────────────────────────────────────────────────────
MAC        = "XX:XX:XX:XX:XX:XX"
DEVICE_KEY = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

NOTIFY_UUID  = "0000bbb1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID2 = "0000bbb3-0000-1000-8000-00805f9b34fb"  # second notify, per Greywood
WRITE_UUID   = "0000bbb0-0000-1000-8000-00805f9b34fb"

POLL_INTERVAL = 3   # seconds between PROBE_TEMPERATURE_REQUEST polls

# ── Crypto ────────────────────────────────────────────────────────────────────
_AES_KEY = bytes.fromhex(hashlib.md5(DEVICE_KEY.encode()).hexdigest())
_AES_IV  = b'0000000000000000'
_XOR_KEY = hashlib.md5(DEVICE_KEY.encode()).digest()   # 16 raw bytes

APP_UUID  = str(uuid.uuid4())

# ── TX sequence number ───────────────────────────────────────────────────────
_tx_tsn = 0

def _next_tsn() -> int:
    global _tx_tsn
    tsn = _tx_tsn
    _tx_tsn = (_tx_tsn + 1) % 256
    return tsn

# ── Last good temperatures from a PUSH (source=DEVICE) frame ─────────────────
_last_push_probes: list[dict] | None = None

# ── BLE client reference ─────────────────────────────────────────────────────
_client: BleakClient | None = None


# ════════════════════════════════════════════════════════════════════════════
# AES helpers (auth channel only)
# ════════════════════════════════════════════════════════════════════════════

def _aes_encrypt(plaintext: str) -> str:
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext.encode() + bytes([pad] * pad)
    cipher = Cipher(algorithms.AES(_AES_KEY), modes.CBC(_AES_IV))
    enc = cipher.encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def _aes_decrypt(b64: str) -> str:
    ct = base64.b64decode(b64)
    cipher = Cipher(algorithms.AES(_AES_KEY), modes.CBC(_AES_IV))
    dec = cipher.decryptor()
    raw = dec.update(ct) + dec.finalize()
    return raw[:-raw[-1]].decode()


# ════════════════════════════════════════════════════════════════════════════
# XOR crypto (control channel — encrypt === decrypt, XOR is self-inverse)
# Mirrors encryptUtils.encrypt in output.js (line 5384648):
#   splice input in 16-byte blocks; for each byte at index i within block,
#   XOR with _XOR_KEY[i].
# ════════════════════════════════════════════════════════════════════════════

def _xor_crypt(data: bytes) -> bytes:
    out = bytearray()
    for start in range(0, len(data), 16):
        block = data[start:start + 16]
        for i, b in enumerate(block):
            out.append(b ^ _XOR_KEY[i])
    return bytes(out)


# ════════════════════════════════════════════════════════════════════════════
# Protocol constants (from ControlCommand enum, output.js line 5384243)
# ════════════════════════════════════════════════════════════════════════════

class CC:
    BATTERY_LEVEL_REQUEST            = 257
    BATTERY_LEVEL_RESPONSE           = 258
    PROBE_TEMPERATURE_REQUEST        = 259
    PROBE_TEMPERATURE_RESPONSE       = 260
    PROBE_PRESET_SETTING             = 261
    ALARM_NOTIFY                     = 262
    HISTORY_REQUEST                  = 263
    HISTORY_RESPONSE                 = 264
    CLEAR_HISTORY                    = 265
    TEMPERATURE_CALIBRATION_SETTING  = 273
    TEMPERATURE_CALIBRATION_REQUEST  = 275
    TEMPERATURE_CALIBRATION_RESPONSE = 276
    ADVANCE_ALARM_REQUEST            = 277
    ADVANCE_ALARM_RESPONSE           = 278
    ADVANCE_ALARM_SETTING            = 279
    TEMPERATURE_UNIT_REQUEST         = 281
    TEMPERATURE_UNIT_RESPONSE        = 282
    TEMPERATURE_UNIT_SETTING         = 283
    CANCEL_ALARM_REQUEST             = 284
    CANCEL_ALARM_RESPONSE            = 285
    COMMON_RESPONSE                  = 65535

_CC_NAMES = {v: k for k, v in vars(CC).items() if not k.startswith('_')}

_PROBE_SENTINELS = {
    0xFFFF: 'NOT_ACTIVE',
    0xFFFE: 'TOO_HIGH',
    0xFFFD: 'TOO_LOW',
    0x0FFF: 'INVALID',
}


# Per-probe masks for 3D RESP PROBE_TEMPERATURE_RESPONSE frames.
# Each probe's uint16-LE °C bytes are XOR'd with a 2-byte probe mask before
# being placed in the RESP payload.  The masks equal:
#   mask[i] = _XOR_KEY[2+i*2 : 4+i*2] XOR _RESP_SECONDARY_KEY[i*2 : i*2+2]
# _RESP_SECONDARY_KEY is a fixed 8-byte firmware constant (verified across
# multiple captures against all 4 probes and several temperatures):
_RESP_SECONDARY_KEY = bytes([0x38, 0xA3, 0x50, 0xAD, 0xED, 0x6F, 0x19, 0x76])
_RESP_PROBE_MASKS = [
    bytes([_XOR_KEY[2 + i*2] ^ _RESP_SECONDARY_KEY[i*2],
           _XOR_KEY[3 + i*2] ^ _RESP_SECONDARY_KEY[i*2 + 1]])
    for i in range(4)
]


def _unmask_resp_payload(payload_content: bytes) -> bytes:
    """Convert 3D RESP probe encoding back to standard uint16-LE °C bytes."""
    out = bytearray()
    for i, mask in enumerate(_RESP_PROBE_MASKS):
        ofs = i * 2
        if ofs + 1 >= len(payload_content):
            break
        out.append(payload_content[ofs]     ^ mask[0])
        out.append(payload_content[ofs + 1] ^ mask[1])
    return bytes(out)


# ════════════════════════════════════════════════════════════════════════════
# Control frame parser
# Mirrors extractControlMessage in output.js (line 5385210)
# ════════════════════════════════════════════════════════════════════════════

def _extract_control_message(data: bytes) -> dict | None:
    """Parse an inbound control-channel BLE frame.

    Frame layout:
      [cmd_lo cmd_hi] [len_lo len_hi] [...XOR-encrypted payload...]
    Decrypted payload:
      [flags] [rx_tsn] [...payloadContent...]
    flags bits (LSB-first per byteToBits in output.js):
      bit0 = source      (0=APP, 1=DEVICE)
      bit1 = needResponse (0=False, 1=True)
    """
    if len(data) < 4:
        return None
    command     = struct.unpack_from('<H', data, 0)[0]
    data_length = struct.unpack_from('<H', data, 2)[0]
    decrypted   = _xor_crypt(data[4:])
    if data_length != len(decrypted):
        print(f"[WARN] control frame length mismatch: expected={data_length} got={len(decrypted)}")
        return None
    flags           = decrypted[0]
    source          =  flags & 0x01          # bit 0: 1=DEVICE push, 0=RESP/housekeeping
    need_response   = (flags >> 1) & 0x01    # bit 1
    rx_tsn          = decrypted[1]
    payload_content = bytes(decrypted[2:])
    return {
        'command':         command,
        'name':            _CC_NAMES.get(command, f'0x{command:04X}'),
        'source':          source,
        'need_response':   need_response,
        'rx_tsn':          rx_tsn,
        'payload_content': payload_content,
    }


# ════════════════════════════════════════════════════════════════════════════
# Temperature parser
# Mirrors bytesToProbeTemperature (output.js line 5386357)
# ════════════════════════════════════════════════════════════════════════════

def _decode_probe(raw: int) -> dict:
    sentinel = _PROBE_SENTINELS.get(raw)
    if sentinel:
        return {'status': sentinel, 'temp_c': None, 'temp_f': None,
                'raw': f'0x{raw:04X}'}
    temp_c = float(raw)
    temp_f = round(temp_c * 9 / 5 + 32, 1)
    return {'status': 'ok', 'temp_c': temp_c, 'temp_f': temp_f,
            'raw': f'0x{raw:04X}'}


def _parse_probe_temperatures(payload_content: bytes) -> list[dict]:
    probes = []
    for i in range(0, len(payload_content) - 1, 2):
        raw = struct.unpack_from('<H', payload_content, i)[0]
        probes.append(_decode_probe(raw))
    return probes


# ════════════════════════════════════════════════════════════════════════════
# Control frame builder
# Mirrors createControlMessage in output.js (line 5385069)
# ════════════════════════════════════════════════════════════════════════════

def _build_control_frame(command: int, need_response: bool = True,
                         payload_content: bytes = b'') -> bytes:
    flags       = (0 << 0) | ((1 if need_response else 0) << 1)
    tx_tsn      = _next_tsn()
    raw_payload = bytes([flags, tx_tsn]) + payload_content
    encrypted   = _xor_crypt(raw_payload)
    return struct.pack('<HH', command, len(encrypted)) + encrypted


# ════════════════════════════════════════════════════════════════════════════
# Transport helpers
# ════════════════════════════════════════════════════════════════════════════

async def _ble_write(data: bytes):
    for i in range(0, len(data), 20):
        await _client.write_gatt_char(WRITE_UUID, data[i:i + 20], response=False)
        await asyncio.sleep(0.05)


async def _send_auth_frame(msg_type: int, body: bytes):
    header = bytes([msg_type, 0x00]) + struct.pack('<H', len(body))
    await _ble_write(header + body)


async def _send_control(command: int, need_response: bool = True,
                        payload_content: bytes = b''):
    frame = _build_control_frame(command, need_response, payload_content)
    await _ble_write(frame)


# ════════════════════════════════════════════════════════════════════════════
# Display helpers
# ════════════════════════════════════════════════════════════════════════════

def _fmt_hex(data: bytes) -> str:
    return ' '.join(
        f'\033[32m{b:02X}\033[0m' if i < 4 else f'{b:02X}'
        for i, b in enumerate(data)
    )


def _fmt_probe(p: dict, label: str) -> str:
    if p['status'] != 'ok':
        return f"{label}={p['status']}"
    return f"{label}={p['temp_c']:.0f}°C({p['temp_f']:.1f}°F)"


def _print_temps(probes: list[dict], tag: str, tsn: int):
    now = datetime.now().strftime('%H:%M:%S')
    probe_str = '  '.join(_fmt_probe(p, f'P{i+1}') for i, p in enumerate(probes))
    print(f"TEMP [{now}] {tag} tsn={tsn:3d}  {probe_str}")


# ════════════════════════════════════════════════════════════════════════════
# BLE notification handler
# ════════════════════════════════════════════════════════════════════════════

async def _on_notify(sender, data: bytes):
    global _last_push_probes

    print(f"RX: {_fmt_hex(data)}")

    if len(data) < 2:
        return

    # Control-channel frames: ControlCommands 257-285 have data[1]==0x01 in LE.
    # COMMON_RESPONSE (0xFFFF) has both bytes 0xFF.
    # Auth frames (0x00-0x03, 0x21-0x26) have data[1]==0x00 or small values.
    is_control = (data[1] == 0x01) or (data[0] == 0xFF and data[1] == 0xFF)

    if is_control:
        msg = _extract_control_message(data)
        if msg is None:
            return
        cmd = msg['command']
        is_push = msg['source'] == 1   # bit0=1: DEVICE autonomous push (D4)
        src = 'PUSH' if is_push else 'RESP'

        if cmd == CC.PROBE_TEMPERATURE_RESPONSE:
            if is_push:
                probes = _parse_probe_temperatures(msg['payload_content'])
                _last_push_probes = probes
                _print_temps(probes, 'PUSH', msg['rx_tsn'])
            else:
                # 3D RESP frames use per-probe XOR masks over the uint16-LE °C values.
                # Unmask first, then decode identically to PUSH frames.
                unmasked = _unmask_resp_payload(msg['payload_content'])
                probes = _parse_probe_temperatures(unmasked)
                _last_push_probes = probes
                _print_temps(probes, 'RESP', msg['rx_tsn'])

        elif cmd == CC.BATTERY_LEVEL_RESPONSE:
            level = msg['payload_content'][0] if msg['payload_content'] else '?'
            print(f"BATTERY [{src}]: {level}%")

        elif cmd == CC.TEMPERATURE_UNIT_RESPONSE:
            unit = 'Fahrenheit' if (msg['payload_content'] and msg['payload_content'][0]) else 'Celsius'
            print(f"TEMP_UNIT [{src}]: {unit}")

        elif cmd == CC.COMMON_RESPONSE:
            if len(msg['payload_content']) >= 2:
                status = struct.unpack_from('<H', msg['payload_content'])[0]
            else:
                status = '?'
            print(f"COMMON_RESPONSE [{src}]: status={status}")

        else:
            print(f"CONTROL [{src}] [{msg['name']}] tsn={msg['rx_tsn']} "
                  f"payload={msg['payload_content'].hex().upper()}")
        return

    # ── Auth / OTA frames ────────────────────────────────────────────────────
    cmd = data[0]

    if cmd == 0x01 and data[1] == 0x00:
        try:
            body = data[4:].decode('ascii', errors='ignore').strip('\x00')
            device_uuid = _aes_decrypt(body)
            confirm = _aes_encrypt(f"{APP_UUID}_{device_uuid}").encode()
            await _send_auth_frame(0x02, confirm)
            print("AUTH: challenge response sent")
        except Exception as e:
            print(f"AUTH error: {e}")
        return

    if cmd == 0x03:
        print("AUTH: accepted")
        await _client.write_gatt_char(WRITE_UUID, bytes([0x21, 0x00, 0x00, 0x00]),
                                      response=False)
        await asyncio.sleep(0.2)
        await _send_control(CC.PROBE_TEMPERATURE_REQUEST, need_response=True)
        print("Probe temperature requested\n")
        return

    if cmd in (0x1D, 0x22):
        return

    print(f"UNKNOWN cmd=0x{cmd:02X} data={data.hex().upper()}")


async def _on_notify2(sender, data: bytes):
    """Raw log for bbb3 — second notify characteristic (per Greywood)."""
    print(f"RX2: {_fmt_hex(data)}")


# ════════════════════════════════════════════════════════════════════════════
# Main loop (auto-reconnect on disconnect or BLE error)
# ════════════════════════════════════════════════════════════════════════════

async def _poll_loop():
    """Periodically request probe temperatures so updates continue after button press."""
    while True:
        await asyncio.sleep(POLL_INTERVAL)
        if _client and _client.is_connected:
            await _send_control(CC.PROBE_TEMPERATURE_REQUEST, need_response=True)


async def main():
    global _client, _tx_tsn, _last_push_probes

    print(f"BMT01 version 2026-05-03 — connecting to {MAC}")
    print(f"XOR key (MD5 raw bytes): {_XOR_KEY.hex()}\n")

    while True:
        _tx_tsn = 0
        _last_push_probes = None
        try:
            async with BleakClient(MAC, timeout=20) as client:
                _client = client
                print("Connected")

                await client.start_notify(NOTIFY_UUID, _on_notify)
                try:
                    await client.start_notify(NOTIFY_UUID2, _on_notify2)
                    print("bbb3 subscribed")
                except Exception:
                    pass  # bbb3 may not be present on all firmware versions

                await _send_auth_frame(0x00, _aes_encrypt(APP_UUID).encode())
                print("AUTH: request sent\n")

                poll_task = asyncio.create_task(_poll_loop())
                try:
                    while client.is_connected:
                        await asyncio.sleep(1)
                finally:
                    poll_task.cancel()

                print("Disconnected — reconnecting in 3 s...")
                await asyncio.sleep(3)

        except BleakError as e:
            print(f"BLE error: {e} — retry in 5 s...")
            await asyncio.sleep(5)
        except KeyboardInterrupt:
            print("\nStopped.")
            return


if __name__ == "__main__":
    asyncio.run(main())
