"""
Sonoff BMT01 BLE BBQ Thermometer Client version 2026-05-06 rev B
================================================================
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
  per-probe 2-byte mask before embedding in the payload.  Masks are
  device-specific: mask[i] = MD5(apikey)[2+i*2:4+i*2] XOR secondary_key[i*2:i*2+2]
  where secondary_key = 38 A3 50 AD ED 6F 19 76 (firmware constant).
  For this device: P1=BD 72  P2=1E 02  P3=13 DE  P4=6A 94.
  The same masks apply to PROBE_PRESET_SETTING outbound payloads.

GATT:
  bbb0 = WRITE (TX)   bbb1 = NOTIFY (RX)   bbb3 = NOTIFY2 (RX, secondary)

Source bit semantics:
  source=DEVICE (bit0=1) → autonomous periodic push (byte5=0xD4)
  source=APP    (bit0=0) → device response after button press (byte5=0x3D)

New in v8:
  Temperature unit (TEMPERATURE_UNIT_SETTING = 283):
    payload = [0=Celsius | 1=Fahrenheit]

  Range alarm (ADVANCE_ALARM_SETTING = 279):
    payload = [wire_probe (0-based), lower_c_lo, lower_c_hi, upper_c_lo, upper_c_hi]
    Use 0xFFFF for disabled bounds.

  Battery (BATTERY_LEVEL_REQUEST = 257):
    No payload; response byte[0] = battery %.

  Calibration (TEMPERATURE_CALIBRATION_SETTING = 273):
    payload = 4 × [celsius_lo, celsius_hi_sign, fahrenheit_lo, fahrenheit_hi_sign]
    Sign-magnitude: bit15=1 → positive, bit15=0 → negative.
    Fahrenheit offset = celsius_offset × 9/5 (rounded to integer).
"""

import asyncio
import base64
import hashlib
import struct
import sys
import time
import uuid
import builtins
import threading
from datetime import datetime

from bleak import BleakClient, BleakError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    import readline
except ImportError:
    readline = None

_orig_print = builtins.print
_print_lock = threading.Lock()
_awaiting_input = False

def _coordinated_print(*args, **kwargs):
    """Print with coordination for terminal output, preserving user input."""
    global _awaiting_input
    if kwargs.get('file', sys.stdout) in (None, sys.stdout):
        with _print_lock:
            if _awaiting_input:
                # Save current input buffer if readline is available
                input_buffer = ""
                if readline:
                    input_buffer = readline.get_line_buffer()
                    # Clear the current input line
                    sys.stdout.write('\r' + ' ' * 120 + '\r')
                    sys.stdout.flush()
            
            _orig_print(*args, **kwargs)
            
            if _awaiting_input:
                # Restore prompt and input buffer
                sys.stdout.write("cmd> " + input_buffer)
                sys.stdout.flush()
    else:
        _orig_print(*args, **kwargs)

builtins.print = _coordinated_print

MAC        = "XX:XX:XX:XX:XX:XX"
DEVICE_KEY = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

NOTIFY_UUID  = "0000bbb1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID2 = "0000bbb3-0000-1000-8000-00805f9b34fb"
WRITE_UUID   = "0000bbb0-0000-1000-8000-00805f9b34fb"

POLL_INTERVAL = 3

# --debug enables RX/TX hex line output (verbose protocol tracing)
_DEBUG = '--debug' in sys.argv or '-d' in sys.argv

_AES_KEY = bytes.fromhex(hashlib.md5(DEVICE_KEY.encode()).hexdigest())
_AES_IV  = b'0000000000000000'
_XOR_KEY = hashlib.md5(DEVICE_KEY.encode()).digest()

APP_UUID  = str(uuid.uuid4())

_tx_tsn = 0

def _next_tsn() -> int:
    global _tx_tsn
    tsn = _tx_tsn
    _tx_tsn = (_tx_tsn + 1) % 256
    return tsn

_last_push_probes: list[dict] | None = None

_ticket_queue: asyncio.Queue[int] | None = None
_last_ticket: int | None = None
_last_ticket_mono: float = 0.0
_pending_ticket_responses: dict[int, asyncio.Future[dict]] = {}

_client: BleakClient | None = None
_last_marker: int | None = None
_last_battery_pct: int | None = None

# Calibration offsets (°C) per probe, cached from last CALIBRATION_RESPONSE
_calibration_offsets: list[float] = [0.0, 0.0, 0.0, 0.0]


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


def _xor_crypt(data: bytes) -> bytes:
    out = bytearray()
    for start in range(0, len(data), 16):
        block = data[start:start + 16]
        for i, b in enumerate(block):
            out.append(b ^ _XOR_KEY[i])
    return bytes(out)


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

_RESP_SECONDARY_KEY = bytes([0x38, 0xA3, 0x50, 0xAD, 0xED, 0x6F, 0x19, 0x76])
_RESP_PROBE_MASKS = [
    bytes([_XOR_KEY[2 + i*2] ^ _RESP_SECONDARY_KEY[i*2],
           _XOR_KEY[3 + i*2] ^ _RESP_SECONDARY_KEY[i*2 + 1]])
    for i in range(4)
]

# Marker 0xD2 frames (raw, post-button-press temperature pushes) use these
# device-specific per-probe masks applied directly to the bytes (no XOR layer).
# Verified empirically against this device's pre-button-press D4 readings.
_D2_PROBE_MASKS = [
    bytes([0x4B, 0x94]),
    bytes([0x47, 0xAD]),
    bytes([0xFC, 0x93]),
    bytes([0x3F, 0xDA]),
]


def _unmask_resp_payload(payload_content: bytes) -> bytes:
    out = bytearray()
    for i, mask in enumerate(_RESP_PROBE_MASKS):
        ofs = i * 2
        if ofs + 1 >= len(payload_content):
            break
        out.append(payload_content[ofs]     ^ mask[0])
        out.append(payload_content[ofs + 1] ^ mask[1])
    return bytes(out)


def _unmask_d2_payload(raw_probe_bytes: bytes) -> bytes:
    """Apply D2-specific per-probe masks to raw (non-XOR'd) probe data."""
    out = bytearray()
    for i, mask in enumerate(_D2_PROBE_MASKS):
        ofs = i * 2
        if ofs + 1 >= len(raw_probe_bytes):
            break
        out.append(raw_probe_bytes[ofs]     ^ mask[0])
        out.append(raw_probe_bytes[ofs + 1] ^ mask[1])
    return bytes(out)


NO_ALARM = 0x0100
_alarm_targets: list[int | None] = [None, None, None, None]
PRESET_EMPTY = 0
PRESET_UPPER_TEMP = 1
PRESET_RANGE = 2
WIRE_PROBE_INDEX_BASE = 0


def _build_preset_payload(targets: list[int | None]) -> bytes:
    probe = bytearray()
    for i in range(4):
        t = NO_ALARM if (i >= len(targets) or targets[i] is None) else int(targets[i])
        lo, hi = t & 0xFF, (t >> 8) & 0xFF
        probe.append(lo ^ _RESP_PROBE_MASKS[i][0])
        probe.append(hi ^ _RESP_PROBE_MASKS[i][1])
    x0 = 0xDA
    for b in probe:
        x0 ^= b
    return bytes(probe) + bytes([x0, 0x1E, 0x60, 0xA8])


def _le16(value: int) -> bytes:
    return struct.pack('<H', int(value) & 0xFFFF)


def _build_probe_alarm_payload(probe: int, lower_c: int | None, upper_c: int | None) -> bytes:
    wire_probe = probe - 1
    if lower_c is None and upper_c is None:
        preset_type = PRESET_EMPTY
        l_c = l_f = u_c = u_f = NO_ALARM
    elif lower_c == upper_c:
        preset_type = PRESET_UPPER_TEMP
        u_c = int(upper_c)
        u_f = round(u_c * 9 / 5 + 32)
        l_c, l_f = u_c, u_f
    else:
        preset_type = PRESET_RANGE
        l_c = int(lower_c)
        l_f = round(l_c * 9 / 5 + 32)
        u_c = int(upper_c)
        u_f = round(u_c * 9 / 5 + 32)

    return (
        bytes([wire_probe, preset_type])
        + _le16(l_c) + _le16(l_f)
        + _le16(u_c) + _le16(u_f)
        + _le16(0) + bytes([0])  # timer
    )

# --- Temperature unit -------------------------------------------------------

def _build_temp_unit_payload(use_fahrenheit: bool) -> bytes:
    return bytes([1 if use_fahrenheit else 0])

# Confirmed from bytesToAdvanceAlarm: response byte[0] is AdvanceAlarmEnable.ENABLE=1
# This is a global (device-wide) alarm, not per-probe.
# ---------------------------------------------------------------------------
def _build_advance_alarm_payload(lower_c: int | None, upper_c: int | None) -> bytes:
    if lower_c is None and upper_c is None:
        return bytes([0, 0, 0, 0, 0])  # DISABLE
    enable = 1
    lower = lower_c if lower_c is not None else 0xFFFF
    upper = upper_c if upper_c is not None else 0xFFFF
    return struct.pack('<B', enable) + _le16(lower) + _le16(upper)


# ---------------------------------------------------------------------------
# Calibration encoding (sign-magnitude, bit15=1→positive, bit15=0→negative)
# ---------------------------------------------------------------------------

def _calibration_value_to_bytes(value: float) -> bytes:
    abs_val = int(round(abs(value)))
    abs_val = min(abs_val, 0x7FFF)
    lo = abs_val & 0xFF
    hi = (abs_val >> 8) & 0x7F
    if value >= 0:
        hi |= 0x80  # bit15 = 1 → positive
    return bytes([lo, hi])


def _calibration_bytes_to_value(data: bytes) -> float:
    lo = data[0]
    hi = data[1]
    positive = bool(hi & 0x80)
    hi_clean = hi & 0x7F
    magnitude = lo | (hi_clean << 8)
    return float(magnitude) if positive else -float(magnitude)


def _parse_calibration_response(payload: bytes) -> list[dict]:
    calibrations = []
    for i in range(4):
        ofs = i * 4
        if ofs + 3 >= len(payload):
            break
        c = _calibration_bytes_to_value(payload[ofs:ofs + 2])
        f = _calibration_bytes_to_value(payload[ofs + 2:ofs + 4])
        calibrations.append({'celsius': c, 'fahrenheit': f})
    return calibrations


def _build_calibration_payload(offsets_c: list[float]) -> bytes:
    payload = bytearray()
    for i in range(4):
        oc = offsets_c[i] if i < len(offsets_c) else 0.0
        of_ = round(oc * 9 / 5)
        payload += _calibration_value_to_bytes(oc)
        payload += _calibration_value_to_bytes(float(of_))
    return bytes(payload)


def _extract_control_message(data: bytes) -> dict | None:
    if len(data) < 4:
        return None
    command     = struct.unpack_from('<H', data, 0)[0]
    data_length = struct.unpack_from('<H', data, 2)[0]
    decrypted   = _xor_crypt(data[4:])
    if data_length != len(decrypted):
        print(f"[WARN] control frame length mismatch: expected={data_length} got={len(decrypted)}")
        return None
    flags           = decrypted[0]
    raw_flags       = flags
    source          =  flags & 0x01
    need_response   = (flags >> 1) & 0x01
    rx_tsn          = decrypted[1]
    payload_content = bytes(decrypted[2:])
    return {
        'command':         command,
        'name':            _CC_NAMES.get(command, f'0x{command:04X}'),
        'flags':           raw_flags,
        'source':          source,
        'need_response':   need_response,
        'rx_tsn':          rx_tsn,
        'payload_content': payload_content,
    }


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


def _build_control_frame(command: int, need_response: bool = True,
                         payload_content: bytes = b'',
                         token_tsn: int | None = None) -> bytes:
    flags       = (0 << 0) | ((1 if need_response else 0) << 1)
    tx_tsn      = token_tsn if token_tsn is not None else _next_tsn()
    raw_payload = bytes([flags, tx_tsn]) + payload_content
    encrypted   = _xor_crypt(raw_payload)
    return struct.pack('<HH', command, len(encrypted)) + encrypted


def _command_marker_for_state() -> int:
    """Pick the command marker based on the device's current state.

    Marker pattern (XOR 0x50 between normal/button-press states):
      - Telemetry: 0x82 (normal)  / 0xD2 (button-press) / 0xD4 (XOR push)
      - Response:  0x8E (normal)  / 0xDE (button-press)
      - Command:   0x89 (normal)  / 0xD9 (button-press)
    """
    if _last_marker in (0xD2, 0xDE):
        return 0xD9
    return 0x89


def _mask_d9_payload(content: bytes) -> bytes:
    """Mask command payload when sending in button-press (0xD9) mode.

    Mirror of _unmask_de_payload — XOR with D2 probe-1 mask [0x4B, 0x94] cyclic.
    """
    mask = _D2_PROBE_MASKS[0]
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(content))


def _build_ticketed_frame(command: int, ticket: int, payload_content: bytes = b'',
                          marker: int | None = None) -> bytes:
    if marker is None:
        marker = _command_marker_for_state()
    if marker == 0xD9 and payload_content:
        # Button-press mode: device expects payload masked like D2/DE frames
        payload_content = _mask_d9_payload(payload_content)
    raw_payload = bytes([marker, ticket]) + payload_content
    return struct.pack('<HH', command, len(raw_payload)) + raw_payload


def _build_outputjs_control_frame(command: int, ticket: int,
                                  payload_content: bytes) -> tuple[bytes, int]:
    token_tsn = ticket ^ _XOR_KEY[1]
    frame = _build_control_frame(
        command,
        need_response=True,
        payload_content=payload_content,
        token_tsn=token_tsn,
    )
    return frame, token_tsn


def _live_ticket_marker(data: bytes) -> int | None:
    if len(data) >= 6 and data[:4] == b'\x04\x01\x0A\x00' and data[4] in (0x82, 0xD4, 0xD2):
        return data[4]
    return None

async def _next_ticket(timeout: float = 5.0) -> int:
    """Wait for a FRESH ticket from the next live telemetry packet.

    The device sends single-use ticket bytes in each live telemetry packet.
    Per protocol: each command must use a fresh ticket; reusing the same XX
    causes the device to ignore the command. So we drain any stale ticket
    sitting in the queue and wait for the next telemetry packet to arrive.
    """
    if _ticket_queue is None:
        raise TimeoutError("ticket queue is not ready")
    # Drain any stale ticket from previous telemetry — we want a fresh one
    try:
        stale = _ticket_queue.get_nowait()
        if _DEBUG:
            print(f"TICKET drain stale: 0x{stale:02X}")
    except asyncio.QueueEmpty:
        pass
    try:
        return await asyncio.wait_for(_ticket_queue.get(), timeout=timeout)
    except asyncio.TimeoutError as e:
        raise TimeoutError("timeout waiting for fresh live telemetry ticket") from e


def _offer_ticket(ticket: int):
    global _last_ticket, _last_ticket_mono
    _last_ticket = ticket
    _last_ticket_mono = time.monotonic()
    if _ticket_queue is None:
        return
    try:
        _ticket_queue.get_nowait()  # drain stale entry (maxsize=1)
    except asyncio.QueueEmpty:
        pass
    _ticket_queue.put_nowait(ticket)


def _unmask_de_payload(content: bytes) -> bytes:
    """Decode payload of 0xDE (post-button-press) responses.

    The payload bytes are masked with the same D2 probe-1 mask [0x4B, 0x94]
    used for D2 telemetry pushes — applied cyclically across the payload.
    Verified empirically: 0x1B ^ 0x4B = 0x50 (80% battery).
    """
    mask = _D2_PROBE_MASKS[0]
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(content))


def _parse_raw_ticket_response(data: bytes) -> dict | None:
    # 0x8E = normal raw response marker
    # 0xDE = post-button-press raw response marker (parallel to D4/D2 telemetry)
    if len(data) < 6 or data[4] not in (0x8E, 0xDE):
        return None
    command = struct.unpack_from('<H', data, 0)[0]
    data_length = struct.unpack_from('<H', data, 2)[0]
    payload = data[4:]
    if data_length != len(payload):
        print(f"[WARN] raw frame length mismatch: expected={data_length} got={len(payload)}")
        return None
    content = bytes(payload[2:])
    if payload[0] == 0xDE:
        # Post-button-press responses encode payload with D2 probe-1 mask
        content = _unmask_de_payload(content)
    msg = {
        'command': command,
        'name': _CC_NAMES.get(command, f'0x{command:04X}'),
        'marker': payload[0],
        'ticket': payload[1],
        'payload_content': content,
        'status': None,
    }
    if command == CC.COMMON_RESPONSE and len(content) >= 2:
        msg['status'] = struct.unpack_from('<H', content, 0)[0]
    return msg


def _finish_pending_response(ticket: int, msg: dict):
    future = _pending_ticket_responses.get(ticket)
    if future and not future.done():
        future.set_result(msg)


async def _send_adaptive_control(command: int, payload_content: bytes = b'',
                                 timeout: float = 7.0) -> dict:
    """Send command, adapting frame format based on device state (last marker seen).

    If device is in XOR-encrypted mode (0xD4): use encrypted control frames.
    Otherwise (0x82, 0xD2, unknown): use raw ticketed frames.
    """
    if _last_marker == 0xD4:
        return await _send_outputjs_control(command, payload_content, timeout=timeout)
    else:
        return await _send_ticketed_control(command, payload_content, timeout=timeout)


async def _send_ticketed_control(command: int, payload_content: bytes = b'',
                                 timeout: float = 5.0) -> dict:
    ticket = await _next_ticket(timeout=timeout)
    frame = _build_ticketed_frame(command, ticket, payload_content)

    loop = asyncio.get_running_loop()
    response_future: asyncio.Future[dict] = loop.create_future()
    _pending_ticket_responses[ticket] = response_future
    if _DEBUG:
        print(f"TX ticket=0x{ticket:02X}: {_fmt_hex(frame)}")
    try:
        await _ble_write(frame)
        try:
            return await asyncio.wait_for(response_future, timeout=timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"timeout waiting for response to ticket 0x{ticket:02X}") from e
    finally:
        _pending_ticket_responses.pop(ticket, None)


async def _send_outputjs_control(command: int, payload_content: bytes,
                                 timeout: float = 7.0) -> dict:
    """Send a setting command using the XOR-encrypted output.js frame format.

    Uses fresh device tickets to ensure command processing even after button presses.
    Ticket is XORed with _XOR_KEY[1] to create the tx_tsn used in frame encryption.
    """
    ticket = await _next_ticket(timeout=timeout)
    frame, token_tsn = _build_outputjs_control_frame(command, ticket, payload_content)

    loop = asyncio.get_running_loop()
    response_future: asyncio.Future[dict] = loop.create_future()
    _pending_ticket_responses[token_tsn] = response_future
    if _DEBUG:
        print(f"TX outputjs cmd={command} ticket=0x{ticket:02X} tsn=0x{token_tsn:02X}: {_fmt_hex(frame)}")
    try:
        await _ble_write(frame)
        try:
            return await asyncio.wait_for(response_future, timeout=timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"timeout waiting for response to cmd={command} ticket=0x{ticket:02X}") from e
    finally:
        _pending_ticket_responses.pop(token_tsn, None)


async def _send_outputjs_alarm_control(payload_content: bytes,
                                       timeout: float = 5.0) -> dict:
    ticket = await _next_ticket(timeout=timeout)
    frame, token_tsn = _build_outputjs_alarm_frame(ticket, payload_content)

    loop = asyncio.get_running_loop()
    response_future: asyncio.Future[dict] = loop.create_future()
    _pending_ticket_responses[token_tsn] = response_future
    _pending_ticket_responses[ticket]    = response_future
    if _DEBUG:
        print(f"TX outputjs-alarm ticket=0x{ticket:02X} tsn=0x{token_tsn:02X}: {_fmt_hex(frame)}")
    try:
        await _ble_write(frame)
        try:
            return await asyncio.wait_for(response_future, timeout=timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"timeout waiting for COMMON_RESPONSE to ticket 0x{ticket:02X}") from e
    finally:
        _pending_ticket_responses.pop(token_tsn, None)
        _pending_ticket_responses.pop(ticket, None)


async def _ble_write(data: bytes):
    for i in range(0, len(data), 20):
        await _client.write_gatt_char(WRITE_UUID, data[i:i + 20], response=False)
        await asyncio.sleep(0.05)


async def _send_auth_frame(msg_type: int, body: bytes):
    header = bytes([msg_type, 0x00]) + struct.pack('<H', len(body))
    await _ble_write(header + body)


async def _send_control(command: int, need_response: bool = True,
                        payload_content: bytes = b''):
    if need_response:
        # Adapt command format based on device state (last marker seen)
        if _last_marker == 0xD4:
            # Device in XOR-encrypted mode: use encrypted control frames
            await _send_outputjs_control(command, payload_content)
        else:
            # Device in raw mode (0x82, 0xD2, or unknown): use raw ticketed frames
            await _send_ticketed_control(command, payload_content)
        return
    frame = _build_control_frame(command, need_response, payload_content)
    await _ble_write(frame)


def _fmt_hex(data: bytes) -> str:
    return ' '.join(
        f'\033[32m{b:02X}\033[0m' if i < 4 else f'{b:02X}'
        for i, b in enumerate(data)
    )


def _fmt_probe(p: dict, label: str) -> str:
    if p['status'] != 'ok':
        return f"{label}={p['status']}"
    # Highlight active probe Celsius temperature in red
    return f"{label}=\033[31m{p['temp_c']:.0f}°C\033[0m({p['temp_f']:.1f}°F)"


def _print_temps(probes: list[dict], tag: str, tsn: int):
    now = datetime.now().strftime('%H:%M:%S')
    probe_str = '  '.join(_fmt_probe(p, f'P{i+1}') for i, p in enumerate(probes))
    print(f"\033[32mTEMP\033[0m [{now}] {tag} tsn={tsn:3d}  {probe_str}")


def _handle_raw_v5_packet(data: bytes) -> bool:
    global _last_push_probes, _calibration_offsets, _last_marker, _last_battery_pct

    marker = _live_ticket_marker(data)
    if marker is not None:
        _last_marker = marker
        ticket = data[5]
        _offer_ticket(ticket)
        if _DEBUG:
            print(f"TICKET fresh: marker=0x{marker:02X} ticket=0x{ticket:02X}")

        if marker == 0xD4:
            # Standard XOR-encrypted PUSH — let _on_notify decrypt it.
            return False

        if marker == 0xD2:
            # Post-button-press push — frame is RAW (no XOR), probe data
            # is per-probe masked with device-specific D2 masks.
            unmasked = _unmask_d2_payload(data[6:])
            probes = _parse_probe_temperatures(unmasked)
            _last_push_probes = probes
            _print_temps(probes, 'BTN', ticket)
            return True

        # 0x82 raw push: probe bytes are not encrypted/masked.
        probes = _parse_probe_temperatures(data[6:])
        _last_push_probes = probes
        _print_temps(probes, 'PUSH', ticket)
        return True

    raw_response = _parse_raw_ticket_response(data)
    if raw_response is None:
        return False

    ticket = raw_response['ticket']
    _finish_pending_response(ticket, raw_response)

    cmd = raw_response['command']
    payload = raw_response['payload_content']
    if cmd == CC.BATTERY_LEVEL_RESPONSE:
        if payload:
            level = payload[0]
            display_level = max(0, min(100, level))
            label = 'LOW' if display_level < 30 else ('OK' if display_level < 70 else 'FULL')
            _last_battery_pct = display_level
            if level != display_level:
                print(f"BATTERY [RAW] ticket=0x{ticket:02X}: {level}% (raw) -> {display_level}% ({label})")
            else:
                print(f"BATTERY [RAW] ticket=0x{ticket:02X}: {display_level}% ({label})")
        else:
            print(f"BATTERY [RAW] ticket=0x{ticket:02X}: (no payload)")
    elif cmd == CC.TEMPERATURE_CALIBRATION_RESPONSE:
        cals = _parse_calibration_response(payload)
        _calibration_offsets = [c['celsius'] for c in cals] + [0.0] * (4 - len(cals))
        cal_str = '  '.join(f"P{i+1}={c['celsius']:+.0f}°C" for i, c in enumerate(cals))
        print(f"CALIBRATION [RAW] ticket=0x{ticket:02X}: {cal_str}")
    elif cmd == CC.ADVANCE_ALARM_RESPONSE:
        if len(payload) >= 3:
            enabled = payload[0] == 1
            cel = payload[1]
            fah = payload[2]
            print(f"ADVANCE_ALARM [RAW] ticket=0x{ticket:02X}: "
                  f"enabled={enabled} celsius={cel} fahrenheit={fah}")
        else:
            print(f"ADVANCE_ALARM [RAW] ticket=0x{ticket:02X}: payload={payload.hex().upper()}")
    elif cmd == CC.COMMON_RESPONSE:
        print(f"COMMON_RESPONSE [RAW] ticket=0x{ticket:02X}: status={raw_response['status']}")
    else:
        print(f"CONTROL [RAW] [{raw_response['name']}] ticket=0x{ticket:02X} "
              f"payload={payload.hex().upper()}")
    return True


async def _on_notify(sender, data: bytes):
    global _last_push_probes, _calibration_offsets, _last_marker, _last_battery_pct

    if _DEBUG:
        print(f"RX: {_fmt_hex(data)}")

    if len(data) < 2:
        return

    if _handle_raw_v5_packet(data):
        return

    is_control = (data[1] == 0x01) or (data[0] == 0xFF and data[1] == 0xFF)

    if is_control:
        msg = _extract_control_message(data)
        if msg is None:
            return
        cmd = msg['command']
        is_push = msg['source'] == 1
        src = 'PUSH' if is_push else 'RESP'

        if cmd == CC.PROBE_TEMPERATURE_RESPONSE:
            if is_push:
                probes = _parse_probe_temperatures(msg['payload_content'])
                _last_push_probes = probes
                _print_temps(probes, 'PUSH', msg['rx_tsn'])
            else:
                # RESP frames (button-press response) use per-probe masking.
                unmasked = _unmask_resp_payload(msg['payload_content'])
                probes = _parse_probe_temperatures(unmasked)
                _last_push_probes = probes
                _print_temps(probes, 'RESP', msg['rx_tsn'])

        elif cmd == CC.BATTERY_LEVEL_RESPONSE:
            if msg['payload_content']:
                level = msg['payload_content'][0]
                display_level = max(0, min(100, level))
                label = 'LOW' if display_level < 30 else ('OK' if display_level < 70 else 'FULL')
                _last_battery_pct = display_level
                if level != display_level:
                    print(f"BATTERY [{src}]: {level}% (raw) -> {display_level}% ({label})")
                else:
                    print(f"BATTERY [{src}]: {display_level}% ({label})")
            else:
                print(f"BATTERY [{src}]: (no payload)")

        elif cmd == CC.TEMPERATURE_UNIT_RESPONSE:
            unit = 'Fahrenheit' if (msg['payload_content'] and msg['payload_content'][0]) else 'Celsius'
            print(f"TEMP_UNIT [{src}]: {unit}")

        elif cmd == CC.TEMPERATURE_CALIBRATION_RESPONSE:
            cals = _parse_calibration_response(msg['payload_content'])
            _calibration_offsets = [c['celsius'] for c in cals] + [0.0] * (4 - len(cals))
            cal_str = '  '.join(f"P{i+1}={c['celsius']:+.0f}°C/{c['fahrenheit']:+.0f}°F"
                                for i, c in enumerate(cals))
            print(f"CALIBRATION [{src}]: {cal_str}")

        elif cmd == CC.ADVANCE_ALARM_RESPONSE:
            p = msg['payload_content']
            if len(p) >= 3:
                print(f"ADVANCE_ALARM [{src}]: enabled={p[0]==1} celsius={p[1]} fahrenheit={p[2]}")
            else:
                print(f"ADVANCE_ALARM [{src}]: payload={p.hex().upper()}")

        elif cmd == CC.COMMON_RESPONSE:
            if len(msg['payload_content']) >= 2:
                status = struct.unpack_from('<H', msg['payload_content'])[0]
            else:
                status = '?'
            msg['status'] = status
            print(f"COMMON_RESPONSE [{src}]: status={status}")

        else:
            print(f"CONTROL [{src}] [{msg['name']}] tsn={msg['rx_tsn']} "
                  f"payload={msg['payload_content'].hex().upper()}")

        # Resolve any pending GET/SET request future regardless of response type.
        # The device echoes our tx_tsn back as rx_tsn, but the same logical
        # ticket is also tracked under (tsn ^ XOR_KEY[1]).
        _finish_pending_response(msg['rx_tsn'], msg)
        _finish_pending_response(msg['rx_tsn'] ^ _XOR_KEY[1], msg)
        return

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
        asyncio.create_task(_initial_probe_request())
        return

    if cmd in (0x1D, 0x22):
        return

    print(f"UNKNOWN cmd=0x{cmd:02X} data={data.hex().upper()}")


async def _on_notify2(sender, data: bytes):
    if _DEBUG:
        print(f"RX2: {_fmt_hex(data)}")
    _handle_raw_v5_packet(data)


async def _poll_loop():
    while True:
        await asyncio.sleep(POLL_INTERVAL)
        if _client and _client.is_connected:
            if time.monotonic() - _last_ticket_mono < POLL_INTERVAL * 2:
                continue
            try:
                await _send_control(CC.PROBE_TEMPERATURE_REQUEST, need_response=True)
            except TimeoutError as e:
                print(f"Probe temperature request skipped: {e}")


async def _initial_probe_request():
    await asyncio.sleep(0.5)
    if not (_client and _client.is_connected):
        return
    try:
        await _send_control(CC.PROBE_TEMPERATURE_REQUEST, need_response=True)
        print("Probe temperature requested")
    except TimeoutError as e:
        print(f"Initial probe temperature request skipped: {e}")

    await asyncio.sleep(0.5)
    for cmd, label in [
        (CC.BATTERY_LEVEL_REQUEST,           "Battery level"),
        (CC.TEMPERATURE_UNIT_REQUEST,        "Temperature unit"),
        (CC.TEMPERATURE_CALIBRATION_REQUEST, "Calibration"),
    ]:
        if not (_client and _client.is_connected):
            break
        try:
            await _send_control(cmd, need_response=True)
            print(f"{label} requested")
        except TimeoutError as e:
            print(f"{label} request skipped: {e}")
        await asyncio.sleep(0.3)
    print()


# ---------------------------------------------------------------------------
# High-level command functions
# ---------------------------------------------------------------------------

async def set_probe_alarm(probe: int, temp_c: int | None):
    await _set_probe_preset(probe, temp_c, temp_c)


async def set_probe_range_alarm(probe: int, lower_c: int, upper_c: int):
    await _set_probe_preset(probe, lower_c, upper_c)


async def _set_probe_preset(probe: int, lower_c: int | None, upper_c: int | None):
    if not (1 <= probe <= 4):
        print(f"Error: probe must be 1-4, got {probe}")
        return
    if lower_c is not None and not (0 <= lower_c <= 300):
        print(f"Error: lower temp {lower_c} out of range")
        return
    if upper_c is not None and not (0 <= upper_c <= 300):
        print(f"Error: upper temp {upper_c} out of range")
        return

    _alarm_targets[probe - 1] = upper_c
    payload = _build_probe_alarm_payload(probe, lower_c, upper_c)

    if lower_c == upper_c:
        label = f"{upper_c}°C" if upper_c is not None else "disabled"
    else:
        label = f"{lower_c}–{upper_c}°C"

    try:
        response = await _send_adaptive_control(CC.PROBE_PRESET_SETTING, payload, timeout=7.0)
    except TimeoutError as e:
        print(f"ALARM P{probe}: {e}")
        return

    if response.get('command') != CC.COMMON_RESPONSE:
        name = response.get('name', f"0x{response.get('command', 0):04X}")
        print(f"ALARM P{probe}: unexpected response {name}; status={response.get('status')}")
        return

    status = response.get('status')
    if status == 0:
        print(f"PROBE ALARM SET P{probe}: {label}")
    else:
        print(f"PROBE ALARM P{probe}: {label} rejected, status={status}")


async def set_temp_unit(use_fahrenheit: bool):
    payload = bytes([1 if use_fahrenheit else 0])
    label = "Fahrenheit" if use_fahrenheit else "Celsius"

    try:
        response = await _send_adaptive_control(CC.TEMPERATURE_UNIT_SETTING, payload, timeout=7.0)
    except TimeoutError as e:
        print(f"UNIT: {e}")
        return

    # Accept either a COMMON_RESPONSE (status) or a TEMPERATURE_UNIT_RESPONSE
    resp_cmd = response.get('command')
    if resp_cmd == CC.COMMON_RESPONSE:
        status = response.get('status')
        if status == 0:
            print(f"UNIT SET: {label}")
        else:
            print(f"UNIT: {label} rejected, status={status}")
        return

    if resp_cmd == CC.TEMPERATURE_UNIT_RESPONSE:
        p = response.get('payload_content') or b''
        unit = 'Fahrenheit' if (len(p) >= 1 and p[0]) else 'Celsius'
        print(f"UNIT SET (response): {unit}")
        return

    print(f"UNIT: unexpected response {response.get('name')}")

async def set_range_alarm(lower_c: int | None, upper_c: int | None):
    payload = _build_advance_alarm_payload(lower_c, upper_c)
    if lower_c is None and upper_c is None:
        label = "disabled"
    else:
        lo_str = f"{lower_c}°C" if lower_c is not None else "none"
        hi_str = f"{upper_c}°C" if upper_c is not None else "none"
        label = f"{lo_str}–{hi_str}"

    try:
        response = await _send_adaptive_control(
            CC.ADVANCE_ALARM_SETTING, payload, timeout=7.0)
    except TimeoutError as e:
        print(f"RANGE_ALARM: {e}")
        return

    if response.get('command') != CC.COMMON_RESPONSE:
        print(f"RANGE_ALARM: unexpected response {response.get('name')}")
        return

    status = response.get('status')
    if status == 0:
        print(f"RANGE_ALARM SET: {label}")
    else:
        print(f"RANGE_ALARM: {label} rejected, status={status}")


async def set_probe_calibration(probe: int, offset_c: float):
    if not (1 <= probe <= 4):
        raise ValueError(f"probe must be 1-4, got {probe}")
    if not (-15 <= offset_c <= 15):
        raise ValueError(f"calibration offset must be -15..+15 °C, got {offset_c}")

    _calibration_offsets[probe - 1] = offset_c
    payload = _build_calibration_payload(_calibration_offsets)

    try:
        response = await _send_adaptive_control(
            CC.TEMPERATURE_CALIBRATION_SETTING, payload, timeout=7.0)
    except TimeoutError as e:
        print(f"CALIBRATION: {e}")
        return

    if response.get('command') != CC.COMMON_RESPONSE:
        print(f"CALIBRATION P{probe}: unexpected response {response.get('name')}")
        return

    status = response.get('status')
    if status == 0:
        print(f"CALIBRATION SET P{probe}: {offset_c:+.1f}°C")
    else:
        print(f"CALIBRATION P{probe}: {offset_c:+.1f}°C rejected, status={status}")


async def request_battery():
    try:
        await _send_control(CC.BATTERY_LEVEL_REQUEST, need_response=True)
    except TimeoutError as e:
        print(f"BATTERY request skipped: {e}")


# ---------------------------------------------------------------------------
# Input loop
# ---------------------------------------------------------------------------

_HELP = """\
Commands:
  <temp>                   target alarm probe 1 (°C, 0-300)
  <probe>:<temp>           target alarm for probe 1-4
  <probe>:off              disable target alarm for probe
  <probe>:<lo>-<hi>        per-probe range alarm (e.g. 1:20-30)
  <probe>:cal:<off>        set calibration offset °C (e.g. 2:cal:-3)
  <probe>:cal:0            clear calibration for probe
  unit:C  / unit:F         set temperature display unit
  battery                  request battery level
  exit                     exit the script
  help                     show this help

Run with --debug (or -d) to print RX/TX hex frames.\
"""


async def _input_loop():
    global _awaiting_input
    loop = asyncio.get_event_loop()
    print(_HELP)
    while True:
        try:
            _awaiting_input = True
            sys.stdout.write("cmd> ")
            sys.stdout.flush()
            line = await loop.run_in_executor(None, input)
            _awaiting_input = False
        except Exception:
            _awaiting_input = False
            break
        line = line.strip()
        if line.lower() == 'exit':
            print("Exiting...")
            _exit_event.set()
            break

        if not line:
            continue
        if line.lower() == 'help':
            print(_HELP)
            continue

        # battery
        if line.lower() == 'battery':
            if _client and _client.is_connected:
                await request_battery()
            else:
                print("Not connected")
            continue

        # unit:C / unit:F
        if line.lower().startswith('unit:'):
            unit_str = line[5:].strip().upper()
            if unit_str not in ('C', 'F'):
                print("Usage: unit:C  or  unit:F")
                continue
            if _client and _client.is_connected:
                await set_temp_unit(unit_str == 'F')
            else:
                print("Not connected")
            continue

        # off as alias for 1:off
        if line.lower() == 'off':
            line = '1:off'

        # probe-prefixed commands
        if ':' in line:
            parts = line.split(':', 2)
            try:
                probe = int(parts[0].strip())
            except ValueError:
                print("Usage: <probe>:<cmd>  (probe = 1-4)")
                continue

            if not (1 <= probe <= 4):
                print("Probe must be 1-4")
                continue

            rhs = parts[1].strip()

            # calibration: <probe>:cal:<offset>
            if rhs.startswith('cal:'):
                offset_str = rhs[4:].strip()
                try:
                    offset_c = float(offset_str)
                except ValueError:
                    print("Offset must be a number (e.g. 2:cal:-3)")
                    continue
                if _client and _client.is_connected:
                    await set_probe_calibration(probe, offset_c)
                else:
                    _calibration_offsets[probe - 1] = offset_c
                    print(f"CALIBRATION P{probe} queued: {offset_c:+.1f}°C (not connected yet)")
                continue

            # target alarm off: <probe>:off
            if rhs.lower() == 'off':
                temp = None
                if _client and _client.is_connected:
                    await set_probe_alarm(probe, temp)
                else:
                    _alarm_targets[probe - 1] = temp
                    print(f"ALARM P{probe} queued: disabled (not connected yet)")
                continue

            # per-probe range alarm: <probe>:<lo>-<hi>
            if '-' in rhs:
                try:
                    lo_s, hi_s = rhs.split('-', 1)
                    lower_c, upper_c = int(lo_s.strip()), int(hi_s.strip())
                    if not (0 <= lower_c <= 300 and 0 <= upper_c <= 300):
                        raise ValueError
                    if lower_c >= upper_c:
                        print(f"Lower ({lower_c}) must be less than upper ({upper_c})")
                        continue
                except ValueError:
                    print("Usage: <probe>:<lo>-<hi>  (e.g. 1:20-30)")
                    continue
                if _client and _client.is_connected:
                    await set_probe_range_alarm(probe, lower_c, upper_c)
                else:
                    print("Not connected")
                continue

            # target alarm: <probe>:<temp>
            try:
                temp = int(rhs)
                if not (0 <= temp <= 300):
                    print(f"Temperature must be 0-300°C (got {temp})")
                    continue
            except ValueError:
                print("Usage: <probe>:<temp>  or  <probe>:off  or  <probe>:cal:<offset>  or  <probe>:<lo>-<hi>")
                continue

            if _client and _client.is_connected:
                await set_probe_alarm(probe, temp)
            else:
                _alarm_targets[probe - 1] = temp
                print(f"ALARM P{probe} queued: {temp}°C (not connected yet)")
            continue

        # plain <temp> → probe 1 target alarm
        try:
            temp = int(line)
            if not (0 <= temp <= 300):
                print(f"Temperature must be 0-300°C (got {temp})")
                continue
        except ValueError:
            print("Unknown command. Type 'help' for usage.")
            continue

        if _client and _client.is_connected:
            await set_probe_alarm(1, temp)
        else:
            _alarm_targets[0] = temp
            print(f"ALARM P1 queued: {temp}°C (not connected yet)")


async def main():
    global _client, _tx_tsn, _last_push_probes, _ticket_queue, _last_ticket, _exit_event

    print(f"Sonoff BMT01 version 2026-05-06 rev B — connecting to {MAC}")
    print(f"XOR key (MD5 raw bytes): {_XOR_KEY.hex()}\n")
    _ticket_queue = asyncio.Queue(maxsize=1)
    _exit_event = asyncio.Event()

    input_task = asyncio.create_task(_input_loop())

    while True:
        _tx_tsn = 0
        _last_push_probes = None
        _last_ticket = None
        _pending_ticket_responses.clear()
        while _ticket_queue is not None:
            try:
                _ticket_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        try:
            client = BleakClient(MAC, timeout=20)
            try:
                await client.connect(timeout=20)
            except Exception as e:
                raise
            _client = client
            print("Connected")

            try:
                await client.start_notify(NOTIFY_UUID, _on_notify)
                try:
                    await client.start_notify(NOTIFY_UUID2, _on_notify2)
                    print("bbb3 subscribed")
                except Exception:
                    pass

                await _send_auth_frame(0x00, _aes_encrypt(APP_UUID).encode())
                print("AUTH: request sent\n")

                poll_task = asyncio.create_task(_poll_loop())
                try:
                    while client.is_connected:
                        if _exit_event.is_set():
                            print("Exit requested — stopping notifications...")
                            try:
                                await client.stop_notify(NOTIFY_UUID)
                            except Exception:
                                pass
                            try:
                                await client.stop_notify(NOTIFY_UUID2)
                            except Exception:
                                pass
                            break
                        await asyncio.sleep(1)
                finally:
                    poll_task.cancel()

            finally:
                # ensure we disconnect and clear client reference before continuing
                try:
                    if client.is_connected:
                        await client.disconnect()
                except Exception:
                    pass
                _client = None

            # If exit requested, do not attempt to reconnect — return cleanly
            if _exit_event.is_set():
                print("Exiting — clean shutdown.")
                return

            print("Disconnected — reconnecting in 3 s...")
            await asyncio.sleep(3)

        except BleakError as e:
            print(f"BLE error: {e} — retry in 5 s...")
            await asyncio.sleep(5)
        except KeyboardInterrupt:
            input_task.cancel()
            print("\nStopped.")
            return
        
        if _exit_event.is_set():
            input_task.cancel()
            print("\nClosed.")
            return


if __name__ == "__main__":
    asyncio.run(main())
