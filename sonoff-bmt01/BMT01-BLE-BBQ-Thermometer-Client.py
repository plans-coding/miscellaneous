"""
eWeLink BMT01 BLE BBQ Thermometer Client version 2026-05-03 rev B
=================================================================
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
"""

import asyncio
import base64
import hashlib
import struct
import sys
import time
import uuid
import builtins
from datetime import datetime

from bleak import BleakClient, BleakError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    import readline
except ImportError:
    readline = None

_orig_print = builtins.print

def _async_print(*args, **kwargs):
    if kwargs.get('file', sys.stdout) in (None, sys.stdout):
        sys.stdout.write('\r\x1b[2K')
        _orig_print(*args, **kwargs)
        if readline:
            buf = readline.get_line_buffer()
            sys.stdout.write(f"Alarm input> {buf}")
        else:
            sys.stdout.write("Alarm input> ")
        sys.stdout.flush()
    else:
        _orig_print(*args, **kwargs)

builtins.print = _async_print

MAC        = "XX:XX:XX:XX:XX:XX"
DEVICE_KEY = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

NOTIFY_UUID  = "0000bbb1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID2 = "0000bbb3-0000-1000-8000-00805f9b34fb"  
WRITE_UUID   = "0000bbb0-0000-1000-8000-00805f9b34fb"

POLL_INTERVAL = 3   

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


def _unmask_resp_payload(payload_content: bytes) -> bytes:
    out = bytearray()
    for i, mask in enumerate(_RESP_PROBE_MASKS):
        ofs = i * 2
        if ofs + 1 >= len(payload_content):
            break
        out.append(payload_content[ofs]     ^ mask[0])
        out.append(payload_content[ofs + 1] ^ mask[1])
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


def _build_upper_alarm_payload(probe: int, temp_c: int | None, timer_ms: int = 0) -> bytes:
    wire_probe = probe - 1 + WIRE_PROBE_INDEX_BASE
    if temp_c is None:
        preset_type = PRESET_EMPTY
        lower_c = lower_f = upper_c = upper_f = NO_ALARM
    else:
        preset_type = PRESET_UPPER_TEMP
        upper_c = int(temp_c)
        upper_f = round(upper_c * 9 / 5 + 32)
        lower_c = upper_c
        lower_f = upper_f

    timer_seconds = int(timer_ms / 1000)
    return (
        bytes([wire_probe, preset_type])
        + _le16(lower_c)
        + _le16(lower_f)
        + _le16(upper_c)
        + _le16(upper_f)
        + _le16(timer_seconds)
        + bytes([int(timer_ms) & 0xFF])
    )


def _build_captured_alarm_payload(temp_c: int | None) -> bytes:
    if temp_c is None:
        values = [NO_ALARM, NO_ALARM, NO_ALARM, NO_ALARM]
    else:
        temp_f = round(temp_c * 9 / 5 + 32)
        values = [NO_ALARM, int(temp_c), int(temp_f), int(temp_c)]
    return _build_preset_payload(values)


async def set_probe_alarm(probe: int, temp_c: int | None):
    if not (1 <= probe <= 4):
        raise ValueError(f"probe must be 1-4, got {probe}")
    if temp_c is not None and not (20 <= temp_c <= 82):
        raise ValueError(f"temp_c must be 20-82 C, got {temp_c}")

    _alarm_targets[probe - 1] = temp_c
    payload = _build_upper_alarm_payload(probe, temp_c)

    try:
        response = await _send_outputjs_alarm_control(payload, timeout=7.0)
    except TimeoutError as e:
        print(f"ALARM: {e} — command was sent but no ACK arrived")
        return

    label = f"{temp_c}°C" if temp_c is not None else "disabled"
    if response.get('command') != CC.COMMON_RESPONSE:
        name = response.get('name', f"0x{response.get('command', 0):04X}")
        print(f"ALARM P{probe}: unexpected response {name}; not marking as set")
        return

    status = response.get('status')
    if status == 0:
        print(f"ALARM SET P{probe}: {label}")
    else:
        print(f"ALARM P{probe}: {label} rejected, response status={status}")


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
    source          =  flags & 0x01          
    need_response   = (flags >> 1) & 0x01    
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


def _build_ticketed_frame(command: int, ticket: int, payload_content: bytes = b'') -> bytes:
    raw_payload = bytes([0x89, ticket]) + payload_content
    return struct.pack('<HH', command, len(raw_payload)) + raw_payload


def _build_captured_alarm_frame(ticket: int, payload_content: bytes) -> bytes:
    raw_payload = bytes([0xEB, ticket ^ _XOR_KEY[1]]) + payload_content
    encrypted = _xor_crypt(raw_payload)
    return struct.pack('<HH', CC.PROBE_PRESET_SETTING, len(encrypted)) + encrypted


def _build_outputjs_alarm_frame(ticket: int, payload_content: bytes) -> tuple[bytes, int]:
    token_tsn = ticket ^ _XOR_KEY[1]
    frame = _build_control_frame(
        CC.PROBE_PRESET_SETTING,
        need_response=True,
        payload_content=payload_content,
        token_tsn=token_tsn,
    )
    return frame, token_tsn


def _live_ticket_marker(data: bytes) -> int | None:
    if len(data) >= 6 and data[:4] == b'\x04\x01\x0A\x00' and data[4] in (0x82, 0xD4):
        return data[4]
    return None


def _offer_ticket(ticket: int):
    global _last_ticket, _last_ticket_mono
    _last_ticket = ticket
    _last_ticket_mono = time.monotonic()
    if _ticket_queue is None:
        return
    try:
        _ticket_queue.put_nowait(ticket)
    except asyncio.QueueFull:
        try:
            _ticket_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        _ticket_queue.put_nowait(ticket)


async def _next_ticket(timeout: float = 5.0) -> int:
    if _ticket_queue is None:
        raise TimeoutError("ticket queue is not ready")
    try:
        return await asyncio.wait_for(_ticket_queue.get(), timeout=timeout)
    except asyncio.TimeoutError as e:
        raise TimeoutError("timeout waiting for fresh live telemetry ticket") from e


def _parse_raw_ticket_response(data: bytes) -> dict | None:
    if len(data) < 6 or data[4] != 0x8E:
        return None
    command = struct.unpack_from('<H', data, 0)[0]
    data_length = struct.unpack_from('<H', data, 2)[0]
    payload = data[4:]
    if data_length != len(payload):
        print(f"[WARN] raw frame length mismatch: expected={data_length} got={len(payload)}")
        return None
    content = bytes(payload[2:])
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


async def _send_ticketed_control(command: int, payload_content: bytes = b'',
                                 timeout: float = 5.0) -> dict:
    ticket = await _next_ticket(timeout=timeout)
    frame = _build_ticketed_frame(command, ticket, payload_content)

    loop = asyncio.get_running_loop()
    response_future: asyncio.Future[dict] = loop.create_future()
    _pending_ticket_responses[ticket] = response_future
    print(f"TX ticket=0x{ticket:02X}: {_fmt_hex(frame)}")
    try:
        await _ble_write(frame)
        try:
            return await asyncio.wait_for(response_future, timeout=timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"timeout waiting for response to ticket 0x{ticket:02X}") from e
    finally:
        _pending_ticket_responses.pop(ticket, None)


async def _send_captured_alarm_control(payload_content: bytes,
                                       timeout: float = 5.0) -> dict:
    ticket = await _next_ticket(timeout=timeout)
    frame = _build_captured_alarm_frame(ticket, payload_content)

    loop = asyncio.get_running_loop()
    response_future: asyncio.Future[dict] = loop.create_future()
    _pending_ticket_responses[ticket] = response_future
    print(f"TX captured-alarm ticket=0x{ticket:02X}: {_fmt_hex(frame)}")
    try:
        await _ble_write(frame)
        try:
            return await asyncio.wait_for(response_future, timeout=timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"timeout waiting for response to ticket 0x{ticket:02X}") from e
    finally:
        _pending_ticket_responses.pop(ticket, None)


async def _send_outputjs_alarm_control(payload_content: bytes,
                                       timeout: float = 5.0) -> dict:
    ticket = await _next_ticket(timeout=timeout)
    frame, token_tsn = _build_outputjs_alarm_frame(ticket, payload_content)

    loop = asyncio.get_running_loop()
    response_future: asyncio.Future[dict] = loop.create_future()
    _pending_ticket_responses[token_tsn] = response_future
    _pending_ticket_responses[ticket] = response_future
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
    return f"{label}={p['temp_c']:.0f}°C({p['temp_f']:.1f}°F)"


def _print_temps(probes: list[dict], tag: str, tsn: int):
    now = datetime.now().strftime('%H:%M:%S')
    probe_str = '  '.join(_fmt_probe(p, f'P{i+1}') for i, p in enumerate(probes))
    print(f"TEMP [{now}] {tag} tsn={tsn:3d}  {probe_str}")


def _handle_raw_v5_packet(data: bytes) -> bool:
    global _last_push_probes

    marker = _live_ticket_marker(data)
    if marker is not None:
        ticket = data[5]
        _offer_ticket(ticket)
        print(f"TICKET fresh: marker=0x{marker:02X} ticket=0x{ticket:02X}")

        if marker == 0xD4:
            return False

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
        level = payload[0] if payload else '?'
        print(f"BATTERY [RAW] ticket=0x{ticket:02X}: {level}%")
    elif cmd == CC.PROBE_TEMPERATURE_RESPONSE:
        probes = _parse_probe_temperatures(payload)
        _last_push_probes = probes
        _print_temps(probes, 'RESP', ticket)
    elif cmd == CC.TEMPERATURE_UNIT_RESPONSE:
        unit = 'Fahrenheit' if payload and payload[0] else 'Celsius'
        print(f"TEMP_UNIT [RAW] ticket=0x{ticket:02X}: {unit}")
    elif cmd == CC.COMMON_RESPONSE:
        print(f"COMMON_RESPONSE [RAW] ticket=0x{ticket:02X}: status={raw_response['status']}")
    else:
        print(f"CONTROL [RAW] [{raw_response['name']}] ticket=0x{ticket:02X} "
              f"payload={payload.hex().upper()}")
    return True


async def _on_notify(sender, data: bytes):
    global _last_push_probes

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
            msg['status'] = status
            _finish_pending_response(msg['rx_tsn'], msg)
            _finish_pending_response(msg['rx_tsn'] ^ _XOR_KEY[1], msg)
            print(f"COMMON_RESPONSE [{src}]: status={status}")

        else:
            print(f"CONTROL [{src}] [{msg['name']}] tsn={msg['rx_tsn']} "
                  f"payload={msg['payload_content'].hex().upper()}")
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
    if _client and _client.is_connected:
        try:
            await _send_control(CC.PROBE_TEMPERATURE_REQUEST, need_response=True)
            print("Probe temperature requested\n")
        except TimeoutError as e:
            print(f"Initial probe temperature request skipped: {e}\n")


async def _input_loop():
    loop = asyncio.get_event_loop()
    print("Alarm input: <temp 20-82> for probe 1, or <probe:temp>, or <probe:off>")
    while True:
        try:
            line = await loop.run_in_executor(None, input, "Alarm input> ")
        except Exception:
            break
        line = line.strip()
        if not line:
            continue
        try:
            if ':' in line:
                p_str, t_str = line.split(':', 1)
                probe = int(p_str.strip())
                t_str = t_str.strip()
            else:
                probe = 1
                t_str = line.strip()
            
            if t_str.lower() == 'off':
                temp = None
            else:
                temp = int(t_str)
                if not (20 <= temp <= 82):
                    print(f"Temperature must be 20-82°C (got {temp})")
                    continue
        except ValueError:
            print("Usage: <temp>  or  <probe:temp>  or  <probe:off>")
            continue
        
        if _client and _client.is_connected:
            await set_probe_alarm(probe, temp)
        else:
            _alarm_targets[probe - 1] = temp
            label = f"{temp}°C" if temp is not None else "disabled"
            print(f"ALARM P{probe} queued: {label} (not connected yet)")


async def main():
    global _client, _tx_tsn, _last_push_probes, _ticket_queue, _last_ticket

    print(f"BMT01 version 2026-05-03 rev B — connecting to {MAC}")
    print(f"XOR key (MD5 raw bytes): {_XOR_KEY.hex()}\n")
    _ticket_queue = asyncio.Queue(maxsize=1)

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
            async with BleakClient(MAC, timeout=20) as client:
                _client = client
                print("Connected")

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
                        await asyncio.sleep(1)
                finally:
                    poll_task.cancel()

                print("Disconnected — reconnecting in 3 s...")
                await asyncio.sleep(3)

        except BleakError as e:
            print(f"BLE error: {e} — retry in 5 s...")
            await asyncio.sleep(5)
        except KeyboardInterrupt:
            input_task.cancel()
            print("\nStopped.")
            return


if __name__ == "__main__":
    asyncio.run(main())
