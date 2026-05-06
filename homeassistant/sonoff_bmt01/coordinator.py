"""BLE coordinator for Sonoff BMT01 — protocol ported from bmt01_v9.py."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import struct
import time

from bleak import BleakClient, BleakError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    DOMAIN,
    NOTIFY_UUID,
    NOTIFY_UUID2,
    WRITE_UUID,
    POLL_INTERVAL,
    PROBE_SENTINELS,
    RESP_SECONDARY_KEY,
    D2_PROBE_MASKS,
    CC_BATTERY_LEVEL_REQUEST,
    CC_BATTERY_LEVEL_RESPONSE,
    CC_PROBE_TEMPERATURE_REQUEST,
    CC_PROBE_TEMPERATURE_RESPONSE,
    CC_PROBE_PRESET_SETTING,
    CC_TEMPERATURE_CALIBRATION_SETTING,
    CC_TEMPERATURE_CALIBRATION_REQUEST,
    CC_TEMPERATURE_CALIBRATION_RESPONSE,
    CC_ADVANCE_ALARM_SETTING,
    CC_TEMPERATURE_UNIT_REQUEST,
    CC_TEMPERATURE_UNIT_RESPONSE,
    CC_TEMPERATURE_UNIT_SETTING,
    CC_COMMON_RESPONSE,
    CC_NAMES,
    NO_ALARM,
    PRESET_EMPTY,
    PRESET_UPPER_TEMP,
    PRESET_RANGE,
)

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------

class BMT01Coordinator(DataUpdateCoordinator):
    """Manages BLE connection and protocol for a single BMT01 device."""

    def __init__(self, hass: HomeAssistant, mac: str, device_key: str, app_uuid: str) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{mac}",
            # No polling — data comes via BLE push notifications
            update_interval=None,
        )

        self.mac        = mac
        self.device_key = device_key
        self.app_uuid   = app_uuid

        # Crypto keys (same derivation as bmt01_v9.py)
        self._aes_key = bytes.fromhex(hashlib.md5(device_key.encode()).hexdigest())
        self._aes_iv  = b"0000000000000000"
        self._xor_key = hashlib.md5(device_key.encode()).digest()

        # Per-probe RESP masks (same derivation as _RESP_PROBE_MASKS in v9)
        self._resp_probe_masks = [
            bytes([
                self._xor_key[2 + i * 2]     ^ RESP_SECONDARY_KEY[i * 2],
                self._xor_key[3 + i * 2]     ^ RESP_SECONDARY_KEY[i * 2 + 1],
            ])
            for i in range(4)
        ]

        # Runtime state
        self._client:    BleakClient | None = None
        self._tx_tsn     = 0
        self._last_marker: int | None = None
        self._ticket_queue: asyncio.Queue[int] = asyncio.Queue(maxsize=1)
        self._last_ticket_mono = 0.0
        self._pending: dict[int, asyncio.Future[dict]] = {}
        self._stop_event = asyncio.Event()
        self._ble_task:  asyncio.Task | None = None
        self._alarm_targets: list[int | None] = [None, None, None, None]
        self._calibration_offsets: list[float]  = [0.0, 0.0, 0.0, 0.0]

        # The coordinator's `data` dict:
        # {
        #   "connected": bool,
        #   "probes": [{"status": str, "temp_c": float|None, "temp_f": float|None}, ...] * 4,
        #   "battery": int|None,
        #   "temp_unit": "C"|"F",
        # }
        self.data = {
            "connected": False,
            "probes":    [{"status": "not_active", "temp_c": None, "temp_f": None}] * 4,
            "battery":   None,
            "temp_unit": "C",
        }

    # -----------------------------------------------------------------------
    # HA lifecycle
    # -----------------------------------------------------------------------

    async def async_start(self) -> None:
        """Start BLE background task."""
        self._stop_event.clear()
        self._ble_task = self.hass.async_create_task(self._ble_loop())

    async def async_stop(self) -> None:
        """Stop BLE background task and disconnect."""
        self._stop_event.set()
        if self._ble_task:
            self._ble_task.cancel()
            try:
                await self._ble_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._client and self._client.is_connected:
            try:
                await self._client.disconnect()
            except Exception:
                pass
        self._client = None

    # -----------------------------------------------------------------------
    # BLE connection loop (mirrors main() in bmt01_v9.py)
    # -----------------------------------------------------------------------

    async def _ble_loop(self) -> None:
        """Connect, authenticate, receive notifications; reconnect on drop."""
        while not self._stop_event.is_set():
            self._tx_tsn   = 0
            self._last_marker = None
            self._pending.clear()
            self._drain_ticket_queue()

            try:
                async with BleakClient(self.mac, timeout=20) as client:
                    self._client = client
                    _LOGGER.info("BMT01 connected to %s", self.mac)
                    self._update_connected(True)

                    await client.start_notify(NOTIFY_UUID, self._on_notify)
                    try:
                        await client.start_notify(NOTIFY_UUID2, self._on_notify2)
                    except Exception:
                        pass

                    # Send auth request
                    await self._send_auth_frame(0x00, self._aes_encrypt(self.app_uuid).encode())

                    poll_task = asyncio.create_task(self._poll_loop())
                    try:
                        while client.is_connected and not self._stop_event.is_set():
                            await asyncio.sleep(1)
                    finally:
                        poll_task.cancel()
                        try:
                            await poll_task
                        except asyncio.CancelledError:
                            pass

            except (BleakError, asyncio.TimeoutError, OSError) as exc:
                _LOGGER.warning("BMT01 BLE error: %s — retry in 5 s", exc)
                self._update_connected(False)
                await asyncio.sleep(5)
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _LOGGER.exception("BMT01 unexpected error: %s", exc)
                self._update_connected(False)
                await asyncio.sleep(10)
                continue

            self._client = None
            if not self._stop_event.is_set():
                _LOGGER.info("BMT01 disconnected — reconnecting in 3 s")
                self._update_connected(False)
                await asyncio.sleep(3)

    async def _poll_loop(self) -> None:
        """Fallback poller if device stops sending live telemetry."""
        while True:
            await asyncio.sleep(POLL_INTERVAL)
            if not (self._client and self._client.is_connected):
                return
            if time.monotonic() - self._last_ticket_mono < POLL_INTERVAL * 2:
                continue
            try:
                await self._send_control(CC_PROBE_TEMPERATURE_REQUEST, need_response=True)
            except TimeoutError:
                pass

    async def _initial_requests(self) -> None:
        """Fetch temperatures, battery and settings right after auth."""
        await asyncio.sleep(0.5)
        if not (self._client and self._client.is_connected):
            return
        for cmd, label in [
            (CC_PROBE_TEMPERATURE_REQUEST,        "probe temperature"),
            (CC_BATTERY_LEVEL_REQUEST,            "battery"),
            (CC_TEMPERATURE_UNIT_REQUEST,         "temperature unit"),
            (CC_TEMPERATURE_CALIBRATION_REQUEST,  "calibration"),
        ]:
            if not (self._client and self._client.is_connected):
                break
            try:
                await self._send_control(cmd, need_response=True)
                _LOGGER.debug("Requested %s", label)
            except TimeoutError:
                _LOGGER.debug("Request timed out: %s", label)
            await asyncio.sleep(0.3)

    def _update_connected(self, connected: bool) -> None:
        new_data = dict(self.data)
        new_data["connected"] = connected
        self.async_set_updated_data(new_data)

    def _push_data(self) -> None:
        self.async_set_updated_data(dict(self.data))

    # -----------------------------------------------------------------------
    # Notification handlers (mirrors _on_notify / _on_notify2 in v9)
    # -----------------------------------------------------------------------

    async def _on_notify(self, _sender, data: bytes) -> None:
        if len(data) < 2:
            return
        if self._handle_raw_v5_packet(data):
            return
        is_control = (data[1] == 0x01) or (data[0] == 0xFF and data[1] == 0xFF)
        if is_control:
            self._handle_control_message(data)
            return
        cmd = data[0]
        if cmd == 0x01 and data[1] == 0x00:
            await self._handle_auth_challenge(data)
        elif cmd == 0x03:
            await self._handle_auth_accepted()
        elif cmd in (0x1D, 0x22):
            pass
        else:
            _LOGGER.debug("UNKNOWN cmd=0x%02X data=%s", cmd, data.hex().upper())

    async def _on_notify2(self, _sender, data: bytes) -> None:
        self._handle_raw_v5_packet(data)

    async def _handle_auth_challenge(self, data: bytes) -> None:
        try:
            body         = data[4:].decode("ascii", errors="ignore").strip("\x00")
            device_uuid  = self._aes_decrypt(body)
            confirm      = self._aes_encrypt(f"{self.app_uuid}_{device_uuid}").encode()
            await self._send_auth_frame(0x02, confirm)
            _LOGGER.debug("AUTH: challenge response sent")
        except Exception as exc:
            _LOGGER.error("AUTH error: %s", exc)

    async def _handle_auth_accepted(self) -> None:
        _LOGGER.debug("AUTH: accepted")
        if self._client:
            await self._client.write_gatt_char(WRITE_UUID, bytes([0x21, 0x00, 0x00, 0x00]),
                                               response=False)
        self.hass.async_create_task(self._initial_requests())

    def _handle_raw_v5_packet(self, data: bytes) -> bool:
        """Handle raw-frame protocol (markers 0x82 / 0xD4 / 0xD2 / 0x8E / 0xDE)."""
        marker = self._live_ticket_marker(data)
        if marker is not None:
            self._last_marker = marker
            ticket = data[5]
            self._offer_ticket(ticket)

            if marker == 0xD4:
                return False  # let _handle_control_message decode XOR frame

            if marker == 0xD2:
                raw = self._unmask_d2_payload(data[6:])
                probes = self._parse_probe_temps(raw)
                self._set_probes(probes)
                return True

            # 0x82 raw push — no masking
            probes = self._parse_probe_temps(data[6:])
            self._set_probes(probes)
            return True

        raw_resp = self._parse_raw_ticket_response(data)
        if raw_resp is None:
            return False

        ticket  = raw_resp["ticket"]
        self._finish_pending(ticket, raw_resp)

        cmd     = raw_resp["command"]
        payload = raw_resp["payload_content"]

        if cmd == CC_BATTERY_LEVEL_RESPONSE and payload:
            self._set_battery(payload[0])
        elif cmd == CC_TEMPERATURE_CALIBRATION_RESPONSE:
            self._calibration_offsets = self._parse_calibration_offsets(payload)
        elif cmd == CC_TEMPERATURE_UNIT_RESPONSE and payload:
            unit = "F" if payload[0] else "C"
            self.data["temp_unit"] = unit
            self._push_data()

        return True

    def _handle_control_message(self, data: bytes) -> None:
        """Decode and dispatch XOR-encrypted control frames."""
        msg = self._extract_control_message(data)
        if msg is None:
            return

        cmd     = msg["command"]
        is_push = msg["source"] == 1
        payload = msg["payload_content"]

        if cmd == CC_PROBE_TEMPERATURE_RESPONSE:
            if is_push:
                probes = self._parse_probe_temps(payload)
            else:
                probes = self._parse_probe_temps(self._unmask_resp_payload(payload))
            self._set_probes(probes)

        elif cmd == CC_BATTERY_LEVEL_RESPONSE and payload:
            self._set_battery(payload[0])

        elif cmd == CC_TEMPERATURE_UNIT_RESPONSE and payload:
            unit = "F" if payload[0] else "C"
            self.data["temp_unit"] = unit
            self._push_data()

        elif cmd == CC_TEMPERATURE_CALIBRATION_RESPONSE:
            self._calibration_offsets = self._parse_calibration_offsets(payload)

        elif cmd == CC_COMMON_RESPONSE:
            if len(payload) >= 2:
                msg["status"] = struct.unpack_from("<H", payload)[0]

        self._finish_pending(msg["rx_tsn"], msg)
        self._finish_pending(msg["rx_tsn"] ^ self._xor_key[1], msg)

    # -----------------------------------------------------------------------
    # State helpers
    # -----------------------------------------------------------------------

    def _set_probes(self, probes: list[dict]) -> None:
        self.data["probes"] = probes
        self._push_data()

    def _set_battery(self, raw: int) -> None:
        level = max(0, min(100, raw))
        self.data["battery"] = level
        self._push_data()
        _LOGGER.debug("Battery: %d%%", level)

    # -----------------------------------------------------------------------
    # Ticket management (mirrors _offer_ticket / _next_ticket in v9)
    # -----------------------------------------------------------------------

    def _drain_ticket_queue(self) -> None:
        while True:
            try:
                self._ticket_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    def _offer_ticket(self, ticket: int) -> None:
        self._last_ticket_mono = time.monotonic()
        try:
            self._ticket_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        self._ticket_queue.put_nowait(ticket)

    async def _next_ticket(self, timeout: float = 5.0) -> int:
        try:
            self._ticket_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            return await asyncio.wait_for(self._ticket_queue.get(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError("timeout waiting for live telemetry ticket") from exc

    def _finish_pending(self, ticket: int, msg: dict) -> None:
        future = self._pending.get(ticket)
        if future and not future.done():
            future.set_result(msg)

    # -----------------------------------------------------------------------
    # Frame sending (mirrors _send_adaptive_control / _send_ticketed_control etc.)
    # -----------------------------------------------------------------------

    async def _send_adaptive_control(self, command: int, payload: bytes = b"",
                                     timeout: float = 7.0) -> dict:
        if self._last_marker == 0xD4:
            return await self._send_outputjs_control(command, payload, timeout=timeout)
        return await self._send_ticketed_control(command, payload, timeout=timeout)

    async def _send_ticketed_control(self, command: int, payload: bytes = b"",
                                     timeout: float = 5.0) -> dict:
        ticket = await self._next_ticket(timeout=timeout)
        frame  = self._build_ticketed_frame(command, ticket, payload)
        loop   = asyncio.get_running_loop()
        future: asyncio.Future[dict] = loop.create_future()
        self._pending[ticket] = future
        try:
            await self._ble_write(frame)
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(f"timeout on ticket 0x{ticket:02X}") from exc
        finally:
            self._pending.pop(ticket, None)

    async def _send_outputjs_control(self, command: int, payload: bytes,
                                     timeout: float = 7.0) -> dict:
        ticket    = await self._next_ticket(timeout=timeout)
        frame, tsn = self._build_outputjs_control_frame(command, ticket, payload)
        loop      = asyncio.get_running_loop()
        future: asyncio.Future[dict] = loop.create_future()
        self._pending[tsn] = future
        try:
            await self._ble_write(frame)
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError(f"timeout on outputjs cmd={command} ticket=0x{ticket:02X}") from exc
        finally:
            self._pending.pop(tsn, None)

    async def _send_control(self, command: int, need_response: bool = True,
                            payload: bytes = b"") -> None:
        if need_response:
            if self._last_marker == 0xD4:
                await self._send_outputjs_control(command, payload)
            else:
                await self._send_ticketed_control(command, payload)
            return
        frame = self._build_control_frame(command, False, payload)
        await self._ble_write(frame)

    async def _send_auth_frame(self, msg_type: int, body: bytes) -> None:
        header = bytes([msg_type, 0x00]) + struct.pack("<H", len(body))
        await self._ble_write(header + body)

    async def _ble_write(self, data: bytes) -> None:
        if self._client is None:
            return
        for i in range(0, len(data), 20):
            await self._client.write_gatt_char(WRITE_UUID, data[i:i + 20], response=False)
            await asyncio.sleep(0.05)

    # -----------------------------------------------------------------------
    # Frame builders (mirrors v9 exactly)
    # -----------------------------------------------------------------------

    def _next_tsn(self) -> int:
        tsn = self._tx_tsn
        self._tx_tsn = (self._tx_tsn + 1) % 256
        return tsn

    def _build_control_frame(self, command: int, need_response: bool = True,
                              payload_content: bytes = b"",
                              token_tsn: int | None = None) -> bytes:
        flags    = (0 << 0) | ((1 if need_response else 0) << 1)
        tx_tsn   = token_tsn if token_tsn is not None else self._next_tsn()
        raw      = bytes([flags, tx_tsn]) + payload_content
        enc      = self._xor_crypt(raw)
        return struct.pack("<HH", command, len(enc)) + enc

    def _command_marker_for_state(self) -> int:
        if self._last_marker in (0xD2, 0xDE):
            return 0xD9
        return 0x89

    def _mask_d9_payload(self, content: bytes) -> bytes:
        mask = D2_PROBE_MASKS[0]
        return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(content))

    def _build_ticketed_frame(self, command: int, ticket: int,
                               payload_content: bytes = b"",
                               marker: int | None = None) -> bytes:
        if marker is None:
            marker = self._command_marker_for_state()
        if marker == 0xD9 and payload_content:
            payload_content = self._mask_d9_payload(payload_content)
        raw = bytes([marker, ticket]) + payload_content
        return struct.pack("<HH", command, len(raw)) + raw

    def _build_outputjs_control_frame(self, command: int, ticket: int,
                                       payload_content: bytes) -> tuple[bytes, int]:
        token_tsn = ticket ^ self._xor_key[1]
        frame = self._build_control_frame(command, True, payload_content, token_tsn)
        return frame, token_tsn

    # -----------------------------------------------------------------------
    # Payload builders (mirrors v9)
    # -----------------------------------------------------------------------

    def _build_preset_payload(self, targets: list[int | None]) -> bytes:
        probe = bytearray()
        for i in range(4):
            t  = NO_ALARM if (i >= len(targets) or targets[i] is None) else int(targets[i])
            lo, hi = t & 0xFF, (t >> 8) & 0xFF
            probe.append(lo ^ self._resp_probe_masks[i][0])
            probe.append(hi ^ self._resp_probe_masks[i][1])
        x0 = 0xDA
        for b in probe:
            x0 ^= b
        return bytes(probe) + bytes([x0, 0x1E, 0x60, 0xA8])

    def _build_probe_alarm_payload(self, probe: int,
                                   lower_c: int | None, upper_c: int | None) -> bytes:
        wire = probe - 1
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
            bytes([wire, preset_type])
            + struct.pack("<H", l_c) + struct.pack("<H", l_f)
            + struct.pack("<H", u_c) + struct.pack("<H", u_f)
            + struct.pack("<H", 0)  + bytes([0])
        )

    def _build_advance_alarm_payload(self, lower_c: int | None, upper_c: int | None) -> bytes:
        if lower_c is None and upper_c is None:
            return bytes([0, 0, 0, 0, 0])
        lower = lower_c if lower_c is not None else 0xFFFF
        upper = upper_c if upper_c is not None else 0xFFFF
        return struct.pack("<B", 1) + struct.pack("<H", lower) + struct.pack("<H", upper)

    def _build_calibration_payload(self, offsets_c: list[float]) -> bytes:
        payload = bytearray()
        for i in range(4):
            oc = offsets_c[i] if i < len(offsets_c) else 0.0
            of_ = round(oc * 9 / 5)
            payload += self._calibration_value_to_bytes(oc)
            payload += self._calibration_value_to_bytes(float(of_))
        return bytes(payload)

    # -----------------------------------------------------------------------
    # Parsers (mirrors v9)
    # -----------------------------------------------------------------------

    def _live_ticket_marker(self, data: bytes) -> int | None:
        if len(data) >= 6 and data[:4] == b"\x04\x01\x0A\x00" and data[4] in (0x82, 0xD4, 0xD2):
            return data[4]
        return None

    def _parse_raw_ticket_response(self, data: bytes) -> dict | None:
        if len(data) < 6 or data[4] not in (0x8E, 0xDE):
            return None
        command     = struct.unpack_from("<H", data, 0)[0]
        data_length = struct.unpack_from("<H", data, 2)[0]
        payload     = data[4:]
        if data_length != len(payload):
            return None
        content = bytes(payload[2:])
        if payload[0] == 0xDE:
            content = self._unmask_de_payload(content)
        msg: dict = {
            "command":         command,
            "name":            CC_NAMES.get(command, f"0x{command:04X}"),
            "marker":          payload[0],
            "ticket":          payload[1],
            "payload_content": content,
            "status":          None,
        }
        if command == CC_COMMON_RESPONSE and len(content) >= 2:
            msg["status"] = struct.unpack_from("<H", content, 0)[0]
        return msg

    def _extract_control_message(self, data: bytes) -> dict | None:
        if len(data) < 4:
            return None
        command     = struct.unpack_from("<H", data, 0)[0]
        data_length = struct.unpack_from("<H", data, 2)[0]
        decrypted   = self._xor_crypt(data[4:])
        if data_length != len(decrypted):
            return None
        flags   = decrypted[0]
        return {
            "command":         command,
            "name":            CC_NAMES.get(command, f"0x{command:04X}"),
            "flags":           flags,
            "source":          flags & 0x01,
            "need_response":   (flags >> 1) & 0x01,
            "rx_tsn":          decrypted[1],
            "payload_content": bytes(decrypted[2:]),
            "status":          None,
        }

    def _parse_probe_temps(self, payload: bytes) -> list[dict]:
        probes = []
        for i in range(0, len(payload) - 1, 2):
            raw  = struct.unpack_from("<H", payload, i)[0]
            sentinel = PROBE_SENTINELS.get(raw)
            if sentinel:
                probes.append({"status": sentinel, "temp_c": None, "temp_f": None})
            else:
                temp_c = float(raw)
                probes.append({
                    "status": "ok",
                    "temp_c": temp_c,
                    "temp_f": round(temp_c * 9 / 5 + 32, 1),
                })
        # Pad to 4 probes
        while len(probes) < 4:
            probes.append({"status": "not_active", "temp_c": None, "temp_f": None})
        return probes[:4]

    def _parse_calibration_offsets(self, payload: bytes) -> list[float]:
        offsets = []
        for i in range(4):
            ofs = i * 4
            if ofs + 1 >= len(payload):
                offsets.append(0.0)
                continue
            lo, hi = payload[ofs], payload[ofs + 1]
            positive  = bool(hi & 0x80)
            magnitude = lo | ((hi & 0x7F) << 8)
            offsets.append(float(magnitude) if positive else -float(magnitude))
        return offsets

    # -----------------------------------------------------------------------
    # Crypto helpers (mirrors v9)
    # -----------------------------------------------------------------------

    def _aes_encrypt(self, plaintext: str) -> str:
        pad    = 16 - (len(plaintext) % 16)
        padded = plaintext.encode() + bytes([pad] * pad)
        cipher = Cipher(algorithms.AES(self._aes_key), modes.CBC(self._aes_iv))
        enc    = cipher.encryptor()
        return base64.b64encode(enc.update(padded) + enc.finalize()).decode()

    def _aes_decrypt(self, b64: str) -> str:
        ct     = base64.b64decode(b64)
        cipher = Cipher(algorithms.AES(self._aes_key), modes.CBC(self._aes_iv))
        dec    = cipher.decryptor()
        raw    = dec.update(ct) + dec.finalize()
        return raw[:-raw[-1]].decode()

    def _xor_crypt(self, data: bytes) -> bytes:
        out = bytearray()
        for start in range(0, len(data), 16):
            block = data[start:start + 16]
            for i, b in enumerate(block):
                out.append(b ^ self._xor_key[i])
        return bytes(out)

    def _unmask_resp_payload(self, payload_content: bytes) -> bytes:
        out = bytearray()
        for i, mask in enumerate(self._resp_probe_masks):
            ofs = i * 2
            if ofs + 1 >= len(payload_content):
                break
            out.append(payload_content[ofs]     ^ mask[0])
            out.append(payload_content[ofs + 1] ^ mask[1])
        return bytes(out)

    def _unmask_d2_payload(self, raw: bytes) -> bytes:
        out = bytearray()
        for i, mask in enumerate(D2_PROBE_MASKS):
            ofs = i * 2
            if ofs + 1 >= len(raw):
                break
            out.append(raw[ofs]     ^ mask[0])
            out.append(raw[ofs + 1] ^ mask[1])
        return bytes(out)

    def _unmask_de_payload(self, content: bytes) -> bytes:
        mask = D2_PROBE_MASKS[0]
        return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(content))

    def _calibration_value_to_bytes(self, value: float) -> bytes:
        abs_val = min(int(round(abs(value))), 0x7FFF)
        lo = abs_val & 0xFF
        hi = (abs_val >> 8) & 0x7F
        if value >= 0:
            hi |= 0x80
        return bytes([lo, hi])

    # -----------------------------------------------------------------------
    # Public command API (used by services and UI)
    # -----------------------------------------------------------------------

    async def set_probe_alarm(self, probe: int, temp_c: int | None) -> str:
        """Set target alarm for a single probe (None = disable)."""
        return await self._set_probe_preset(probe, temp_c, temp_c)

    async def set_probe_range_alarm(self, probe: int, lower_c: int, upper_c: int) -> str:
        return await self._set_probe_preset(probe, lower_c, upper_c)

    async def _set_probe_preset(self, probe: int, lower_c: int | None,
                                 upper_c: int | None) -> str:
        if not (1 <= probe <= 4):
            return f"Error: probe must be 1-4, got {probe}"
        payload = self._build_probe_alarm_payload(probe, lower_c, upper_c)
        try:
            response = await self._send_adaptive_control(CC_PROBE_PRESET_SETTING, payload)
        except TimeoutError as exc:
            return str(exc)
        status = response.get("status")
        if response.get("command") == CC_COMMON_RESPONSE and status == 0:
            label = f"{upper_c}°C" if upper_c is not None else "disabled"
            return f"P{probe} alarm set: {label}"
        return f"P{probe} alarm rejected, status={status}"

    async def set_temperature_unit(self, use_fahrenheit: bool) -> str:
        payload = bytes([1 if use_fahrenheit else 0])
        try:
            response = await self._send_adaptive_control(CC_TEMPERATURE_UNIT_SETTING, payload)
        except TimeoutError as exc:
            return str(exc)
        label = "Fahrenheit" if use_fahrenheit else "Celsius"
        if response.get("command") in (CC_COMMON_RESPONSE, CC_TEMPERATURE_UNIT_RESPONSE):
            self.data["temp_unit"] = "F" if use_fahrenheit else "C"
            self._push_data()
            return f"Unit set: {label}"
        return f"Unit set failed: {response.get('name')}"

    async def set_probe_calibration(self, probe: int, offset_c: float) -> str:
        if not (1 <= probe <= 4):
            return f"Error: probe must be 1-4"
        if not (-15 <= offset_c <= 15):
            return f"Error: offset must be -15..+15 °C"
        self._calibration_offsets[probe - 1] = offset_c
        payload = self._build_calibration_payload(self._calibration_offsets)
        try:
            response = await self._send_adaptive_control(CC_TEMPERATURE_CALIBRATION_SETTING,
                                                          payload)
        except TimeoutError as exc:
            return str(exc)
        status = response.get("status")
        if response.get("command") == CC_COMMON_RESPONSE and status == 0:
            return f"P{probe} calibration: {offset_c:+.1f}°C"
        return f"P{probe} calibration rejected, status={status}"

    async def request_battery(self) -> None:
        try:
            await self._send_control(CC_BATTERY_LEVEL_REQUEST, need_response=True)
        except TimeoutError:
            pass
