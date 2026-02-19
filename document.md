# Scyrox Web App JS Guide (Beginner Friendly)

This document explains how the bundled web app JavaScript talks to the mouse, and how the same logic is implemented in Rust in this repo.

It focuses on two practical things:
- How values are **read** from an attached mouse.
- How values are **set** on an attached mouse.

## 1) Quick project structure

- `app.918085c0.js`
  - Main web app bundle (Vue UI + WebHID protocol logic).
  - This is minified, so function names are short.
- `chunk-vendors.68c197cc.js`
  - Third-party libraries (Vue, UI libraries, etc.).
- `src/main.rs`
  - Rust reimplementation of the same protocol (cleaner to read).

## 2) How the JS app is organized

In `app.918085c0.js`, the important protocol pieces are:

- Device transport and connection:
  - `ie(filters)` -> opens WebHID device (`navigator.hid.requestDevice`).
  - `re()` -> installs `oninputreport` handler and parses responses.
  - `ue(packet)` -> sends a packet and waits for matching response.
- Command helpers:
  - `de(cmd, payload)` -> send command with payload.
  - `he(cmd)` -> send command without payload.
- Read flow:
  - `Ve()` -> reads flash memory in 10-byte blocks.
  - `Oe()` -> decodes flash bytes into settings (report rate, DPI, etc.).
- Write flow:
  - `Me(addr, bytes)` -> write array to flash.
  - `Re(addr, value)` -> write report rate style value (`value`, `85-value` pair).
  - `Te(addr, len)` -> read a specific flash range.

State objects in JS:
- `ee` -> connection/device runtime state (online, battery, CID/MID, firmware).
- `te` -> decoded mouse settings (report rate, DPI slots, sensor options).
- `z` -> command IDs.
- `B` -> flash memory addresses.

## 3) Core protocol basics

The app sends a 16-byte command payload to HID **report ID = 8**.

Packet format:
- Byte `0`: command ID.
- Bytes `2..3`: flash address (for read/write flash commands).
- Byte `4`: payload length.
- Bytes `5..14`: payload data.
- Byte `15`: checksum.

Checksum logic (same as Rust):
- `checksum = (85 - (sum(packet[0..14]) & 0xFF) - report_id) & 0xFF`
- report ID is `8`.

## 4) Read values from attached mouse

Typical JS read sequence after device is selected:

1. Check online status: `DeviceOnLine` command (`3`).
2. Set PC driver status: `PCDriverStatus` command (`2`) with payload `[1]`.
3. Run encryption handshake: `EncryptionData` command (`1`).
4. Read flash blocks: `ReadFlashData` command (`8`), addresses `0..255` in chunks.
5. Decode flash bytes into settings (`Oe()`):
   - report rate from flash byte `0`
   - current DPI slot from byte `4`
   - DPI slots from offset `12` onward
6. Read battery: `BatteryLevel` command (`4`):
   - `response[5]` = battery level (%)
   - `response[6]` = charging flag
   - `response[7..8]` = battery voltage

## 5) Set values on attached mouse

Example: set polling/report rate.

1. Encode Hz to protocol value:
   - 125->8, 250->4, 500->2, 1000->1, 2000->16, 4000->32, 8000->64
2. Send `WriteFlashData` command (`7`) to flash address `0` (`ReportRate`).
3. Payload format used by app/Rust:
   - byte 5 = encoded value
   - byte 6 = `85 - encoded`
4. Read back current config to confirm (`ReadFlashData` or full refresh).

## 6) JS -> Rust mapping in this repo

- JS `ie()` -> Rust device selection/open in `src/main.rs` (`scan_candidates`, `open_path`).
- JS `ue()/de()/he()` -> Rust `exchange()`, `send_command()`, `send_command_with_payload()`.
- JS `Ve()` -> Rust `read_flash()`.
- JS `Oe()` -> Rust `decode_polling_hz()` + `decode_dpi()`.
- JS `Re()` -> Rust `set_polling_rate()`.
- JS command map `z` -> Rust `CMD_*` constants.
- JS address map `B` -> Rust flash offsets (for example report rate at address `0`).

## 7) Rust example: read battery + polling + DPI

This is a minimal educational example (same protocol style as the app):

```rust
use hidapi::{HidApi, HidDevice};
use std::error::Error;
use std::thread;
use std::time::{Duration, Instant};

const VID: u16 = 0x3554;
const PIDS: [u16; 3] = [0xF5F7, 0xF5F4, 0xF5F6];
const REPORT_ID: u8 = 8;

const CMD_ENCRYPTION: u8 = 1;
const CMD_PC_DRIVER_STATUS: u8 = 2;
const CMD_DEVICE_ONLINE: u8 = 3;
const CMD_BATTERY_LEVEL: u8 = 4;
const CMD_READ_FLASH: u8 = 8;

fn checksum(packet: &[u8; 16]) -> u8 {
    let sum: u16 = packet[..15].iter().map(|b| u16::from(*b)).sum();
    ((85i16 - (sum as i16 & 0xFF) - REPORT_ID as i16) & 0xFF) as u8
}

fn build_packet(cmd: u8, payload: &[u8]) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[0] = cmd;
    p[4] = payload.len() as u8;
    p[5..5 + payload.len()].copy_from_slice(payload);
    p[15] = checksum(&p);
    p
}

fn build_read_flash(addr: u16, len: u8) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[0] = CMD_READ_FLASH;
    p[2] = (addr >> 8) as u8;
    p[3] = (addr & 0xFF) as u8;
    p[4] = len;
    p[15] = checksum(&p);
    p
}

fn exchange(device: &HidDevice, req: [u8; 16]) -> Result<[u8; 16], Box<dyn Error>> {
    let mut report = [0u8; 17];
    report[0] = REPORT_ID;
    report[1..].copy_from_slice(&req);
    device.write(&report)?;

    let start = Instant::now();
    let mut buf = [0u8; 64];
    while start.elapsed() < Duration::from_millis(400) {
        let n = device.read_timeout(&mut buf, 20)?;
        if n == 0 {
            continue;
        }

        let mut frame = [0u8; 16];
        if n >= 17 && (buf[0] == REPORT_ID || buf[0] == 0) {
            frame.copy_from_slice(&buf[1..17]);
            return Ok(frame);
        }
        if n >= 16 {
            frame.copy_from_slice(&buf[0..16]);
            return Ok(frame);
        }
    }
    Err("timeout waiting response".into())
}

fn decode_polling_hz(raw: u8) -> u32 {
    if raw == 0 {
        0
    } else if raw >= 16 {
        (u32::from(raw) / 16) * 2000
    } else {
        1000 / u32::from(raw)
    }
}

fn decode_dpi(flash: &[u8], slot: usize) -> u32 {
    let i = 4 * slot + 12;
    let upper = u16::from((flash[i + 2] & 0x0C) >> 2);
    let raw = u16::from(flash[i]) + (upper << 8);
    u32::from(raw + 1) * 50
}

fn main() -> Result<(), Box<dyn Error>> {
    let api = HidApi::new()?;
    let info = api
        .device_list()
        .find(|d| d.vendor_id() == VID && PIDS.contains(&d.product_id()))
        .ok_or("no supported mouse found")?;
    let dev = api.open_path(info.path())?;

    let online = exchange(&dev, build_packet(CMD_DEVICE_ONLINE, &[]))?[5] == 1;
    if !online {
        return Err("device is offline".into());
    }

    let _ = exchange(&dev, build_packet(CMD_PC_DRIVER_STATUS, &[1]))?;
    let _ = exchange(&dev, build_packet(CMD_ENCRYPTION, &[1, 2, 3, 4, 0, 0, 0, 0]))?;

    let bat = exchange(&dev, build_packet(CMD_BATTERY_LEVEL, &[]))?;
    let level = bat[5];
    let charging = bat[6] == 1;

    let mut flash = vec![0u8; 260];
    for addr in (0u16..260u16).step_by(10) {
        let r = exchange(&dev, build_read_flash(addr, 10))?;
        let o = addr as usize;
        flash[o..o + 10].copy_from_slice(&r[5..15]);
        thread::sleep(Duration::from_millis(2));
    }

    let polling_hz = decode_polling_hz(flash[0]);
    let current_slot = flash[4] as usize;
    let current_dpi = decode_dpi(&flash, current_slot.min(7));

    println!("Battery: {}% (charging: {})", level, charging);
    println!("Polling: {} Hz", polling_hz);
    println!("Current DPI slot: {}", current_slot);
    println!("Current DPI: {}", current_dpi);
    Ok(())
}
```

## 8) Rust example: set polling rate

```rust
fn encode_polling_hz(hz: u32) -> Option<u8> {
    match hz {
        125 => Some(8),
        250 => Some(4),
        500 => Some(2),
        1000 => Some(1),
        2000 => Some(16),
        4000 => Some(32),
        8000 => Some(64),
        _ => None,
    }
}

fn set_polling_rate_packet(hz: u32) -> Option<[u8; 16]> {
    let encoded = encode_polling_hz(hz)?;
    let mut p = [0u8; 16];
    p[0] = 7; // CMD_WRITE_FLASH
    p[2] = 0; // address high byte (ReportRate address = 0)
    p[3] = 0; // address low byte
    p[4] = 2; // data length
    p[5] = encoded;
    p[6] = 85u8.wrapping_sub(encoded);
    p[15] = checksum(&p);
    Some(p)
}
```

Use with `exchange(&device, packet)` and then read back flash address `0` to verify.

## 9) Beginner tips

- If no values appear, the mouse may be sleeping. Move/click it, then retry.
- Always do the online check + handshake before reading/writing settings.
- After writing, read the value back to confirm.
- If you need production-ready logic, use the existing robust implementation in `src/main.rs`.
