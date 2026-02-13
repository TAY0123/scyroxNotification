# Scyrox HID Tray Monitor

Standalone Rust app for Scyrox mouse/dongle HID monitoring.

It can:
- Enumerate compatible HID interfaces.
- Read battery, DPI, and polling rate.
- Run in system tray with battery icon updates.
- Show notifications for:
  - low battery (<= 20%)
  - DPI/polling changes (toggleable in tray menu)

## Features

- Protocol reimplemented from the vendor web app bundle.
- Device filter:
  - VID: `0x3554`
  - PID: `0xF5F7`, `0xF5F4`, `0xF5F6`
- Tray menu:
  - device selection
  - `Notify on DPI/polling changes` toggle
  - refresh devices
  - quit

## Requirements

- Rust stable toolchain
- Windows recommended for tray + HID use

## Build

```bash
cargo build --release
```

Binary output:

- `target/release/scyrox_hid_reader.exe`

## Run

Tray mode (default if no args):

```bash
cargo run -- tray
# or
cargo run
```

List candidate HID interfaces:

```bash
cargo run -- list
```

Read one-time values:

```bash
cargo run -- read
cargo run -- read --index 9
```

## Tray Config File

The tray app reads config from:

- `tray_config.toml` (current working directory)

If the file does not exist, it is auto-created with default settings:

```toml
poll_interval_secs = 5
```

Rules:
- `poll_interval_secs` controls tray polling interval.
- Value is clamped to `1..=3600`.
- Invalid config is replaced with default.

## Notifications

- Low battery notification triggers at `<= 20%`.
- DPI/polling-change notification is controlled by tray menu toggle.

## GitHub Actions Release (Manual)

Workflow file:

- `.github/workflows/windows-release.yml`

Trigger:
- GitHub Actions -> `Windows Release` -> `Run workflow`

Inputs:
- `tag` (example: `v1.0.0`)
- `release_name`
- `poll_interval_secs` (written into packaged `tray_config.toml`)

### Optional Signing Secrets

If these repository secrets are set, the exe is signed before upload:

- `WINDOWS_CERT_PFX_BASE64` (base64-encoded `.pfx`)
- `WINDOWS_CERT_PASSWORD`

If secrets are not set, build + release upload still runs, but signing steps are skipped.

## Project Structure

- `src/main.rs` - HID protocol, CLI, tray runtime, config loading
- `Cargo.toml` - dependencies and package config
- `.github/workflows/windows-release.yml` - manual Windows release pipeline

## License

Add your preferred license file if you plan to distribute publicly.
