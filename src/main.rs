use hidapi::{DeviceInfo, HidApi, HidDevice};
use std::env;
use std::error::Error;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type AnyError = Box<dyn Error + Send + Sync>;

const VENDOR_ID: u16 = 0x3554;
const PRODUCT_IDS: [u16; 3] = [0xF5F7, 0xF5F4, 0xF5F6];

const REPORT_ID: u8 = 8;

const CMD_ENCRYPTION: u8 = 1;
const CMD_PC_DRIVER_STATUS: u8 = 2;
const CMD_DEVICE_ONLINE: u8 = 3;
const CMD_BATTERY_LEVEL: u8 = 4;
const CMD_READ_FLASH: u8 = 8;
const MAX_RETRIES: usize = 8;
const DEFAULT_TIMEOUT_MS: u64 = 350;
const FLASH_TIMEOUT_MS: u64 = 600;

#[derive(Debug, Clone, Copy)]
struct BatteryReadout {
    level: u8,
    charging: bool,
    voltage_mv: u16,
}

#[derive(Debug, Clone)]
struct DeviceIdentity {
    vendor_id: u16,
    product_id: u16,
    interface_number: i32,
    usage_page: u16,
    usage: u16,
    path: String,
    product: Option<String>,
}

#[derive(Debug)]
struct ReadResult {
    cid: u8,
    mid: u8,
    device_type: u8,
    online: bool,
    battery: Option<BatteryReadout>,
    polling_hz: u32,
    max_dpi_profiles: u8,
    current_dpi_slot: u8,
    current_dpi: u32,
    dpi_slots: [u32; 8],
}

fn main() -> Result<(), AnyError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return Ok(());
    }

    match args[1].as_str() {
        "list" => {
            let do_probe = !args[2..].iter().any(|a| a == "--no-probe");
            cmd_list(do_probe)?;
        }
        "read" => {
            let index = parse_index_arg(&args[2..])?;
            cmd_read(index)?;
        }
        _ => {
            print_help();
        }
    }

    Ok(())
}

fn print_help() {
    println!("scyrox_hid_reader");
    println!();
    println!("Usage:");
    println!("  scyrox_hid_reader list [--no-probe]");
    println!("  scyrox_hid_reader read [--index N]");
    println!();
    println!("Notes:");
    println!(
        "  - Filters default to VID=0x{VENDOR_ID:04X} and PIDs={}.",
        product_ids_hex()
    );
    println!("  - `list` probes each interface and highlights the recommended one.");
    println!("  - `read` fetches battery, polling rate, and DPI from the device.");
}

fn parse_index_arg(args: &[String]) -> Result<Option<usize>, AnyError> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--index" {
            if i + 1 >= args.len() {
                return Err("missing value for --index".into());
            }
            let parsed = args[i + 1].parse::<usize>()?;
            return Ok(Some(parsed));
        }
        if let Some(value) = args[i].strip_prefix("--index=") {
            let parsed = value.parse::<usize>()?;
            return Ok(Some(parsed));
        }
        i += 1;
    }
    Ok(None)
}

fn cmd_list(do_probe: bool) -> Result<(), AnyError> {
    let api = HidApi::new()?;
    let candidates = collect_candidates(&api);

    println!(
        "Target filter: VID=0x{VENDOR_ID:04X}, PIDs={}",
        product_ids_hex()
    );
    println!("Found {} matching HID interface(s).", candidates.len());
    println!();

    if candidates.is_empty() {
        println!("No matching HID devices found.");
        return Ok(());
    }

    let mut recommended: Option<usize> = None;
    for (index, info) in candidates.iter().enumerate() {
        let identity = identity_from_info(info);
        println!(
            "[{index}] VID:PID {:04X}:{:04X} iface={} usage={:04X}:{:04X}",
            identity.vendor_id,
            identity.product_id,
            identity.interface_number,
            identity.usage_page,
            identity.usage
        );
        println!(
            "    product={} path={}",
            identity.product.as_deref().unwrap_or("-"),
            identity.path
        );

        if do_probe {
            match probe_candidate(&api, info) {
                Ok(online) => {
                    println!("    probe=OK (protocol response), online={online}");
                    if recommended.is_none() {
                        recommended = Some(index);
                    }
                }
                Err(err) => {
                    println!("    probe=FAIL ({err})");
                }
            }
        }
    }

    println!();
    if do_probe {
        if let Some(index) = recommended {
            println!("Recommended interface index: {index}");
        } else {
            println!(
                "No responsive protocol interface found. Try `read --index N` on a listed item."
            );
        }
    } else {
        println!("Probe skipped. Re-run without `--no-probe` for recommendation.");
    }
    Ok(())
}

fn cmd_read(index: Option<usize>) -> Result<(), AnyError> {
    let api = HidApi::new()?;
    let (selected_index, device, identity) = match index {
        Some(i) => {
            let info = candidate_by_index(&api, i)?;
            let identity = identity_from_info(info);
            let device = api.open_path(info.path())?;
            (i, device, identity)
        }
        None => auto_select_device(&api)?,
    };

    println!(
        "Using interface [{}] VID:PID {:04X}:{:04X} iface={} usage={:04X}:{:04X}",
        selected_index,
        identity.vendor_id,
        identity.product_id,
        identity.interface_number,
        identity.usage_page,
        identity.usage
    );
    println!("Path: {}", identity.path);
    println!();

    let result = read_device(&device)?;

    println!(
        "Handshake: CID={}, MID={}, type={}",
        result.cid, result.mid, result.device_type
    );
    println!("Online: {}", result.online);

    match result.battery {
        Some(bat) => {
            println!(
                "Battery: level={}%, charging={}, voltage={}mV",
                bat.level, bat.charging, bat.voltage_mv
            );
        }
        None => {
            println!("Battery: unavailable (device reported offline)");
        }
    }

    println!("Polling rate: {} Hz", result.polling_hz);
    println!(
        "Current DPI: slot={} value={}",
        result.current_dpi_slot, result.current_dpi
    );
    println!("DPI slots: {:?}", result.dpi_slots);
    println!("Max DPI profiles (raw): {}", result.max_dpi_profiles);
    Ok(())
}

fn collect_candidates(api: &HidApi) -> Vec<&DeviceInfo> {
    api.device_list().filter(|d| is_target_device(d)).collect()
}

fn is_target_device(info: &DeviceInfo) -> bool {
    info.vendor_id() == VENDOR_ID && PRODUCT_IDS.contains(&info.product_id())
}

fn candidate_by_index<'a>(api: &'a HidApi, index: usize) -> Result<&'a DeviceInfo, AnyError> {
    let candidates = collect_candidates(api);
    candidates
        .get(index)
        .copied()
        .ok_or_else(|| format!("index {index} is out of range").into())
}

fn identity_from_info(info: &DeviceInfo) -> DeviceIdentity {
    DeviceIdentity {
        vendor_id: info.vendor_id(),
        product_id: info.product_id(),
        interface_number: info.interface_number(),
        usage_page: info.usage_page(),
        usage: info.usage(),
        path: info.path().to_string_lossy().into_owned(),
        product: info.product_string().map(|s| s.to_owned()),
    }
}

fn probe_candidate(api: &HidApi, info: &DeviceInfo) -> Result<bool, AnyError> {
    let device = api.open_path(info.path())?;
    drain_input(&device);
    get_online(&device)
}

fn auto_select_device(api: &HidApi) -> Result<(usize, HidDevice, DeviceIdentity), AnyError> {
    let candidates = collect_candidates(api);
    for (index, info) in candidates.iter().enumerate() {
        let Ok(device) = api.open_path(info.path()) else {
            continue;
        };
        drain_input(&device);
        if get_online(&device).is_ok() {
            return Ok((index, device, identity_from_info(info)));
        }
    }
    Err(
        "failed to auto-select a responsive interface; run `list` and choose --index manually"
            .into(),
    )
}

fn read_device(device: &HidDevice) -> Result<ReadResult, AnyError> {
    drain_input(device);

    let online = get_online(device)?;
    let _ = set_pc_driver_status(device, 1);
    let (cid, mid, device_type) = run_encryption(device)?;
    let flash = read_flash(device)?;
    let battery = if online {
        Some(get_battery(device)?)
    } else {
        None
    };
    let mut dpi_slots = [0u32; 8];
    for (slot, dpi_value) in dpi_slots.iter_mut().enumerate() {
        *dpi_value = decode_dpi(&flash, slot);
    }

    let current_dpi_slot = flash.get(4).copied().unwrap_or(0);
    let current_slot_index = usize::from(current_dpi_slot);
    let current_dpi = dpi_slots
        .get(current_slot_index)
        .copied()
        .or_else(|| {
            current_slot_index
                .checked_sub(1)
                .and_then(|i| dpi_slots.get(i).copied())
        })
        .unwrap_or(0);

    Ok(ReadResult {
        cid,
        mid,
        device_type,
        online,
        battery,
        polling_hz: decode_polling_hz(flash[0]),
        max_dpi_profiles: flash[2],
        current_dpi_slot,
        current_dpi,
        dpi_slots,
    })
}

fn set_pc_driver_status(device: &HidDevice, status: u8) -> Result<(), AnyError> {
    let _ = send_command_with_payload(device, CMD_PC_DRIVER_STATUS, &[status])?;
    Ok(())
}

fn get_online(device: &HidDevice) -> Result<bool, AnyError> {
    let response = send_command(device, CMD_DEVICE_ONLINE)?;
    Ok(response[5] == 1)
}

fn get_battery(device: &HidDevice) -> Result<BatteryReadout, AnyError> {
    let response = send_command(device, CMD_BATTERY_LEVEL)?;
    Ok(BatteryReadout {
        level: response[5],
        charging: response[6] == 1,
        voltage_mv: u16::from(response[7]) << 8 | u16::from(response[8]),
    })
}

fn run_encryption(device: &HidDevice) -> Result<(u8, u8, u8), AnyError> {
    let payload = make_encryption_payload();
    let response = send_command_with_payload(device, CMD_ENCRYPTION, &payload)?;
    Ok((response[9], response[10], response[11]))
}

fn make_encryption_payload() -> [u8; 8] {
    let mut payload = [0u8; 8];
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xA5A5_5A5A_DEAD_BEEF);

    for b in payload.iter_mut().take(4) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = (state & 0xFF) as u8;
    }
    payload
}

fn read_flash(device: &HidDevice) -> Result<Vec<u8>, AnyError> {
    let mut flash = vec![0u8; 260];
    drain_input(device);
    for addr in (0u16..260u16).step_by(10) {
        let request = build_read_flash_packet(addr, 10);
        let response = exchange(device, request, Duration::from_millis(FLASH_TIMEOUT_MS))?;
        let offset = usize::from(addr);
        flash[offset..offset + 10].copy_from_slice(&response[5..15]);
        thread::sleep(Duration::from_millis(2));
    }
    Ok(flash)
}

fn decode_polling_hz(raw: u8) -> u32 {
    if raw == 0 {
        return 0;
    }
    if raw >= 16 {
        (u32::from(raw) / 16) * 2000
    } else {
        1000 / u32::from(raw)
    }
}

fn decode_dpi(flash: &[u8], slot: usize) -> u32 {
    let index = 4 * slot + 12;
    if index + 2 >= flash.len() {
        return 0;
    }
    let upper_bits = u16::from((flash[index + 2] & 0x0C) >> 2);
    let raw = u16::from(flash[index]) + (upper_bits << 8);
    u32::from(raw + 1) * 50
}

fn send_command(device: &HidDevice, command: u8) -> Result<[u8; 16], AnyError> {
    let request = build_packet(command, &[])?;
    exchange(device, request, Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

fn send_command_with_payload(
    device: &HidDevice,
    command: u8,
    payload: &[u8],
) -> Result<[u8; 16], AnyError> {
    let request = build_packet(command, payload)?;
    exchange(device, request, Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

fn build_packet(command: u8, payload: &[u8]) -> Result<[u8; 16], AnyError> {
    if payload.len() > 10 {
        return Err("payload exceeds 10-byte protocol limit".into());
    }

    let mut packet = [0u8; 16];
    packet[0] = command;
    packet[4] = payload.len() as u8;
    packet[5..5 + payload.len()].copy_from_slice(payload);
    packet[15] = checksum(&packet);
    Ok(packet)
}

fn build_read_flash_packet(address: u16, length: u8) -> [u8; 16] {
    let mut packet = [0u8; 16];
    packet[0] = CMD_READ_FLASH;
    packet[2] = (address >> 8) as u8;
    packet[3] = (address & 0xFF) as u8;
    packet[4] = length;
    packet[15] = checksum(&packet);
    packet
}

fn checksum(packet: &[u8; 16]) -> u8 {
    let sum: u16 = packet[..15].iter().map(|b| u16::from(*b)).sum();
    let folded = (sum & 0xFF) as i16;
    ((85 - folded - i16::from(REPORT_ID)) & 0xFF) as u8
}

fn write_packet(device: &HidDevice, packet: &[u8; 16]) -> Result<(), AnyError> {
    let mut report = [0u8; 17];
    report[0] = REPORT_ID;
    report[1..].copy_from_slice(packet);
    let written = device.write(&report)?;
    if written == 0 {
        return Err("hid write returned 0 bytes".into());
    }
    Ok(())
}

fn exchange(
    device: &HidDevice,
    request: [u8; 16],
    timeout: Duration,
) -> Result<[u8; 16], AnyError> {
    for _ in 0..MAX_RETRIES {
        write_packet(device, &request)?;
        let start = Instant::now();
        let mut buffer = [0u8; 64];

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            let wait_ms = remaining.as_millis().min(30) as i32;
            let bytes_read = device.read_timeout(&mut buffer, wait_ms)?;
            if bytes_read == 0 {
                continue;
            }
            for frame in candidate_frames(&buffer, bytes_read) {
                if response_matches(&request, &frame) {
                    return Ok(frame);
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    Err(format!("no valid response for command {}", request[0]).into())
}

fn candidate_frames(raw: &[u8], bytes_read: usize) -> Vec<[u8; 16]> {
    let mut frames = Vec::new();

    if bytes_read >= 18 && raw[1] == REPORT_ID {
        let mut frame = [0u8; 16];
        frame.copy_from_slice(&raw[2..18]);
        frames.push(frame);
    }

    if bytes_read >= 17 && (raw[0] == REPORT_ID || raw[0] == 0) {
        let mut frame = [0u8; 16];
        frame.copy_from_slice(&raw[1..17]);
        if frames.iter().all(|seen| seen != &frame) {
            frames.push(frame);
        }
    }

    if bytes_read >= 16 {
        let mut frame = [0u8; 16];
        frame.copy_from_slice(&raw[0..16]);
        if frames.iter().all(|seen| seen != &frame) {
            frames.push(frame);
        }
    }

    frames
}

fn response_matches(request: &[u8; 16], response: &[u8; 16]) -> bool {
    if request[0] == CMD_READ_FLASH {
        request[..5] == response[..5]
    } else {
        request[..3] == response[..3]
    }
}

fn drain_input(device: &HidDevice) {
    let mut buffer = [0u8; 64];
    while let Ok(size) = device.read_timeout(&mut buffer, 1) {
        if size == 0 {
            break;
        }
    }
}

fn product_ids_hex() -> String {
    PRODUCT_IDS
        .iter()
        .map(|pid| format!("0x{pid:04X}"))
        .collect::<Vec<_>>()
        .join(",")
}
