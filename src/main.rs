use hidapi::{DeviceInfo, HidApi, HidDevice};
use notify_rust::Notification;
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

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
const LOW_BATTERY_THRESHOLD: u8 = 20;
const POLL_INTERVAL_SECS: u64 = 5;

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

#[derive(Debug, Clone)]
struct CandidateDevice {
    path: CString,
    identity: DeviceIdentity,
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

#[derive(Debug)]
enum UserEvent {
    Tray,
    Menu(tray_icon::menu::MenuEvent),
}

struct TrayMenuState {
    menu: Menu,
    status_item: MenuItem,
    device_paths: Vec<CString>,
    notify_changes_item: CheckMenuItem,
    refresh_item: MenuItem,
    quit_item: MenuItem,
}

struct TrayRuntime {
    api: HidApi,
    tray_icon: Option<TrayIcon>,
    menu_state: TrayMenuState,
    selected_device_path: Option<CString>,
    notify_on_change: bool,
    low_battery_notified: bool,
    last_report: Option<ReadResult>,
    status_text: String,
    next_poll: Instant,
}

fn main() -> Result<(), AnyError> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        run_tray_mode()?;
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
        "tray" => {
            run_tray_mode()?;
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
    println!("  scyrox_hid_reader tray");
    println!("  scyrox_hid_reader list [--no-probe]");
    println!("  scyrox_hid_reader read [--index N]");
    println!();
    println!("Notes:");
    println!(
        "  - Filters default to VID=0x{VENDOR_ID:04X} and PIDs={}.",
        product_ids_hex()
    );
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

fn run_tray_mode() -> Result<(), AnyError> {
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = event;
        let _ = proxy.send_event(UserEvent::Tray);
    }));

    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Menu(event));
    }));

    let mut app = TrayRuntime::new()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::WaitUntil(app.next_poll);

        match event {
            Event::NewEvents(cause) => {
                if matches!(cause, StartCause::Init) {
                    if let Err(err) = app.create_tray_icon() {
                        eprintln!("failed to create tray icon: {err}");
                        *control_flow = ControlFlow::Exit;
                        return;
                    }
                    app.poll_once();
                } else if matches!(cause, StartCause::ResumeTimeReached { .. }) {
                    app.poll_once();
                }
                *control_flow = ControlFlow::WaitUntil(app.next_poll);
            }
            Event::UserEvent(UserEvent::Menu(menu_event)) => {
                if app.handle_menu_event(menu_event) {
                    app.tray_icon.take();
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::UserEvent(UserEvent::Tray) => {}
            _ => {}
        }
    });
}

impl TrayRuntime {
    fn new() -> Result<Self, AnyError> {
        let mut api = HidApi::new()?;
        api.refresh_devices()?;

        let selected_device_path = first_responsive_device_path(&api);
        let status_text = "Status: starting...".to_string();
        let notify_on_change = true;

        let menu_state = build_tray_menu(
            &api,
            selected_device_path.as_ref(),
            notify_on_change,
            &status_text,
        )?;

        Ok(Self {
            api,
            tray_icon: None,
            menu_state,
            selected_device_path,
            notify_on_change,
            low_battery_notified: false,
            last_report: None,
            status_text,
            next_poll: Instant::now() + Duration::from_secs(1),
        })
    }

    fn create_tray_icon(&mut self) -> Result<(), AnyError> {
        let icon = build_battery_icon(None, false)?;
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(self.menu_state.menu.clone()))
            .with_tooltip("Scyrox monitor")
            .with_icon(icon)
            .build()?;

        self.tray_icon = Some(tray_icon);
        Ok(())
    }

    fn rebuild_menu(&mut self) -> Result<(), AnyError> {
        self.api.refresh_devices()?;
        self.menu_state = build_tray_menu(
            &self.api,
            self.selected_device_path.as_ref(),
            self.notify_on_change,
            &self.status_text,
        )?;

        if let Some(tray_icon) = &self.tray_icon {
            tray_icon.set_menu(Some(Box::new(self.menu_state.menu.clone())));
        }

        Ok(())
    }

    fn handle_menu_event(&mut self, event: tray_icon::menu::MenuEvent) -> bool {
        if event.id == self.menu_state.quit_item.id() {
            return true;
        }

        if event.id == self.menu_state.refresh_item.id() {
            let _ = self.rebuild_menu();
            return false;
        }

        if event.id == self.menu_state.notify_changes_item.id() {
            self.notify_on_change = self.menu_state.notify_changes_item.is_checked();
            return false;
        }

        if let Some(index_text) = event.id.as_ref().strip_prefix("device-") {
            if let Ok(index) = index_text.parse::<usize>() {
                if let Some(path) = self.menu_state.device_paths.get(index) {
                    self.selected_device_path = Some(path.clone());
                    self.last_report = None;
                    self.low_battery_notified = false;
                    let _ = self.rebuild_menu();
                }
            }
        }

        false
    }

    fn poll_once(&mut self) {
        self.next_poll = Instant::now() + Duration::from_secs(POLL_INTERVAL_SECS);

        if self.selected_device_path.is_none() {
            self.selected_device_path = first_responsive_device_path(&self.api);
            if self.selected_device_path.is_some() {
                let _ = self.rebuild_menu();
            }
        }

        let Some(path) = self.selected_device_path.clone() else {
            self.set_disconnected_status("No compatible device selected");
            return;
        };

        match self.read_selected(&path) {
            Ok((identity, result)) => {
                self.update_from_result(&identity, &result);
                self.last_report = Some(result);
            }
            Err(err) => {
                self.set_disconnected_status(&format!("Disconnected ({err})"));
                self.selected_device_path = first_responsive_device_path(&self.api);
                let _ = self.rebuild_menu();
            }
        }
    }

    fn set_disconnected_status(&mut self, detail: &str) {
        self.status_text = format!("Status: {detail}");
        self.menu_state.status_item.set_text(&self.status_text);
        if let Some(tray_icon) = &self.tray_icon {
            let _ = tray_icon.set_tooltip(Some("Scyrox monitor: disconnected"));
            if let Ok(icon) = build_battery_icon(None, false) {
                let _ = tray_icon.set_icon(Some(icon));
            }
        }
    }

    fn read_selected(&mut self, path: &CString) -> Result<(DeviceIdentity, ReadResult), AnyError> {
        self.api.refresh_devices()?;

        let target = scan_candidates(&self.api)
            .into_iter()
            .find(|candidate| candidate.path.as_bytes() == path.as_bytes())
            .ok_or("selected device is no longer present")?;

        let device = self.api.open_path(&target.path)?;
        let result = read_device(&device)?;
        Ok((target.identity, result))
    }

    fn update_from_result(&mut self, identity: &DeviceIdentity, result: &ReadResult) {
        let battery = result.battery;
        let battery_level = battery.map(|b| b.level);
        let charging = battery.map(|b| b.charging).unwrap_or(false);

        self.status_text = format!(
            "Status: Batt {}% | DPI {} | {} Hz",
            battery_level
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".to_string()),
            result.current_dpi,
            result.polling_hz
        );
        self.menu_state.status_item.set_text(&self.status_text);

        if let Some(tray_icon) = &self.tray_icon {
            let tooltip = format!(
                "{}\nBattery: {}%{}\nDPI: {}\nPolling: {} Hz",
                identity.product.as_deref().unwrap_or("Scyrox Device"),
                battery_level
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                if charging { " (charging)" } else { "" },
                result.current_dpi,
                result.polling_hz
            );
            let _ = tray_icon.set_tooltip(Some(&tooltip));
            if let Ok(icon) = build_battery_icon(battery_level, charging) {
                let _ = tray_icon.set_icon(Some(icon));
            }
        }

        if let Some(previous) = &self.last_report {
            if self.notify_on_change
                && (previous.current_dpi != result.current_dpi
                    || previous.polling_hz != result.polling_hz)
            {
                let _ = send_notification(
                    "Mouse setting changed",
                    &format!(
                        "DPI: {} | Polling: {} Hz",
                        result.current_dpi, result.polling_hz
                    ),
                );
            }
        }

        if let Some(bat) = battery {
            if bat.level <= LOW_BATTERY_THRESHOLD && !self.low_battery_notified {
                let _ = send_notification(
                    "Mouse battery low",
                    &format!("Battery is at {}%", bat.level),
                );
                self.low_battery_notified = true;
            }
            if bat.level > LOW_BATTERY_THRESHOLD + 5 {
                self.low_battery_notified = false;
            }
        }
    }
}

fn build_tray_menu(
    api: &HidApi,
    selected_path: Option<&CString>,
    notify_on_change: bool,
    status_text: &str,
) -> Result<TrayMenuState, AnyError> {
    let menu = Menu::new();

    let status_item = MenuItem::with_id("status", status_text, false, None);
    menu.append(&status_item)?;
    menu.append(&PredefinedMenuItem::separator())?;

    let candidates = scan_candidates(api);
    let mut device_paths = Vec::new();

    if candidates.is_empty() {
        menu.append(&MenuItem::new("No compatible devices found", false, None))?;
    } else {
        for (index, candidate) in candidates.iter().enumerate() {
            let selected = selected_path
                .map(|p| p.as_bytes() == candidate.path.as_bytes())
                .unwrap_or(false);

            let label = format!(
                "[{}] {:04X}:{:04X} iface {} {:04X}:{:04X}",
                index,
                candidate.identity.vendor_id,
                candidate.identity.product_id,
                candidate.identity.interface_number,
                candidate.identity.usage_page,
                candidate.identity.usage
            );

            let item =
                CheckMenuItem::with_id(format!("device-{index}"), label, true, selected, None);
            menu.append(&item)?;
            device_paths.push(candidate.path.clone());
        }
    }

    menu.append(&PredefinedMenuItem::separator())?;

    let notify_changes_item = CheckMenuItem::with_id(
        "toggle-notify-change",
        "Notify on DPI/polling changes",
        true,
        notify_on_change,
        None,
    );
    menu.append(&notify_changes_item)?;

    menu.append(&PredefinedMenuItem::separator())?;

    let refresh_item = MenuItem::with_id("refresh-devices", "Refresh devices", true, None);
    let quit_item = MenuItem::with_id("quit", "Quit", true, None);
    menu.append(&refresh_item)?;
    menu.append(&quit_item)?;

    Ok(TrayMenuState {
        menu,
        status_item,
        device_paths,
        notify_changes_item,
        refresh_item,
        quit_item,
    })
}

fn scan_candidates(api: &HidApi) -> Vec<CandidateDevice> {
    api.device_list()
        .filter(|info| is_target_device(info))
        .map(|info| CandidateDevice {
            path: info.path().to_owned(),
            identity: identity_from_info(info),
        })
        .collect()
}

fn first_responsive_device_path(api: &HidApi) -> Option<CString> {
    for candidate in scan_candidates(api) {
        let Ok(device) = api.open_path(&candidate.path) else {
            continue;
        };
        drain_input(&device);
        if get_online(&device).is_ok() {
            return Some(candidate.path);
        }
    }
    None
}

fn send_notification(summary: &str, body: &str) -> Result<(), AnyError> {
    Notification::new().summary(summary).body(body).show()?;
    Ok(())
}

fn build_battery_icon(level: Option<u8>, charging: bool) -> Result<Icon, AnyError> {
    const W: usize = 32;
    const H: usize = 32;
    let mut rgba = vec![0u8; W * H * 4];

    let frame = [220u8, 220, 220, 255];
    let empty = [45u8, 45, 45, 220];

    fill_rect(&mut rgba, W, H, 6, 8, 20, 16, frame);
    fill_rect(&mut rgba, W, H, 26, 13, 2, 6, frame);
    fill_rect(&mut rgba, W, H, 8, 10, 16, 12, empty);

    match level {
        Some(percent) => {
            let p = percent.min(100);
            let fill_width = ((u32::from(p) * 16) / 100) as usize;
            let color = if p <= 20 {
                [220u8, 55, 55, 255]
            } else if p <= 50 {
                [230u8, 180, 40, 255]
            } else {
                [70u8, 190, 80, 255]
            };
            if fill_width > 0 {
                fill_rect(&mut rgba, W, H, 8, 10, fill_width, 12, color);
            }
        }
        None => {
            fill_rect(&mut rgba, W, H, 8, 10, 16, 12, [110u8, 110, 110, 255]);
        }
    }

    if charging {
        fill_rect(&mut rgba, W, H, 14, 11, 3, 4, [80u8, 220, 255, 255]);
        fill_rect(&mut rgba, W, H, 15, 15, 3, 4, [80u8, 220, 255, 255]);
        fill_rect(&mut rgba, W, H, 13, 19, 3, 2, [80u8, 220, 255, 255]);
    }

    Ok(Icon::from_rgba(rgba, W as u32, H as u32)?)
}

fn fill_rect(
    image: &mut [u8],
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    color: [u8; 4],
) {
    let x_end = (x + w).min(width);
    let y_end = (y + h).min(height);
    for yy in y..y_end {
        for xx in x..x_end {
            let idx = (yy * width + xx) * 4;
            image[idx..idx + 4].copy_from_slice(&color);
        }
    }
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
