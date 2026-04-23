// ======================================================================
// R503 Fingerprint Module Driver
// UART protocol — datasheet: R503-fingerprint-module-user-manual-V1.2.1
// ======================================================================

use anyhow::{anyhow, Result};
use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::{thread, time::Duration};

use esp_idf_sys as sys;

// ======================================================================
// Pin definitions temporary
// ======================================================================

const R503_TX_PIN: i32 = 17;     // ESP TX → R503 RXD (reuses BM-Lite MOSI pin)
const R503_RX_PIN: i32 = 15;     // R503 TXD → ESP RX (reuses BM-Lite MISO pin)
const R503_WAKEUP_PIN: i32 = 18; // R503 WAKEUP       (reuses BM-Lite IRQ pin)
const R503_UART_NUM: sys::uart_port_t = 2;
const R503_BAUD: i32 = 57_600;

// UART RX buffer size
const RX_BUF_SIZE: i32 = 1024;

// ======================================================================
// R503 protocol constants
// ======================================================================

const HEADER: [u8; 2] = [0xEF, 0x01];
const DEFAULT_ADDR: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

// Packet identifiers
const PID_COMMAND: u8 = 0x01;
const PID_ACK: u8 = 0x07;

// Instruction codes
const CMD_GEN_IMG: u8 = 0x01;
const CMD_IMG2TZ: u8 = 0x02;
const CMD_MATCH: u8 = 0x03;
const CMD_SEARCH: u8 = 0x04;
const CMD_REG_MODEL: u8 = 0x05;
const CMD_STORE: u8 = 0x06;
const CMD_DELET_CHAR: u8 = 0x0C;
const CMD_EMPTY: u8 = 0x0D;
const CMD_TEMPLATE_NUM: u8 = 0x1D;
const CMD_GET_IMAGE_EX: u8 = 0x28;
const CMD_AUTO_ENROLL: u8 = 0x31;
const CMD_AUTO_IDENTIFY: u8 = 0x32;
const CMD_AURA_LED: u8 = 0x35;
const CMD_CHECK_SENSOR: u8 = 0x36;
const CMD_HANDSHAKE: u8 = 0x40;
const CMD_SOFT_RST: u8 = 0x3D;
const CMD_VFY_PWD: u8 = 0x13;
const CMD_READ_SYS_PARA: u8 = 0x0F;

// Confirmation codes
const CONF_OK: u8 = 0x00;
const CONF_NO_FINGER: u8 = 0x02;

// Max receive buffer (header + addr + pid + length + data + checksum)
const MAX_PKT_LEN: usize = 256;

// Default read timeout in RTOS ticks (ESP-IDF default: 1 tick = 1ms at 1000Hz)
const READ_TIMEOUT_TICKS: u32 = 1000; // 1s — enough for simple commands

// GenImg needs longer: sensor capture takes 300-500ms with finger present
const GENIMG_TIMEOUT_TICKS: u32 = 3000; // 3s

// ======================================================================
// LED control types (public)
// ======================================================================

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum LedMode {
    Breathing  = 0x01,
    Flashing   = 0x02,
    AlwaysOn   = 0x03,
    AlwaysOff  = 0x04,
    GradualOn  = 0x05,
    GradualOff = 0x06,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum LedColor {
    Red    = 0x01,
    Blue   = 0x02,
    Purple = 0x03,
    Green  = 0x04,
    Yellow = 0x05,
    Cyan   = 0x06,
    White  = 0x07,
}

// ======================================================================
// Global context
// ======================================================================

struct R503Ctx {
    initialized: bool,
}

unsafe impl Send for R503Ctx {}
unsafe impl Sync for R503Ctx {}

impl R503Ctx {
    const fn new() -> Self {
        Self { initialized: false }
    }
}

lazy_static! {
    static ref R503_CTX: Mutex<R503Ctx> = Mutex::new(R503Ctx::new());
}

// ======================================================================
// Low-level UART I/O
// ======================================================================

fn uart_tx(data: &[u8]) {
    let ret = unsafe {
        sys::uart_write_bytes(R503_UART_NUM, data.as_ptr() as *const c_void, data.len())
    };
    if ret < 0 {
        log::error!("R503: uart_write_bytes failed (ret={})", ret);
    }
}

fn uart_rx(buf: &mut [u8], timeout_ticks: u32) -> i32 {
    unsafe {
        sys::uart_read_bytes(
            R503_UART_NUM,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            timeout_ticks,
        )
    }
}

fn uart_flush_rx() {
    unsafe {
        sys::uart_flush_input(R503_UART_NUM);
    }
}

/// Aggressively drain any pending RX bytes (power-on 0x55, stale responses).
fn drain_rx() {
    uart_flush_rx();
    let mut junk = [0u8; 64];
    // Read with very short timeout to consume anything still arriving
    loop {
        let n = uart_rx(&mut junk, 5);
        if n <= 0 {
            break;
        }
    }
}

// ======================================================================
// Packet building / parsing
// ======================================================================

/// Build a command packet: HEADER(2) + ADDR(4) + PID(1) + LENGTH(2) + DATA(n) + CHECKSUM(2)
/// `data` contains instruction code + parameters (without PID/LENGTH/CHECKSUM).
/// Returns the total packet in `out` and the number of bytes written.
fn build_packet(data: &[u8], out: &mut [u8; MAX_PKT_LEN]) -> usize {
    let length: u16 = (data.len() + 2) as u16; // data + 2 bytes checksum

    let mut i = 0;
    // Header
    out[i] = HEADER[0]; i += 1;
    out[i] = HEADER[1]; i += 1;
    // Address
    out[i..i+4].copy_from_slice(&DEFAULT_ADDR); i += 4;
    // PID
    out[i] = PID_COMMAND; i += 1;
    // Length (big-endian)
    out[i] = (length >> 8) as u8; i += 1;
    out[i] = (length & 0xFF) as u8; i += 1;
    // Data (instruction code + params)
    out[i..i+data.len()].copy_from_slice(data); i += data.len();

    // Checksum = PID + LENGTH bytes + DATA bytes
    let mut sum: u16 = PID_COMMAND as u16;
    sum = sum.wrapping_add((length >> 8) as u16);
    sum = sum.wrapping_add((length & 0xFF) as u16);
    for &b in data {
        sum = sum.wrapping_add(b as u16);
    }
    out[i] = (sum >> 8) as u8; i += 1;
    out[i] = (sum & 0xFF) as u8; i += 1;

    i
}

/// Parsed acknowledge packet
struct AckPacket {
    pub confirmation_code: u8,
    pub data: [u8; MAX_PKT_LEN],
    pub data_len: usize, // bytes after confirmation_code (parameters only)
}

/// Read and parse an ACK packet from the R503.
/// Scans the byte stream for the 0xEF01 header, discarding any leading
/// garbage (power-on 0x55, noise from hot reset, stale bytes).
fn read_ack(timeout_ticks: u32) -> Result<AckPacket> {
    // --- Scan for header 0xEF 0x01 ---
    // Read byte by byte, looking for the sync sequence.
    // This handles the R503 power-on 0x55 byte and any UART noise.
    let mut prev: u8 = 0;
    let mut found_header = false;
    let max_scan = 64; // don't scan forever

    for _ in 0..max_scan {
        let mut b = [0u8; 1];
        let n = uart_rx(&mut b, timeout_ticks);
        if n <= 0 {
            return Err(anyhow!("R503: no response (header scan timeout)"));
        }
        if prev == HEADER[0] && b[0] == HEADER[1] {
            found_header = true;
            break;
        }
        prev = b[0];
    }
    if !found_header {
        return Err(anyhow!("R503: header 0xEF01 not found (scanned {} bytes)", max_scan));
    }

    // Read address (4 bytes)
    let mut addr = [0u8; 4];
    let n = uart_rx(&mut addr, timeout_ticks);
    if n < 4 {
        return Err(anyhow!("R503: address timeout"));
    }

    // Read PID (1 byte)
    let mut pid = [0u8; 1];
    let n = uart_rx(&mut pid, timeout_ticks);
    if n < 1 {
        return Err(anyhow!("R503: pid timeout"));
    }
    if pid[0] != PID_ACK {
        return Err(anyhow!("R503: unexpected PID 0x{:02X} (expected ACK 0x07)", pid[0]));
    }

    // Read length (2 bytes, big-endian)
    let mut len_bytes = [0u8; 2];
    let n = uart_rx(&mut len_bytes, timeout_ticks);
    if n < 2 {
        return Err(anyhow!("R503: length timeout"));
    }
    let pkt_len = ((len_bytes[0] as u16) << 8) | (len_bytes[1] as u16);
    if pkt_len < 3 || pkt_len as usize > MAX_PKT_LEN {
        return Err(anyhow!("R503: invalid packet length {}", pkt_len));
    }

    // Read remaining bytes: confirmation_code + params + checksum(2)
    let remaining = pkt_len as usize; // includes confirmation_code + params + checksum(2)
    let mut buf = [0u8; MAX_PKT_LEN];
    let n = uart_rx(&mut buf[..remaining], timeout_ticks);
    if (n as usize) < remaining {
        return Err(anyhow!("R503: data timeout, expected {} got {}", remaining, n));
    }

    // Verify checksum
    let mut sum: u16 = pid[0] as u16;
    sum = sum.wrapping_add(len_bytes[0] as u16);
    sum = sum.wrapping_add(len_bytes[1] as u16);
    for j in 0..remaining - 2 {
        sum = sum.wrapping_add(buf[j] as u16);
    }
    let recv_sum = ((buf[remaining - 2] as u16) << 8) | (buf[remaining - 1] as u16);
    if sum != recv_sum {
        return Err(anyhow!("R503: checksum mismatch (calc=0x{:04X} recv=0x{:04X})", sum, recv_sum));
    }

    let confirmation_code = buf[0];
    let data_len = remaining - 3; // minus confirmation_code(1) and checksum(2)

    let mut ack = AckPacket {
        confirmation_code,
        data: [0u8; MAX_PKT_LEN],
        data_len,
    };
    if data_len > 0 {
        ack.data[..data_len].copy_from_slice(&buf[1..1 + data_len]);
    }

    Ok(ack)
}

/// Send a command and receive ACK. Returns the AckPacket.
fn send_cmd(data: &[u8], timeout_ticks: u32) -> Result<AckPacket> {
    uart_flush_rx();
    let mut pkt = [0u8; MAX_PKT_LEN];
    let len = build_packet(data, &mut pkt);
    uart_tx(&pkt[..len]);
    read_ack(timeout_ticks)
}

/// Send a simple command (instruction code only, no params) and check confirmation=OK.
fn send_simple_cmd(cmd: u8) -> Result<AckPacket> {
    send_cmd(&[cmd], READ_TIMEOUT_TICKS)
}

fn conf_to_str(code: u8) -> &'static str {
    match code {
        0x00 => "OK",
        0x01 => "receive error",
        0x02 => "no finger",
        0x03 => "fail to enroll",
        0x06 => "disorderly image",
        0x07 => "too few features",
        0x08 => "no match",
        0x09 => "not found",
        0x0A => "merge fail",
        0x0B => "ID out of range",
        0x0C => "read template error",
        0x0D => "upload template error",
        0x10 => "delete fail",
        0x11 => "clear library fail",
        0x13 => "wrong password",
        0x15 => "no valid primary image",
        0x18 => "flash write error",
        0x1F => "library full",
        0x22 => "template empty",
        0x24 => "library empty",
        0x26 => "timeout",
        0x27 => "fingerprint exists",
        0x29 => "sensor error",
        0xFC => "unsupported command",
        0xFD => "hardware error",
        0xFE => "execution failure",
        _ => "unknown error",
    }
}

fn check_conf(ack: &AckPacket, what: &str) -> Result<()> {
    if ack.confirmation_code == CONF_OK {
        Ok(())
    } else {
        Err(anyhow!(
            "R503 {}: error 0x{:02X} ({})",
            what,
            ack.confirmation_code,
            conf_to_str(ack.confirmation_code)
        ))
    }
}

// ======================================================================
// GPIO helper for WAKEUP pin
// ======================================================================

fn wakeup_pin_init() -> Result<()> {
    unsafe {
        let err = sys::gpio_set_direction(R503_WAKEUP_PIN, sys::gpio_mode_t_GPIO_MODE_INPUT);
        if err != 0 {
            return Err(anyhow!("R503: gpio_set_direction WAKEUP failed ({})", err));
        }
        // The R503 WAKEUP outputs high when no finger, low when finger detected.
        // Enable pull-up to ensure clean high when no finger.
        let err = sys::gpio_set_pull_mode(R503_WAKEUP_PIN, sys::gpio_pull_mode_t_GPIO_PULLUP_ONLY);
        if err != 0 {
            return Err(anyhow!("R503: gpio_set_pull_mode WAKEUP failed ({})", err));
        }
    }
    Ok(())
}

/// Returns true if a finger is currently touching the sensor (WAKEUP=LOW).
pub fn is_finger_present() -> bool {
    unsafe { sys::gpio_get_level(R503_WAKEUP_PIN) == 0 }
}

// ======================================================================
// LED control
// ======================================================================

/// Control the R503 Aura LED ring.
///
/// * `mode`  — breathing, flashing, always on/off, gradual on/off
/// * `speed` — 0x00..0xFF (256 gears, min 5s cycle). Relevant for breathing/flashing/gradual.
/// * `color` — red, blue, purple, green, yellow, cyan, white
/// * `count` — 0 = infinite, 1..255 = number of cycles (breathing/flashing only)
pub fn led_control(mode: LedMode, speed: u8, color: LedColor, count: u8) -> Result<()> {
    let ack = send_cmd(
        &[CMD_AURA_LED, mode as u8, speed, color as u8, count],
        READ_TIMEOUT_TICKS,
    )?;
    check_conf(&ack, "AuraLedConfig")
}

/// Turn LED on with the given color (steady).
pub fn led_on(color: LedColor) -> Result<()> {
    led_control(LedMode::AlwaysOn, 0, color, 0)
}

/// Turn LED off.
pub fn led_off() -> Result<()> {
    led_control(LedMode::AlwaysOff, 0, LedColor::Blue, 0)
}

/// Breathing LED effect.
/// * `speed` — 0x00..0xFF (lower = slower)
/// * `count` — 0 = infinite, 1..255 = cycles
pub fn led_breathing(color: LedColor, speed: u8, count: u8) -> Result<()> {
    led_control(LedMode::Breathing, speed, color, count)
}

/// Flashing LED effect.
pub fn led_flashing(color: LedColor, speed: u8, count: u8) -> Result<()> {
    led_control(LedMode::Flashing, speed, color, count)
}

/// Gradually turn LED on.
pub fn led_gradual_on(color: LedColor, speed: u8) -> Result<()> {
    led_control(LedMode::GradualOn, speed, color, 0)
}

/// Gradually turn LED off.
pub fn led_gradual_off(color: LedColor, speed: u8) -> Result<()> {
    led_control(LedMode::GradualOff, speed, color, 0)
}

// ======================================================================
// Low-level R503 commands (public for flexibility)
// ======================================================================

/// Handshake — verify the module is alive.
pub fn handshake() -> Result<()> {
    let ack = send_simple_cmd(CMD_HANDSHAKE)?;
    check_conf(&ack, "Handshake")
}

/// Verify password (default 0x00000000).
pub fn verify_password(password: u32) -> Result<()> {
    let ack = send_cmd(
        &[
            CMD_VFY_PWD,
            (password >> 24) as u8,
            (password >> 16) as u8,
            (password >> 8) as u8,
            password as u8,
        ],
        READ_TIMEOUT_TICKS,
    )?;
    check_conf(&ack, "VfyPwd")
}

/// Check if the sensor hardware is OK.
pub fn check_sensor() -> Result<()> {
    let ack = send_simple_cmd(CMD_CHECK_SENSOR)?;
    check_conf(&ack, "CheckSensor")
}

/// Soft reset the module. After reset, module sends 0x55 as handshake sign.
pub fn soft_reset() -> Result<()> {
    let ack = send_simple_cmd(CMD_SOFT_RST)?;
    check_conf(&ack, "SoftRst")?;
    // Wait for module to restart and send 0x55
    thread::sleep(Duration::from_millis(100));
    uart_flush_rx();
    Ok(())
}

/// Read system parameters (16 bytes). Returns (status_reg, library_size, security_level).
pub fn read_sys_para() -> Result<(u16, u16, u16)> {
    let ack = send_simple_cmd(CMD_READ_SYS_PARA)?;
    check_conf(&ack, "ReadSysPara")?;
    if ack.data_len < 16 {
        return Err(anyhow!("R503 ReadSysPara: expected 16 data bytes, got {}", ack.data_len));
    }
    let status = ((ack.data[0] as u16) << 8) | (ack.data[1] as u16);
    let lib_size = ((ack.data[4] as u16) << 8) | (ack.data[5] as u16);
    let sec_level = ((ack.data[6] as u16) << 8) | (ack.data[7] as u16);
    Ok((status, lib_size, sec_level))
}

/// Get the number of stored templates.
pub fn template_count() -> Result<u16> {
    let ack = send_simple_cmd(CMD_TEMPLATE_NUM)?;
    check_conf(&ack, "TemplateNum")?;
    if ack.data_len < 2 {
        return Err(anyhow!("R503 TemplateNum: expected 2 data bytes, got {}", ack.data_len));
    }
    let count = ((ack.data[0] as u16) << 8) | (ack.data[1] as u16);
    Ok(count)
}

/// Collect a finger image into ImageBuffer.
/// Returns CONF_NO_FINGER (0x02) if no finger, or error.
pub fn gen_image() -> Result<u8> {
    let ack = send_cmd(&[CMD_GEN_IMG], GENIMG_TIMEOUT_TICKS)?;
    Ok(ack.confirmation_code)
}

/// Collect finger image (extended version — returns error on poor quality).
pub fn gen_image_ex() -> Result<u8> {
    let ack = send_cmd(&[CMD_GET_IMAGE_EX], GENIMG_TIMEOUT_TICKS)?;
    Ok(ack.confirmation_code)
}

/// Generate character file from image in ImageBuffer.
/// `buffer_id`: 1..6 (CharBuffer number).
pub fn img_to_tz(buffer_id: u8) -> Result<()> {
    let ack = send_cmd(&[CMD_IMG2TZ, buffer_id], READ_TIMEOUT_TICKS)?;
    check_conf(&ack, "Img2Tz")
}

/// Match templates in CharBuffer1 and CharBuffer2.
/// Returns the match score, or error if no match.
pub fn match_templates() -> Result<u16> {
    let ack = send_simple_cmd(CMD_MATCH)?;
    check_conf(&ack, "Match")?;
    if ack.data_len < 2 {
        return Err(anyhow!("R503 Match: expected 2 data bytes, got {}", ack.data_len));
    }
    let score = ((ack.data[0] as u16) << 8) | (ack.data[1] as u16);
    Ok(score)
}

/// Search the finger library for a match against CharBuffer1.
/// `start_id`: starting template position.
/// `count`: number of templates to search.
/// Returns (page_id, match_score) on success.
pub fn search(start_id: u16, count: u16) -> Result<(u16, u16)> {
    let ack = send_cmd(
        &[
            CMD_SEARCH,
            0x01, // CharBuffer1
            (start_id >> 8) as u8,
            (start_id & 0xFF) as u8,
            (count >> 8) as u8,
            (count & 0xFF) as u8,
        ],
        READ_TIMEOUT_TICKS,
    )?;
    check_conf(&ack, "Search")?;
    if ack.data_len < 4 {
        return Err(anyhow!("R503 Search: expected 4 data bytes, got {}", ack.data_len));
    }
    let page_id = ((ack.data[0] as u16) << 8) | (ack.data[1] as u16);
    let score = ((ack.data[2] as u16) << 8) | (ack.data[3] as u16);
    Ok((page_id, score))
}

/// Combine CharBuffer1 and CharBuffer2 into a template (stored in both buffers).
pub fn reg_model() -> Result<()> {
    let ack = send_simple_cmd(CMD_REG_MODEL)?;
    check_conf(&ack, "RegModel")
}

/// Store template from CharBuffer to Flash at the given position.
/// `buffer_id`: 1 or 2 (CharBuffer number).
/// `model_id`: 0..N library position.
pub fn store_template(buffer_id: u8, model_id: u16) -> Result<()> {
    let ack = send_cmd(
        &[
            CMD_STORE,
            buffer_id,
            (model_id >> 8) as u8,
            (model_id & 0xFF) as u8,
        ],
        READ_TIMEOUT_TICKS,
    )?;
    check_conf(&ack, "Store")
}

/// Delete `count` templates starting from `start_id`.
pub fn delete_templates(start_id: u16, count: u16) -> Result<()> {
    let ack = send_cmd(
        &[
            CMD_DELET_CHAR,
            (start_id >> 8) as u8,
            (start_id & 0xFF) as u8,
            (count >> 8) as u8,
            (count & 0xFF) as u8,
        ],
        READ_TIMEOUT_TICKS,
    )?;
    check_conf(&ack, "DeletChar")
}

/// Empty the entire finger library.
pub fn empty_library() -> Result<()> {
    let ack = send_simple_cmd(CMD_EMPTY)?;
    check_conf(&ack, "Empty")
}

/// AutoEnroll — automatic enrollment (collects 6 images, merges, stores).
/// `model_id`: library position (0..199, or 0xC8..0xFF for auto-assign).
/// `allow_overwrite`: allow overwriting existing ID.
/// `allow_duplicate`: allow duplicate fingerprints.
/// `return_status`: return progress status at each step.
/// `require_remove`: require finger removal between captures.
///
/// Timeout: up to ~60s for full enrollment (6 captures), so use a long timeout.
pub fn auto_enroll(
    model_id: u8,
    allow_overwrite: bool,
    allow_duplicate: bool,
    return_status: bool,
    require_remove: bool,
) -> Result<()> {
    // Long timeout for auto_enroll: each capture can take up to 10s,
    // 6 captures → worst case ~90s total.
    let long_timeout: u32 = 1500; // ~15s per intermediate ack

    let ack = send_cmd(
        &[
            CMD_AUTO_ENROLL,
            model_id,
            allow_overwrite as u8,
            allow_duplicate as u8,
            return_status as u8,
            require_remove as u8,
        ],
        long_timeout,
    )?;

    if return_status {
        // When return_status=1, the module sends intermediate ACK packets
        // for each step (collect image, generate feature, etc.) before the final one.
        // We need to read ACKs until we get the final one (step=0x0F storage, or error).
        let mut last_code = ack.confirmation_code;
        if last_code != CONF_OK {
            // First ack might be a step status or an error
            // Step statuses have confirmation_code=0x00 and parameter1=step
            // Final errors have non-zero confirmation codes
            if ack.data_len >= 2 {
                let step = ack.data[0];
                log::info!("R503 AutoEnroll step=0x{:02X}, id={}", step, ack.data[1]);
            }
            if last_code != CONF_OK {
                return Err(anyhow!(
                    "R503 AutoEnroll: error 0x{:02X} ({})",
                    last_code,
                    conf_to_str(last_code)
                ));
            }
        }

        // Read subsequent intermediate ACKs
        loop {
            match read_ack(long_timeout) {
                Ok(intermediate) => {
                    last_code = intermediate.confirmation_code;
                    if intermediate.data_len >= 2 {
                        let step = intermediate.data[0];
                        let id = intermediate.data[1];
                        log::info!("R503 AutoEnroll step=0x{:02X}, id={}", step, id);
                        // Step 0x0F = storage template (final step)
                        if step == 0x0F && last_code == CONF_OK {
                            log::info!("R503 AutoEnroll: storage complete, id={}", id);
                            return Ok(());
                        }
                    }
                    if last_code != CONF_OK {
                        return Err(anyhow!(
                            "R503 AutoEnroll: error 0x{:02X} at step ({})",
                            last_code,
                            conf_to_str(last_code)
                        ));
                    }
                }
                Err(e) => {
                    return Err(anyhow!("R503 AutoEnroll: read intermediate ACK failed: {}", e));
                }
            }
        }
    } else {
        // No intermediate status — just one final ACK
        check_conf(&ack, "AutoEnroll")
    }
}

/// AutoIdentify — automatic fingerprint verification.
/// Collects image, generates features, searches library.
/// Returns (model_id, match_score) on success.
///
/// * `security_level`: 1..5
/// * `start_id`: starting search position
/// * `count`: number of templates to search
/// * `return_status`: return progress status
/// * `max_retries`: 0 = loop forever until match, 1..255 = max attempts
pub fn auto_identify(
    security_level: u8,
    start_id: u8,
    count: u8,
    return_status: bool,
    max_retries: u8,
) -> Result<(u16, u16)> {
    let long_timeout: u32 = 1500;

    let ack = send_cmd(
        &[
            CMD_AUTO_IDENTIFY,
            security_level,
            start_id,
            count,
            return_status as u8,
            max_retries,
        ],
        long_timeout,
    )?;

    if return_status {
        // Read intermediate ACKs until we get the search result (step=3)
        let mut last_ack = ack;
        loop {
            if last_ack.data_len >= 5 {
                let step = last_ack.data[0];
                if step == 3 && last_ack.confirmation_code == CONF_OK {
                    // Search result
                    let model_id = ((last_ack.data[1] as u16) << 8) | (last_ack.data[2] as u16);
                    let score = ((last_ack.data[3] as u16) << 8) | (last_ack.data[4] as u16);
                    return Ok((model_id, score));
                }
            }
            if last_ack.confirmation_code != CONF_OK {
                return Err(anyhow!(
                    "R503 AutoIdentify: error 0x{:02X} ({})",
                    last_ack.confirmation_code,
                    conf_to_str(last_ack.confirmation_code)
                ));
            }
            last_ack = read_ack(long_timeout)?;
        }
    } else {
        // Single final ACK: step(1B) + position(2B) + score(2B)
        check_conf(&ack, "AutoIdentify")?;
        if ack.data_len < 5 {
            return Err(anyhow!("R503 AutoIdentify: expected 5+ data bytes, got {}", ack.data_len));
        }
        // data[0] = step (skip), data[1..2] = model_id, data[3..4] = score
        let model_id = ((ack.data[1] as u16) << 8) | (ack.data[2] as u16);
        let score = ((ack.data[3] as u16) << 8) | (ack.data[4] as u16);
        Ok((model_id, score))
    }
}

// ======================================================================
// Public API — mirrors fingerprint.rs (BM-Lite) interface
// ======================================================================

/// Initialize the R503 module: UART driver, WAKEUP GPIO, handshake.
pub fn init() -> Result<()> {
    let mut ctx = R503_CTX.lock().unwrap();
    if ctx.initialized {
        return Ok(());
    }

    unsafe {
        let mut cfg: sys::uart_config_t = zeroed();
        cfg.baud_rate = R503_BAUD;
        cfg.data_bits = sys::uart_word_length_t_UART_DATA_8_BITS;
        cfg.parity = sys::uart_parity_t_UART_PARITY_DISABLE;
        cfg.stop_bits = sys::uart_stop_bits_t_UART_STOP_BITS_1;
        cfg.flow_ctrl = sys::uart_hw_flowcontrol_t_UART_HW_FLOWCTRL_DISABLE;
        cfg.rx_flow_ctrl_thresh = 0;

        let err = sys::uart_param_config(R503_UART_NUM, &cfg);
        if err != 0 {
            return Err(anyhow!("R503: uart_param_config failed ({})", err));
        }

        let err = sys::uart_set_pin(
            R503_UART_NUM,
            R503_TX_PIN,
            R503_RX_PIN,
            sys::UART_PIN_NO_CHANGE,
            sys::UART_PIN_NO_CHANGE,
        );
        if err != 0 {
            return Err(anyhow!("R503: uart_set_pin failed ({})", err));
        }

        let err = sys::uart_driver_install(
            R503_UART_NUM,
            RX_BUF_SIZE,
            0,
            0,
            ptr::null_mut(),
            0,
        );
        if err != 0 {
            return Err(anyhow!("R503: uart_driver_install failed ({})", err));
        }
    }

    // Configure WAKEUP pin as input
    wakeup_pin_init()?;

    // Wait for module power-on initialization.
    // Datasheet says ~50ms, but in practice the module may still be
    // flushing a previous session or sending the 0x55 power-on byte.
    thread::sleep(Duration::from_millis(500));

    // Drain any stale bytes (0x55 power-on byte, leftover from previous session)
    drain_rx();

    // Handshake with retries — the module may need a few attempts after
    // a hot reset of the ESP32 (R503 stays powered, UART lines glitch).
    let mut hs_ok = false;
    for attempt in 1..=5 {
        drain_rx();
        match handshake() {
            Ok(()) => {
                hs_ok = true;
                break;
            }
            Err(e) => {
                log::warn!("R503: handshake attempt {}/5 failed: {}", attempt, e);
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
    if !hs_ok {
        return Err(anyhow!("R503: handshake failed after 5 attempts"));
    }
    log::info!("R503: handshake OK");

    // Verify default password
    verify_password(0x00000000)?;
    log::info!("R503: password verified");

    // Check sensor
    check_sensor()?;
    log::info!("R503: sensor OK");

    // Read system parameters
    match read_sys_para() {
        Ok((status, lib_size, sec_level)) => {
            log::info!(
                "R503: status=0x{:04X}, library_size={}, security_level={}",
                status,
                lib_size,
                sec_level
            );
        }
        Err(e) => log::warn!("R503: ReadSysPara failed: {}", e),
    }

    // Signal success with green LED
    let _ = led_on(LedColor::Green);
    thread::sleep(Duration::from_millis(300));
    let _ = led_off();

    ctx.initialized = true;
    log::info!("R503: init OK");
    Ok(())
}

/// Check if at least one fingerprint template is stored.
pub fn is_user_enrolled() -> Result<bool> {
    let ctx = R503_CTX.lock().unwrap();
    if !ctx.initialized {
        return Err(anyhow!("R503 not initialized"));
    }
    drop(ctx);
    let count = template_count()?;
    Ok(count > 0)
}

/// Delete all fingerprint templates from Flash.
pub fn wipe_templates() -> Result<()> {
    let ctx = R503_CTX.lock().unwrap();
    if !ctx.initialized {
        return Ok(());
    }
    drop(ctx);
    empty_library()?;
    log::info!("R503: all templates wiped");
    Ok(())
}

/// Wait for finger using WAKEUP pin, then capture image with GenImg.
/// Returns Ok(()) when GenImg succeeds, or Err after timeout.
fn wait_finger_and_capture(capture_label: &str, timeout_ms: u32) -> Result<()> {
    let start = unsafe { sys::esp_timer_get_time() } as i64;
    let timeout_us = (timeout_ms as i64) * 1000;

    // Phase 1: wait for finger via WAKEUP pin (no UART traffic)
    loop {
        let now = unsafe { sys::esp_timer_get_time() } as i64;
        if now - start >= timeout_us {
            return Err(anyhow!("R503: timeout waiting for finger ({})", capture_label));
        }
        if is_finger_present() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    log::info!("R503: finger detected (WAKEUP), capturing {}...", capture_label);

    // Phase 2: finger detected — keep retrying GenImg.
    // Do NOT re-check WAKEUP here: it can fluctuate during image capture.
    for attempt in 0..10 {
        drain_rx();
        match gen_image() {
            Ok(code) if code == CONF_OK => return Ok(()),
            Ok(code) if code == CONF_NO_FINGER => {
                log::warn!("R503: GenImg says no finger (attempt {}), retrying", attempt);
            }
            Ok(code) => {
                return Err(anyhow!(
                    "R503 GenImg({}): error 0x{:02X} ({})",
                    capture_label, code, conf_to_str(code)
                ));
            }
            Err(e) => {
                log::warn!("R503: GenImg {} UART error (attempt {}): {}", capture_label, attempt, e);
            }
        }
        // Wait between retries — don't flood the module
        thread::sleep(Duration::from_millis(200));
    }

    Err(anyhow!("R503: GenImg failed after 10 attempts ({})", capture_label))
}

/// Wait for finger removal using WAKEUP pin (no GenImg polling).
fn wait_finger_removed(timeout_ms: u32) {
    let start = unsafe { sys::esp_timer_get_time() } as i64;
    let timeout_us = (timeout_ms as i64) * 1000;
    loop {
        if !is_finger_present() {
            break;
        }
        let now = unsafe { sys::esp_timer_get_time() } as i64;
        if now - start >= timeout_us {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Enroll a new fingerprint using the manual multi-step process.
/// Captures two images, generates features, merges, and stores at position 0.
pub fn enroll_user() -> Result<()> {
    let ctx = R503_CTX.lock().unwrap();
    if !ctx.initialized {
        return Err(anyhow!("R503 not initialized"));
    }
    drop(ctx);

    // Quick handshake to make sure the module is alive before starting
    drain_rx();
    handshake()?;
    log::info!("R503: module alive, starting enrollment");

    log::info!("R503: enroll - place your finger...");
    let _ = led_breathing(LedColor::Cyan, 0x80, 0);
    // Let the LED command complete and drain any stale response
    thread::sleep(Duration::from_millis(100));
    drain_rx();

    // --- Capture 1 ---
    wait_finger_and_capture("capture 1", 30_000)?;

    // Generate feature in CharBuffer1
    img_to_tz(1)?;
    let _ = led_on(LedColor::Yellow);
    log::info!("R503: capture 1 OK, remove finger...");

    // Wait for finger removal using WAKEUP pin
    wait_finger_removed(10_000);

    let _ = led_breathing(LedColor::Cyan, 0x80, 0);
    thread::sleep(Duration::from_millis(100));
    drain_rx();
    log::info!("R503: place the same finger again...");
    thread::sleep(Duration::from_millis(300));

    // --- Capture 2 ---
    wait_finger_and_capture("capture 2", 30_000)?;

    // Generate feature in CharBuffer2
    img_to_tz(2)?;
    log::info!("R503: capture 2 OK");

    // Merge templates
    reg_model()?;
    log::info!("R503: template merged");

    // Store at position 0
    store_template(1, 0)?;
    log::info!("R503: template stored at position 0");

    // Verify
    let count = template_count()?;
    log::info!("R503: templates after enroll: {}", count);

    // Wait for finger removal
    wait_finger_removed(5_000);

    // Brief green flash to confirm enrollment, then back to green constant (unlocked)
    let _ = led_flashing(LedColor::Green, 0x40, 3);
    thread::sleep(Duration::from_millis(1000));
    let _ = led_on(LedColor::Green);
    Ok(())
}

/// Single fingerprint verification attempt.
/// Waits for a finger (up to `timeout_ms`), then identifies against the library.
/// Returns true if matched.
pub fn check_once(timeout_ms: u32) -> Result<bool> {
    let ctx = R503_CTX.lock().unwrap();
    if !ctx.initialized {
        return Err(anyhow!("R503 not initialized"));
    }
    drop(ctx);

    // Wait for finger and capture image
    match wait_finger_and_capture("check", timeout_ms) {
        Ok(()) => {}
        Err(_) => return Ok(false),
    }

    // Generate feature in CharBuffer1
    img_to_tz(1)?;

    // Search entire library (200 templates max for R503)
    let matched = match search(0, 200) {
        Ok((page_id, score)) => {
            log::info!("R503: matched template id={}, score={}", page_id, score);
            true
        }
        Err(_) => false,
    };

    // Wait for finger removal
    wait_finger_removed(5_000);

    Ok(matched)
}

/// Require 3 successful fingerprint matches.
/// LED: blue breathing while waiting, green constant after final success, red on failure.
pub fn test_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    for i in 1..=3 {
        log::info!("R503: test {}/3 - place your finger", i);
        let _ = led_breathing(LedColor::Blue, 0x80, 0);

        match check_once(15_000)? {
            true => {
                log::info!("R503: finger recognized ({}/3)", i);
                if i == 3 {
                    // Final success — green stays on (unlocked)
                    let _ = led_on(LedColor::Green);
                } else {
                    // Intermediate success — brief green flash
                    let _ = led_on(LedColor::Green);
                    thread::sleep(Duration::from_millis(300));
                    let _ = led_off();
                }
            }
            false => {
                let _ = led_on(LedColor::Red);
                thread::sleep(Duration::from_millis(500));
                let _ = led_off();
                return Err("R503: finger not recognized".into());
            }
        }
    }

    log::info!("R503: fingerprint validated 3/3");
    Ok(())
}

/// Complete workflow: init + wipe + enroll + verify 3x.
pub fn fingerprint_validation() -> Result<(), Box<dyn std::error::Error>> {
    init()?;
    wipe_templates()?;
    enroll_user()?;
    match is_user_enrolled() {
        Ok(true) => log::info!("R503: user enrolled, verifying 3 times..."),
        Ok(false) => {
            log::warn!("R503: no user enrolled, enrolling...");
            wipe_templates()?;
            enroll_user()?;
        }
        Err(e) => return Err(e.into()),
    }

    match test_fingerprint() {
        Ok(()) => log::info!("R503: user authenticated!"),
        Err(e) => return Err(e),
    }

    Ok(())
}

/// Single authentication attempt using sliced waiting.
/// LED: blue breathing while waiting, green on success, red only if wrong finger placed.
pub fn test_fingerprint_once() -> Result<(), Box<dyn std::error::Error>> {
    loop {
        log::info!("R503: place your finger");
        let _ = led_breathing(LedColor::Blue, 0x80, 0);

        // Phase 1: wait for finger — Err = timeout (no finger), loop silently, no red
        match wait_finger_and_capture("auth", 10_000) {
            Err(_) => continue,
            Ok(()) => {}
        }

        // Phase 2: finger was placed — identify
        if let Err(e) = img_to_tz(1) {
            log::error!("R503: img_to_tz error: {}, retrying...", e);
            continue;
        }

        match search(0, 200) {
            Ok((page_id, score)) => {
                log::info!("R503: matched id={}, score={}", page_id, score);
                wait_finger_removed(5_000);
                let _ = led_on(LedColor::Green);
                return Ok(());
            }
            Err(_) => {
                // finger placed but not recognized — red
                log::warn!("R503: wrong finger");
                wait_finger_removed(5_000);
                let _ = led_on(LedColor::Red);
                thread::sleep(Duration::from_millis(500));
                let _ = led_off();
            }
        }
    }
}

/// Multi-phase fingerprint identification with sliced waiting.
///
/// * `wait_total_ms` — max time to wait for finger presence
/// * `wait_slice_ms` — polling interval for finger detection
/// * `identify_ms`   — timeout for the identification phase (unused for R503,
///                      search is near-instant, kept for API compatibility)
///
/// Uses the WAKEUP pin for efficient finger detection, then does
/// GenImg → Img2Tz → Search.
pub fn wait_and_identify_sliced(
    wait_total_ms: u32,
    wait_slice_ms: u16,
    _identify_ms: u32,
) -> Result<bool> {
    let ctx = R503_CTX.lock().unwrap();
    if !ctx.initialized {
        return Err(anyhow!("R503 not initialized"));
    }
    drop(ctx);

    let start_us = unsafe { sys::esp_timer_get_time() } as i64;
    let total_timeout_us = (wait_total_ms as i64) * 1000;
    let slice_us = (wait_slice_ms as i64) * 1000;

    // --- Phase A: wait for finger using WAKEUP pin in sliced intervals ---
    loop {
        let now_us = unsafe { sys::esp_timer_get_time() } as i64;
        if now_us - start_us >= total_timeout_us {
            return Ok(false);
        }

        if is_finger_present() {
            // Double-check with GenImg to confirm actual finger contact
            let code = gen_image()?;
            if code == CONF_OK {
                break;
            }
        }

        // Sleep for the slice duration, yielding to other tasks
        let sleep_ms = (slice_us / 1000).min(wait_slice_ms as i64) as u64;
        thread::sleep(Duration::from_millis(sleep_ms));
        unsafe { sys::vTaskDelay(1) };
    }

    // --- Phase B: identify (generate feature + search) ---
    img_to_tz(1)?;

    let matched = match search(0, 200) {
        Ok((page_id, score)) => {
            log::info!("R503: matched template id={}, score={}", page_id, score);
            true
        }
        Err(_) => false,
    };

    // --- Phase C: wait for finger removal ---
    let mut attempts = 0;
    loop {
        if !is_finger_present() {
            break;
        }
        attempts += 1;
        if attempts > 250 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    Ok(matched)
}

/// Robust enrollment with retries (mirrors BM-Lite enroll_once).
pub fn enroll_once() -> Result<(), i32> {
    // Wipe with max 5 retries
    for attempt in 1..=5 {
        match wipe_templates() {
            Ok(()) => {
                log::info!("R503: wipe_templates OK");
                break;
            }
            Err(e) => {
                log::error!("R503: wipe_templates error (attempt {}): {}", attempt, e);
                if attempt == 5 {
                    return Err(-1);
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
    }

    // Let R503 finish flash erase before starting enrollment
    thread::sleep(Duration::from_millis(300));
    drain_rx();

    // Enroll with max 3 retries
    for attempt in 1..=3 {
        match enroll_user() {
            Ok(()) => {
                log::info!("R503: enroll_user OK");
                return Ok(());
            }
            Err(e) => {
                log::error!("R503: enroll_user error (attempt {}): {}", attempt, e);
                if attempt < 3 {
                    thread::sleep(Duration::from_millis(1000));
                    drain_rx();
                }
            }
        }
    }

    log::error!("R503: enrollment failed after 3 attempts");
    Err(-1)
}
