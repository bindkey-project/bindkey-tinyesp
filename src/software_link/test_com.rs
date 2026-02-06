use core::{ffi::c_void, mem::zeroed, ptr};
use esp_idf_sys as sys;
use anyhow::anyhow;

use crate::crypto::secure_element::*;
use crate::fingerprint::*;

const UART_NUM: sys::uart_port_t = 1;
const RX_PIN: i32 = 41;
const TX_PIN: i32 = 42;
const BAUD: i32 = 115_200;

const SLOT: u16 = 0;

#[inline(always)]
fn yield_1tick() {
    unsafe { sys::vTaskDelay(1) };
}

fn esp_err_to_result(err: i32) -> Result<(), i32> {
    if err == 0 { Ok(()) } else { Err(err) }
}

fn uart_write_str(s: &str) {
    unsafe {
        sys::uart_write_bytes(UART_NUM, s.as_ptr() as *const c_void, s.len());
    }
}

fn uart_write_bytes(bytes: &[u8]) {
    unsafe {
        sys::uart_write_bytes(UART_NUM, bytes.as_ptr() as *const c_void, bytes.len());
    }
}

fn bytes_to_hex_upper(src: &[u8], dst: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut j = 0usize;
    for &b in src {
        dst[j] = HEX[(b >> 4) as usize];
        dst[j + 1] = HEX[(b & 0x0F) as usize];
        j += 2;
    }
    j
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// attend exactement 64 hex chars
fn hex_to_bytes_32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        log::error!("bad challenge len={}, expected 64", b.len());
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}



fn handle_enroll() {
    match (|| -> Result<([u8; 9], [u8; 64]), i32> {
        let se = AteccSession::new()?;
        let sn = se.serial_number()?;      // [u8;9]
        let pubkey = se.get_pubkey(SLOT)?; // [u8;64]
        log::info!("sn={:02X?}", sn);
        log::info!("pubkey()={:02X?}", pubkey);
        Ok((sn, pubkey))
    })() {
        Ok((sn, pubkey)) => {
            /*match enroll_once(){
                Ok(()) => log::info!("Enrolled !"),
                Err(rc) => log::error!("Enroll error rc={}", rc)
            }
            log::info!("hello");*/
            let _ = enroll_once();

            let mut hexbuf = [0u8; 256];

            uart_write_str("SN=");
            let n_sn = bytes_to_hex_upper(&sn, &mut hexbuf);
            uart_write_bytes(&hexbuf[..n_sn]);
            uart_write_str("\n");

            uart_write_str("PUB=");
            let n_pk = bytes_to_hex_upper(&pubkey, &mut hexbuf);
            uart_write_bytes(&hexbuf[..n_pk]);
            uart_write_str("\n");

            uart_write_str("OK\n");
        }
        Err(rc) => uart_write_str(&format!("ERR={}\n", rc)),
    }
}

fn handle_uid() {
    match (|| -> Result<[u8; 9], i32> {
        let se = AteccSession::new()?;
        let sn = se.serial_number()?;
        log::info!("sn={:02X?}", sn);
        Ok(sn)
    })() {
        Ok(sn) => {
            let mut hexbuf = [0u8; 64];
            uart_write_str("SN=");
            let n = bytes_to_hex_upper(&sn, &mut hexbuf);
            uart_write_bytes(&hexbuf[..n]);
            uart_write_str("\nOK\n");
        }
        Err(rc) => uart_write_str(&format!("ERR={}\n", rc)),
    }
}

fn handle_challenge_hex(hex: &str) {
    let challenge = match hex_to_bytes_32(hex) {
        Some(c) => c,
        None => {
            uart_write_str("ERR=bad_challenge\n");
            return;
        }
    };

    // fingerprint + signature
    match test_fingerprint_once() {
        Ok(()) => {
            match (|| -> Result<[u8; 64], i32> {
                let se = AteccSession::new()?;
                let sig = se.sign(SLOT, &challenge)?;
                log::info!("ECDSA signature (slot{})={:02X?}", SLOT, sig);
                Ok(sig)
            })() {
                Ok(sig) => {
                    let mut hexbuf = [0u8; 256];
                    uart_write_str("SIG=");
                    let n = bytes_to_hex_upper(&sig, &mut hexbuf);
                    uart_write_bytes(&hexbuf[..n]);
                    uart_write_str("\nOK\n");
                }
                Err(rc) => uart_write_str(&format!("ERR={}\n", rc)),
            }
        }
        Err(e) => {
            uart_write_str(&format!("ERR={}\n", e));
        }
    }
}

pub fn uart_proto_task() -> Result<(), i32> {
    unsafe {
        let mut cfg: sys::uart_config_t = zeroed();
        cfg.baud_rate = BAUD;
        cfg.data_bits = sys::uart_word_length_t_UART_DATA_8_BITS;
        cfg.parity = sys::uart_parity_t_UART_PARITY_DISABLE;
        cfg.stop_bits = sys::uart_stop_bits_t_UART_STOP_BITS_1;
        cfg.flow_ctrl = sys::uart_hw_flowcontrol_t_UART_HW_FLOWCTRL_DISABLE;
        cfg.rx_flow_ctrl_thresh = 0;
        cfg.flags = zeroed();

        esp_err_to_result(sys::uart_param_config(UART_NUM, &cfg))?;
        esp_err_to_result(sys::uart_set_pin(
            UART_NUM,
            TX_PIN,
            RX_PIN,
            sys::UART_PIN_NO_CHANGE,
            sys::UART_PIN_NO_CHANGE,
        ))?;
        esp_err_to_result(sys::uart_driver_install(
            UART_NUM,
            2048,
            0,
            0,
            ptr::null_mut(),
            0,
        ))?;

        uart_write_str("READY\n");

        let mut line: [u8; 160] = [0; 160];
        let mut idx: usize = 0;

        loop {
            let mut b: [u8; 1] = [0];
            let n = sys::uart_read_bytes(
                UART_NUM,
                b.as_mut_ptr() as *mut c_void,
                1,
                20,
            );

            if n > 0 {
                let c = b[0];

                if c == b'\n' || c == b'\r' {
                    if idx > 0 {
                        let msg = core::str::from_utf8(&line[..idx]).unwrap_or("").trim();

                        if msg == "ping" {
                            uart_write_str("pong\n");
                        } else if msg == "enroll" {
                            handle_enroll();
                        } else if let Some(hex) = msg.strip_prefix("challenge=") {
                            handle_challenge_hex(hex);
                        } else if msg == "uid" {
                            handle_uid();
                        } else {
                            uart_write_str("ERR=unknown_cmd\n");
                        }

                        idx = 0;
                    }
                } else {
                    if idx < line.len() {
                        line[idx] = c;
                        idx += 1;
                    } else {
                        idx = 0;
                        uart_write_str("ERR=line_too_long\n");
                    }
                }
            }

            yield_1tick();
        }
    }
}
