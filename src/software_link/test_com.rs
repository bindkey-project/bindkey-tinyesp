use core::{ffi::c_void, mem::zeroed, ptr};
use esp_idf_sys as sys;
use crate::crypto::{get_global_disk, get_global_bk_table, mark_bk_table_dirty, secure_element::*};
use crate::usb_emulation::fake_usb::{reset_disk_state, enter_format_mode, exit_format_mode, is_disk_formatting};
use crate::fingerprint::*;
use crate::fingerprint::fingerprint_r503 as r503;

const UART_NUM: sys::uart_port_t = 1;
const RX_PIN: i32 = 1;
const TX_PIN: i32 = 2;
const BAUD: i32 = 115_200;

const SLOT: u16 = 0;

struct VolumeCmd{
    name: [u8; 32],
    name_len: usize,
    volume_id: [u8; 16],
    lba_start: u32,
    lba_end: u32,
    fields: u8              //bitmask: 0x01=name, 0x02=volume_id, 0x04=lba_start, 0x08=lba_end 
}

impl VolumeCmd{
    fn new() -> Self{
        Self{
            name: [0u8; 32],
            name_len: 0,
            volume_id: [0u8; 16],
            lba_start: 0,
            lba_end: 0,
            fields: 0
        }
    }

    fn is_complete(&self) -> bool{
        self.fields == 0x0F
    }

    fn reset(&mut self){
        *self = Self::new();
    }
}

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
            if crate::USE_R503 == 1 {
                let _ = r503::enroll_once();
            } else {
                let _ = enroll_once();
            }

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
    let fp_result = if crate::USE_R503 == 1 {
        r503::test_fingerprint_once()
    } else {
        test_fingerprint_once()
    };
    match fp_result {
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

        let mut vol_cmd = VolumeCmd::new();

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
                        }
                        else if msg == "enroll" {
                            handle_enroll();
                        }
                        else if let Some(hex) = msg.strip_prefix("challenge=") {
                            handle_challenge_hex(hex);
                        }
                        else if msg == "uid" {
                            handle_uid();
                        }
                        else if let Some(val) = msg.strip_prefix("volume_name="){
                            let bytes = val.as_bytes();
                            let len = bytes.len().min(32);
                            vol_cmd.name[..len].copy_from_slice(&bytes[..len]);
                            vol_cmd.name_len = len;
                            vol_cmd.fields |= 0x01;
                        }
                        else if let Some(val) = msg.strip_prefix("volume_id=") {                                                                                                                                                                                
                            let bytes = val.as_bytes();
                            let len = bytes.len().min(16);                                                                                                                                                                                                        
                            vol_cmd.volume_id = [0u8; 16]; //reset padding
                            vol_cmd.volume_id[..len].copy_from_slice(&bytes[..len]);                                                                                                                                                                              
                            vol_cmd.fields |= 0x02;  
                        }
                        else if let Some(val) = msg.strip_prefix("lba_start="){
                            match val.parse::<u32>(){
                                Ok(v) => {
                                    vol_cmd.lba_start = v;
                                    vol_cmd.fields |= 0x04;
                                }
                                Err(_) => uart_write_str("ERR=bad_lba_start\n"),
                            }
                        }
                        else if let Some(val) = msg.strip_prefix("lba_end="){
                            match val.parse::<u32>(){
                                Ok(v) => {
                                    vol_cmd.lba_end = v;
                                    vol_cmd.fields |= 0x08;
                                }
                                Err(_) => uart_write_str("ERR=bad_lba_end\n"),
                            }
                        }
                        else if msg == "action=init_format"{
                            if let Some(disk) = get_global_disk() {
                                disk.clear_volumes();
                            }
                            if let Some(table) = get_global_bk_table() {
                                let mut new_table = crate::crypto::volume_table::BkTable::new();
                                // Mark as initialized so the gate in TUR hides the disk
                                // on the next boot if no volumes are configured.
                                new_table.initialized = true;
                                *table = new_table;
                                mark_bk_table_dirty();
                            }
                            // Enter format mode: bypass the num_volumes==0 gate so the OS
                            // can still write the msdos partition table via force_format.
                            // The gate re-activates on the next boot if no volumes are added.
                            enter_format_mode();
                            vol_cmd.reset();
                            uart_write_str("STATUS=OK\n");
                            log::info!("action=init_format: volumes cleared, BK Table reset, format mode active");
                        }
                        else {
                            uart_write_str("ERR=unknown_cmd\n");
                        }

                        if vol_cmd.is_complete(){
                            handle_volume_create(&vol_cmd);
                            vol_cmd.reset();
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

fn handle_volume_create(cmd: &VolumeCmd){
    // Remember whether we are in a format session before doing any heavy work.
    // Used at the end to call exit_format_mode() once the first volume is created.
    let was_formatting = is_disk_formatting();

    // ── Idempotency + capacity guard (must run before any heavy work) ──────────
    // The host retry loop may send the same 4 commands multiple times if it
    // does not receive STATUS=OK in time.  We must NOT create duplicate slots.
    //
    // Rule 1 — duplicate LBA range: already registered → return OK immediately
    //   (same key will be re-derived on next boot from the existing BK Table entry)
    // Rule 2 — table full: reject early so the host knows init_format is needed.
    if let Some(table) = get_global_bk_table() {
        for i in 0..table.num_volumes as usize {
            let e = &table.entries[i];
            if e.lba_start == cmd.lba_start && e.lba_end == cmd.lba_end {
                uart_write_str("STATUS=OK\n");
                log::info!("volume_create: lba={}..{} already registered — idempotent OK",
                           cmd.lba_start, cmd.lba_end);
                // Idempotent: still exit format mode if it was active, so the OS can
                // proceed with mkpart/mkfs on the re-registered volume.
                if was_formatting { exit_format_mode(); }
                return;
            }
        }
        if table.num_volumes as usize >= crate::crypto::volume_table::MAX_VOLUMES {
            uart_write_str("STATUS=ERR=BK_TABLE_FULL\n");
            log::error!("volume_create: BK Table full ({} volumes), action=init_format required",
                        crate::crypto::volume_table::MAX_VOLUMES);
            return;
        }
    }
    // ────────────────────────────────────────────────────────────────────────────

    let se = match AteccSession::new(){
        Ok(s) => s,
        Err(rc) => { uart_write_str(&format!("STATUS=ERR={}\n", rc)); return; }
    };

    let owner_sn = match se.serial_number(){
        Ok(s) => s,
        Err(rc) => { uart_write_str(&format!("STATUS=ERR={}\n", rc)); return; }
    };

    log::info!("volume_create: volume_id={:02X?}", &cmd.volume_id);
    let key = match derive_volume_key_hmac(&se, 9, cmd.volume_id){
        Ok(k) => { log::info!("volume_create: key[0..4] = {:02X?}", &k[..4]); k },
        Err(rc) => { uart_write_str(&format!("STATUS=ERR={}\n", rc)); return; }
    };

    let disk = match get_global_disk(){
        Some(d) => d,
        None => { uart_write_str("STATUS=ERR=-1\n"); return; }
    };

    if let Err(rc) = disk.add_volume(cmd.lba_start, cmd.lba_end, &key) {
        uart_write_str(&format!("STATUS=ERR={}\n", rc));
        return;
    }

    // Update BK Table in RAM — flush deferred to next test_unit_ready_cb.
    // Must succeed: capacity was checked above, so failure here is unexpected.
    if let Some(table) = get_global_bk_table() {
        match table.add_volume(cmd.volume_id, cmd.lba_start, cmd.lba_end, owner_sn) {
            Ok(_) => mark_bk_table_dirty(),
            Err(rc) => {
                // Should not happen; log and propagate error so host does not
                // format with a key that will be lost on the next reboot.
                log::error!("volume_create: BK Table add_volume failed rc={} (unexpected)", rc);
                uart_write_str(&format!("STATUS=ERR={}\n", rc));
                return;
            }
        }
    }

    uart_write_str("STATUS=OK\n");
    log::info!("volume created: lba={}..{} id={:?}", cmd.lba_start, cmd.lba_end,
               core::str::from_utf8(&cmd.volume_id).unwrap_or("?"));
    disk.log_volume_table();

    // If this volume was created during an active format session (action=init_format
    // was sent before), exit format mode now: the gate re-enables and UNIT_ATTENTION
    // is queued so the OS discards stale cached partition state.
    if was_formatting {
        exit_format_mode();
    }
}
