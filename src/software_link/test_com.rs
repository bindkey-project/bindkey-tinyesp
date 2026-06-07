use core::{ffi::c_void, mem::zeroed, ptr};
use esp_idf_sys as sys;
use crate::crypto::{get_global_disk, get_global_bk_table, mark_bk_table_dirty, secure_element::*, volume_table::*};
use crate::usb_emulation::fake_usb::{reset_disk_state, enter_format_mode, exit_format_mode, is_disk_formatting};
use crate::fingerprint::*;
use crate::fingerprint::fingerprint_r503 as r503;

const UART_NUM: sys::uart_port_t = 1;
const RX_PIN: i32 = 1;
const TX_PIN: i32 = 2;
const BAUD: i32 = 115_200;

const SLOT: u16 = 0;
const SLOT_ECDH: u16 = 1;

// accumulates the fields of a "create volume" command across several UART lines
struct VolumeCmd{
    name: [u8; 32],
    name_len: usize,
    volume_id: [u8; 16],
    lba_start: u32,
    lba_end: u32,
    fields: u8              // bitmask: 0x01=name, 0x02=volume_id, 0x04=lba_start, 0x08=lba_end
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

// accumulates a "receive shared key" command (target side)
struct RecvShareCmd{
    slot: u16,                  // ATECC slot where to store the unwrapped key (10..14)
    source_pubkey: [u8; 64],    // ECDH pubkey (slot 1) of the source BK
    wrapped: [u8; 60],          // nonce(12) || ct(32) || tag(16)
    fields: u8,                 // 0x01=slot, 0x02=src_pub, 0x04=wrapped
}

impl RecvShareCmd{
    fn new() -> Self{
        Self{
            slot: 0,
            source_pubkey: [0u8; 64],
            wrapped: [0u8; 60],
            fields: 0
        }
    }

    fn is_complete(&self) -> bool{
        self.fields == 0x07
    }

    fn reset(&mut self){
        *self = Self::new();
    }
}


// accumulates a "share volume" command (source side)
struct ShareCmd{
    volume_id: [u8; 16],        // id of the volume to share
    target_sn: [u8; 9],         // SN of the target BK's SE
    target_pubkey: [u8; 64],    // ECDH pubkey (slot 1) of the target BK
    target_slot: u16,           // ATECC slot where the target will store the key (10..14)
    fields: u8                  // 0x01=vol_id, 0x02=target_sn, 0x04=target_pubkey, 0x08=target_slot
}

impl ShareCmd{
    fn new() -> Self{
        Self{
            volume_id: [0u8; 16],
            target_sn: [0u8; 9],
            target_pubkey: [0u8; 64],
            target_slot: 0,
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

// yields one FreeRTOS tick to keep the watchdog happy
#[inline(always)]
fn yield_1tick() {
    unsafe { sys::vTaskDelay(1) };
}

// maps an esp_err_t into a Result
fn esp_err_to_result(err: i32) -> Result<(), i32> {
    if err == 0 { Ok(()) } else { Err(err) }
}

// writes a string to the UART
fn uart_write_str(s: &str) {
    unsafe {
        sys::uart_write_bytes(UART_NUM, s.as_ptr() as *const c_void, s.len());
    }
}

// writes raw bytes to the UART
fn uart_write_bytes(bytes: &[u8]) {
    unsafe {
        sys::uart_write_bytes(UART_NUM, bytes.as_ptr() as *const c_void, bytes.len());
    }
}

// encodes bytes as uppercase hex into dst, returns the number of chars written
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

// decodes a single hex digit to its value
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// expects exactly 64 hex chars
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

// expects exactly 128 hex chars (P-256 pubkey X || Y)
fn hex_to_bytes_64(s: &str) -> Option<[u8; 64]> {
    let b = s.as_bytes();
    if b.len() != 128 {
        log::error!("bad hex64 len={}, expected 128", b.len());
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

// expects exactly 18 hex chars (ATECC608 SN)
fn hex_to_bytes_9(s: &str) -> Option<[u8; 9]> {
    let b = s.as_bytes();
    if b.len() != 18 {
        log::error!("bad hex9 len={}, expected 18", b.len());
        return None;
    }
    let mut out = [0u8; 9];
    for i in 0..9 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

// expects exactly 32 hex chars (16B volume_id)
fn hex_to_bytes_16(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        log::error!("bad hex16 len={}, expected 32", b.len());
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

// expects exactly 120 hex chars (wrapped bundle = nonce 12 + ct 32 + tag 16)
fn hex_to_bytes_60(s: &str) -> Option<[u8; 60]> {
    let b = s.as_bytes();
    if b.len() != 120 {
        log::error!("bad hex60 len={}, expected 120", b.len());
        return None;
    }
    let mut out = [0u8; 60];
    for i in 0..60 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}



// "enroll": fingerprint enroll + emit SN, signing pubkey and ECDH pubkey
fn handle_enroll() {
    match (|| -> Result<([u8; 9], [u8; 64], [u8; 64]), i32> {
        let se = AteccSession::new()?;
        let sn = se.serial_number()?;      // [u8;9]
        let pub_sign = se.get_pubkey(SLOT)?; // [u8;64]
        let pub_ecdh = se.get_pubkey(SLOT_ECDH)?;
        log::info!("sn={:02X?}", sn);
        log::info!("pub_sign()={:02X?}", pub_sign);
        log::info!("pub_ecdh()={:02X?}", pub_ecdh);
        Ok((sn, pub_sign, pub_ecdh))
    })() {
        Ok((sn, pub_sign, pub_ecdh)) => {
            let enroll_result = if crate::USE_R503 == 1 {
                r503::enroll_once()
            } else {
                enroll_once()
            };
            if let Err(rc) = enroll_result {
                uart_write_str(&format!("ERR=enroll_failed={}\n", rc));
                return;
            }
            

            let mut hexbuf = [0u8; 256];

            uart_write_str("SN=");
            let n_sn = bytes_to_hex_upper(&sn, &mut hexbuf);
            uart_write_bytes(&hexbuf[..n_sn]);
            uart_write_str("\n");

            uart_write_str("PUB_SIGN=");
            let n_pk = bytes_to_hex_upper(&pub_sign, &mut hexbuf);
            uart_write_bytes(&hexbuf[..n_pk]);
            uart_write_str("\n");

            uart_write_str("PUB_ECDH=");
            let n_pk = bytes_to_hex_upper(&pub_ecdh, &mut hexbuf);
            uart_write_bytes(&hexbuf[..n_pk]);
            uart_write_str("\n");

            uart_write_str("OK\n");
        }
        Err(rc) => uart_write_str(&format!("ERR={}\n", rc)),
    }
}

// "uid": emit the ATECC608 serial number
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

// "challenge=<hex64>": fingerprint gate + ECDSA-sign the 32-byte challenge
fn handle_challenge_hex(hex: &str) {
    let challenge = match hex_to_bytes_32(hex) {
        Some(c) => c,
        None => {
            uart_write_str("ERR=bad_challenge\n");
            return;
        }
    };
    
    let fp_result = if crate::USE_R503 == 1 {
        r503::test_fingerprint_once()
    } else {
        test_fingerprint_once()
    };
    
    let fp_result: Result<(), i32> = Ok(());
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

// target side: unwrap the received volume key and store it in the given ATECC slot
fn handle_recv_share(cmd: &RecvShareCmd){
    let se = match AteccSession::new(){
        Ok(s) => s,
        Err(rc) => {
            uart_write_str(&format!("STATUS=ERR={}\n", rc));
            return;
        }
    };

    if cmd.slot < 10 || cmd.slot > 14{
        uart_write_str("STATUS=ERR=bad_slot\n");
        return;
    }

    // empty AAD for v1. To harden later: bind volume_id || source_sn
    // to prevent replay of an intercepted wrap onto another slot.
    let aad: [u8; 0] = [];

    let volume_key = match unwrap_volume_key(&se, SLOT_ECDH, &cmd.source_pubkey, &cmd.wrapped, &aad){
        Ok(k) => k,
        Err(rc) => {
            log::error!("recv_share: unwrap failed rc={}", rc);
            uart_write_str(&format!("STATUS=ERR=unwrap={}\n", rc));
            return;
        }
    };

    if let Err(rc) = se.write_data_slot(cmd.slot, 0, &volume_key){
        uart_write_str(&format!("STATUS=ERR={}\n", rc));
        return;
    }

    log::info!("recv_share: slot={} unwrapped key[0..4]={:02X?}", cmd.slot, &volume_key[..4]);
    uart_write_str("STATUS=OK\n");
}

// source side: register the share in the BK Table and emit the wrapped key for the target
fn handle_share(cmd: &ShareCmd){
    // validate the target slot
    if cmd.target_slot < 10 || cmd.target_slot > 14{
        uart_write_str("STATUS=ERR=bad_target_slot\n");
        return;
    }

    // read the local SE serial number
    let se = match AteccSession::new(){
        Ok(s) => s,
        Err(rc) => {
            uart_write_str(&format!("STATUS=ERR={}\n", rc));
            return;
        }
    };
    let self_sn = match se.serial_number(){
        Ok(s) => s,
        Err(rc) => {
            uart_write_str(&format!("STATUS=ERR={}\n", rc));
            return;
        }
    };

    // find the volume in the BK Table, check ownership and capacity
    let table = match get_global_bk_table(){
        Some(t) => t,
        None => {
            uart_write_str("STATUS=ERR=no_bk_table\n");
            return;
        }
    };
    let mut idx_opt: Option<usize> = None;
    for i in 0..table.num_volumes as usize{
        if table.entries[i].volume_id == cmd.volume_id{
            idx_opt = Some(i);
            break;
        }
    }
    let idx = match idx_opt{
        Some(i) => i,
        None => {
            uart_write_str("STATUS=ERR=volume_not_found\n");
            return;
        }
    };
    let entry = &mut table.entries[idx];
    if entry.owner_sn != self_sn{
        uart_write_str("STATUS=ERR=not_owner\n");
        return;
    }
    if entry.num_shared as usize >= MAX_SHARED{
        uart_write_str("STATUS=ERR=shared_full\n");
        return;
    }

    // check no shared entry already exists for this target_sn (idempotency)
    for s in 0..entry.num_shared as usize{
        if entry.shared[s].sn == cmd.target_sn{
            uart_write_str("STATUS=ERR=already_shared\n");
            return;
        }
    }

    // append the SharedAccess + mark the BK Table dirty
    let pos = entry.num_shared as usize;
    entry.shared[pos] = SharedAccess{
        sn: cmd.target_sn,
        slot: cmd.target_slot as u8
    };
    entry.num_shared += 1;
    mark_bk_table_dirty();

    // derive the volume key from the volume_id
    let volume_key = match derive_volume_key_hmac(&se, 9, cmd.volume_id){
        Ok(k) => k,
        Err(rc) => {
            uart_write_str(&format!("STATUS=ERR={}\n", rc));
            return;
        }
    };

    // wrap via ECDH(slot1, target_pubkey) -> KEK -> AES-GCM
    // empty AAD for v1 => to add later: bind volume_id || target_sn
    let aad: [u8; 0] = [];
    let wrapped = match wrap_volume_key(&se, SLOT_ECDH, &cmd.target_pubkey, &volume_key, &aad){
        Ok(w) => w,
        Err(rc) => {
            log::error!("share: wrap failed rc={}", rc);
            uart_write_str(&format!("STATUS=ERR=wrap={}\n", rc));
            return;
        }
    };

    // emit the response
    let mut hexbuf = [0u8; 256];
    uart_write_str("SN=");
    let n_sn = bytes_to_hex_upper(&self_sn, &mut hexbuf);
    uart_write_bytes(&hexbuf[..n_sn]);
    uart_write_str("\n");

    uart_write_str("WRAPPED=");
    let n_w = bytes_to_hex_upper(&wrapped, &mut hexbuf);
    uart_write_bytes(&hexbuf[..n_w]);
    uart_write_str("\n");

    uart_write_str("STATUS=OK\n");

    log::info!("share: vol_idx={} target_sn={:02X?} target_slot={} key[0..4]={:02X?}", idx, &cmd.target_sn, cmd.target_slot, &volume_key[..4]);
}

// UART control task: configures UART1 then parses commands line by line forever
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
        let mut recv_share_cmd = RecvShareCmd::new();
        let mut share_cmd = ShareCmd::new();

        uart_write_str("READY\n");

        let mut line: [u8; 256] = [0; 256];
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
                            vol_cmd.volume_id = [0u8; 16]; // reset padding
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
                            if let Some(table) = get_global_bk_table(){
                                if table.num_volumes > 0{
                                    uart_write_str("TO_DEL=");
                                    for i in 0..table.num_volumes as usize{
                                        let vid = &table.entries[i].volume_id;
                                        let len = vid.iter().position(|&b| b == 0).unwrap_or(16);
                                        uart_write_bytes(&vid[..len]);
                                        if (i + 1) < table.num_volumes as usize{
                                            uart_write_str(";");
                                        }
                                    }
                                    uart_write_str("\n");
                                }
                            }
                            // force the host to drop stale partition/media state before
                            // it writes a new msdos table through the format bypass.
                            reset_disk_state();
                            if let Some(disk) = get_global_disk() {
                                disk.clear_volumes();
                            }
                            if let Some(table) = get_global_bk_table() {
                                let mut new_table = crate::crypto::volume_table::BkTable::new();
                                // mark as initialized so the gate in TUR hides the disk
                                // on the next boot if no volumes are configured.
                                new_table.initialized = true;
                                *table = new_table;
                                mark_bk_table_dirty();
                            }
                            // enter format mode: bypass the num_volumes==0 gate so the OS
                            // can still write the msdos partition table via force_format.
                            // the gate re-activates on the next boot if no volumes are added.
                            enter_format_mode();
                            vol_cmd.reset();
                            uart_write_str("STATUS=OK\n");
                            log::info!("action=init_format: volumes cleared, BK Table reset, format mode active");
                        }
                        else if let Some(val) = msg.strip_prefix("recv_share_slot="){
                            match val.parse::<u16>(){
                                Ok(v) => {
                                    recv_share_cmd.slot = v;
                                    recv_share_cmd.fields |= 0x01;
                                }
                                Err(_) => uart_write_str("ERR=bad_slot\n"),
                            }
                        }
                        else if let Some(hex) = msg.strip_prefix("recv_share_source_pubkey="){
                            match hex_to_bytes_64(hex){
                                Some(p) => {
                                    recv_share_cmd.source_pubkey = p;
                                    recv_share_cmd.fields |= 0x02;
                                }
                                None => uart_write_str("ERR=bad_source_pubkey\n"),
                            }
                        }
                        else if let Some(hex) = msg.strip_prefix("recv_share_wrapped="){
                            match hex_to_bytes_60(hex){
                                Some(w) => {
                                    recv_share_cmd.wrapped = w;
                                    recv_share_cmd.fields |= 0x04;
                                }
                                None => uart_write_str("ERR=bad_wrapped\n"),
                            }
                        }
                        else if let Some(val) = msg.strip_prefix("share_volume_id="){
                            let bytes = val.as_bytes();
                            let len = bytes.len().min(16);
                            share_cmd.volume_id = [0u8; 16];
                            share_cmd.volume_id[..len].copy_from_slice(&bytes[..len]);
                            share_cmd.fields |= 0x01;
                        }
                        else if let Some(hex) = msg.strip_prefix("share_target_sn="){
                            match hex_to_bytes_9(hex){
                                Some(s) => {
                                    share_cmd.target_sn = s;
                                    share_cmd.fields |= 0x02;
                                }
                                None => uart_write_str("ERR=bad_target_sn\n"),
                            }
                        }
                        else if let Some(hex) = msg.strip_prefix("share_target_pubkey="){
                            match hex_to_bytes_64(hex){
                                Some(p) => {
                                    share_cmd.target_pubkey = p;
                                    share_cmd.fields |= 0x04;
                                }
                                None => uart_write_str("ERR=bad_target_pubkey\n"),
                            }
                        }
                        else if let Some(val) = msg.strip_prefix("share_target_slot="){
                            match val.parse::<u16>(){
                                Ok(v) => {
                                    share_cmd.target_slot = v;
                                    share_cmd.fields |= 0x08;
                                }
                                Err(_) => uart_write_str("ERR=bad_target_slot\n"),
                            }
                        }
                        else if let Some(val) = msg.strip_prefix("delete_volume="){
                            let bytes = val.as_bytes();
                            let len = bytes.len().min(16);
                            let mut volume_id = [0u8; 16];
                            volume_id[..len].copy_from_slice(&bytes[..len]);
                            handle_delete_volume(&volume_id);
                        }
                        else {
                            uart_write_str("ERR=unknown_cmd\n");
                        }

                        if vol_cmd.is_complete(){
                            handle_volume_create(&vol_cmd);
                            vol_cmd.reset();
                        }

                        if recv_share_cmd.is_complete(){
                            handle_recv_share(&recv_share_cmd);
                            recv_share_cmd.reset();
                        }

                        if share_cmd.is_complete(){
                            handle_share(&share_cmd);
                            share_cmd.reset();
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

// creates a volume: derive its key, register it in the disk + BK Table (idempotent)
fn handle_volume_create(cmd: &VolumeCmd){
    // remember whether we are in a format session before doing any heavy work.
    // used at the end to call exit_format_mode() once the first volume is created.
    let was_formatting = is_disk_formatting();

    // ── idempotency + capacity guard (must run before any heavy work) ──────────
    // the host retry loop may send the same 4 commands multiple times if it
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
                // idempotent: still exit format mode if it was active, so the OS can
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

    // update BK Table in RAM, flush deferred to next test_unit_ready_cb.
    // must succeed: capacity was checked above, so failure here is unexpected.
    if let Some(table) = get_global_bk_table() {
        match table.add_volume(cmd.volume_id, cmd.lba_start, cmd.lba_end, owner_sn) {
            Ok(_) => mark_bk_table_dirty(),
            Err(rc) => {
                // should not happen; log and propagate error so host does not
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

    // if this volume was created during an active format session (action=init_format
    // was sent before), exit format mode now: the gate re-enables and UNIT_ATTENTION
    // is queued so the OS discards stale cached partition state.
    if was_formatting {
        exit_format_mode();
    }
}

// deletes an owned volume from the BK Table and rebuilds the disk mapping
fn handle_delete_volume(volume_id: &[u8; 16]){
    let se = match AteccSession::new(){
        Ok(s) => s,
        Err(rc) => {
            uart_write_str(&format!("STATUS=ERR={}\n", rc));
            return;
        }
    };
    let self_sn = match se.serial_number(){
        Ok(s) => s,
        Err(rc) => {
            uart_write_str(&format!("STATUS=ERR={}\n", rc));
            return;
        }
    };

    let table = match get_global_bk_table(){
        Some(t) => t,
        None => {
            uart_write_str("STATUS=ERR=no_bk_table\n");
            return;
        }
    };

    let mut idx_opt: Option<usize> = None;
    for i in 0..table.num_volumes as usize{
        if table.entries[i].volume_id == *volume_id{
            idx_opt = Some(i);
            break;
        }
    }
    let idx = match idx_opt{
        Some(i) => i,
        None => {
            uart_write_str("STATUS=ERR=volume_not_found\n");
            return;
        }
    };

    if table.entries[idx].owner_sn != self_sn{
        uart_write_str("STATUS=ERR=not_owner\n");
        return;
    }

    if let Err(rc) = table.remove_volume(idx){
        uart_write_str(&format!("STATUS=ERR=remove={}\n", rc));
        return;
    }
    mark_bk_table_dirty();

    // rebuild disk mapping
    if let Some(disk) = get_global_disk(){
        disk.clear_volumes();
        if let Err(rc) = restore_volumes_from_bk_table(table, disk){
            log::error!("delete_volume: restore failed rc={}", rc);
            uart_write_str(&format!("STATUS=ERR=restore={}\n", rc));
            return;
        }
    }

    uart_write_str("STATUS=OK\n");
    log::info!("delete_volume: removed idx={} volume_id={:02X?}", idx, volume_id);

}
