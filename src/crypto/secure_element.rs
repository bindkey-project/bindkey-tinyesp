use core::ffi::c_int;
use esp_idf_sys::*;

//error code CryptoAuthLib: 0 = ATCA_SUCCESS
pub const ATCA_SUCCESS: i32 = 0;

//zones/lock zones (CryptoAuthLib)
pub const ATCA_ZONE_CONFIG: u8 = 0x00;
pub const ATCA_ZONE_OTP: u8 = 0x01;
pub const ATCA_ZONE_DATA: u8 = 0x02;

//is_locked zones (CryptoAuthLib: 0=config, 1=data)
pub const LOCK_ZONE_CONFIG: u8 = 0;
pub const LOCK_ZONE_DATA: u8 = 1;

//sizes
pub const ATCA_SERIAL_NUM_SIZE: usize = 9;
pub const ATCA_PUBKEY_SIZE: usize = 64;
pub const ATCA_PRIVKEY_SIZE: usize = 32;
pub const ATCA_SIG_SIZE: usize = 64;

//KDF constants
pub const KDF_MODE_SOURCE_SLOT: u8 = 0x02;
pub const KDF_MODE_TARGET_OUTPUT: u8 = 0x10;
pub const KDF_MODE_ALG_HKDF: u8 = 0x40;
pub const KDF_DETAILS_HKDF_MSG_LOC_INPUT: u32 = 0x0000_0002;

#[repr(C)]
pub struct ATCAIfaceCfg {
    _private: [u8; 0] //opaque config no display to rust layout
}

extern "C" {
    // Config "default" fournie côté C (esp-cryptoauthlib) et remplie via sdkconfig
    static cfg_ateccx08a_i2c_default: ATCAIfaceCfg;

    fn atcab_init(cfg: *const ATCAIfaceCfg) -> c_int;
    fn atcab_info(rev: *mut u8) -> c_int;
    fn atcab_release() -> c_int;
    fn atcab_read_serial_number(sn: *mut u8) -> c_int;
    fn atcab_random(random_number: *mut u8) -> c_int;
    fn atcab_lock_config_zone() -> c_int;
    fn atcab_is_locked(zone: u8, is_locked: *mut bool) -> c_int;
    fn atcab_read_config_zone(config_data: *mut u8) -> c_int;

    fn atcab_genkey(key_id: u16, public_key: *mut u8) -> c_int;
    fn atcab_get_pubkey(key_id: u16, public_key: *mut u8) -> c_int;

    fn atcab_sign(key_id: u16, msg: *const u8, sig: *mut u8) -> c_int;

    fn atcab_write_bytes_zone(zone: u8, slot: u16, offset_bytes: usize, data: *const u8, length: usize) -> c_int;
    fn atcab_read_bytes_zone(zone: u8, slot: u16, offset_bytes: usize, data: *mut u8, length: usize) -> c_int;

    fn atcab_ecdh(key_id: u16, public_key: *const u8, pms: *mut u8) -> c_int;
    
    fn atcab_kdf(mode: u8, key_id: u16, details: u32, message: *const u8, out_data: *mut u8, out_nonce: *mut u8) -> c_int; 
}

pub struct AteccSession;

impl AteccSession{
    pub fn new() -> Result<Self, i32>{
        unsafe{
            let rc = atcab_init(&cfg_ateccx08a_i2c_default as *const _);
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(Self)
    }

    pub fn info(&self) -> Result<[u8; 4], i32>{
        let mut rev = [0u8; 4];
        unsafe{
            let rc = atcab_info(rev.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(rev)
    }

    pub fn serial_number(&self) -> Result<[u8; ATCA_SERIAL_NUM_SIZE], i32>{
        let mut sn = [0u8; ATCA_SERIAL_NUM_SIZE];
        unsafe{
            let rc = atcab_read_serial_number(sn.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(sn)
    }

    pub fn random32(&self) -> Result<[u8; 32], i32>{
        let mut r = [0u8; 32];
        unsafe{
            let rc = atcab_random(r.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(r)
    }

    pub fn lock_status(&self) -> Result<(bool, bool), i32>{
        unsafe{
            let mut cfg_locked = false;
            let mut data_locked = false;
            let rc1 = atcab_is_locked(LOCK_ZONE_CONFIG, &mut cfg_locked);
            if rc1 != ATCA_SUCCESS{
                return Err(rc1);
            }
            let rc2 = atcab_is_locked(LOCK_ZONE_DATA, &mut data_locked);
            if rc2 != ATCA_SUCCESS{
                return Err(rc2);
            }
            Ok((cfg_locked, data_locked))
        }
    }

    pub fn gen_ecc_keypair(&self, slot: u16) -> Result<[u8; ATCA_PUBKEY_SIZE], i32>{
        let mut pk = [0u8; ATCA_PUBKEY_SIZE];
        unsafe{
            let rc = atcab_genkey(slot, pk.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(pk)
    }

    pub fn get_pubkey(&self, slot: u16) -> Result<[u8; ATCA_PUBKEY_SIZE], i32>{
        let mut pk = [0u8; ATCA_PUBKEY_SIZE];
        unsafe{
            let rc = atcab_get_pubkey(slot, pk.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(pk)
    }

    pub fn ecdh(&self, priv_slot: u16, peer_pubkey: &[u8; ATCA_PUBKEY_SIZE]) -> Result<[u8; 32], i32>{
        let mut pms = [0u8; 32];
        unsafe{
            let rc = atcab_ecdh(priv_slot, peer_pubkey.as_ptr(), pms.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(pms)
    }

    pub fn ensure_master_secret_dev(&self, slot: u16) -> Result<[u8; 32], i32>{
        let mut master = [0u8; 32];
        unsafe{
            let rc = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 0, master.as_mut_ptr(), master.len());
            if rc == ATCA_SUCCESS{
                return Ok(master);
            }

            let rc = atcab_random(master.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }

            let rc = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, 0, master.as_ptr(), master.len());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }

            let mut check = [0u8; 32];
            let rc = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 0, check.as_mut_ptr(), check.len());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }

            Ok(check)
        }
    }

    pub fn write_data_slot(&self, slot: u16, offset: usize, data: &[u8]) -> Result<(), i32>{
        unsafe{
            let rc = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, offset, data.as_ptr(), data.len());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(())
    }

    pub fn read_data_slot(&self, slot: u16, offset: usize, out: &mut [u8]) -> Result<(), i32>{
        unsafe{
            let rc = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, offset, out.as_mut_ptr(), out.len());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(())
    }   

    pub fn read_config_zone(&self) -> Result<[u8; 128], i32>{
        let mut cfg = [0u8; 128];
        unsafe{
            let rc = atcab_read_config_zone(cfg.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(cfg)
    }

    //irreversible action
    pub fn lock_config_zone(&self) -> Result<(), i32>{
        let (cfg_locked, _) = self.lock_status()?;
        if cfg_locked{
            log::info!("Config already locked");
            return Ok(());
        }

        log::warn!("Locking CONFIG new zone (IRREVERSIBLE)...");
        unsafe{
            let rc = atcab_lock_config_zone();
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(())
    }

    pub fn sign(&self, priv_slot: u16, msg32: &[u8;32]) -> Result<[u8; ATCA_SIG_SIZE], i32>{
        let mut sig = [0u8; ATCA_SIG_SIZE];
        unsafe{
            let rc = atcab_sign(priv_slot, msg32.as_ptr(), sig.as_mut_ptr());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
            Ok(sig)
        }   
    }

    pub fn kdf_hkdf_from_slot(&self, key_id: u16, message: &[u8]) -> Result<[u8; 32], i32>{
        let mut out = [0u8; 32];
        let mode = KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT | KDF_MODE_ALG_HKDF;
        let details = KDF_DETAILS_HKDF_MSG_LOC_INPUT;

        unsafe{
            let rc = atcab_kdf(mode, key_id, details, message.as_ptr(), out.as_mut_ptr(), core::ptr::null_mut());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
            Ok(out)
        }
    }

}

impl Drop for AteccSession{
    fn drop(&mut self){
        unsafe{
            let _ = atcab_release();
        }
    }
}

pub fn atecc_smoke() -> Result<[u8; 4], i32>{
    let se = AteccSession::new()?;
    se.info()
}

pub fn se_dump_and_master_dev() -> Result<(), i32> {
    let se = AteccSession::new()?;

    let rev = se.info()?;
    let sn = se.serial_number()?;
    let (cfg_locked, data_locked) = se.lock_status()?;

    log::info!("rev={:02X?}", rev);
    log::info!("sn={:02X?}", sn);
    log::info!("locked cfg={} data={}", cfg_locked, data_locked);

    // DEV: récupérer/provisionner le master
    let master = se.ensure_master_secret_dev(9)?;
    log::info!("master(dev)={:02X?}", master);

    Ok(())
}

pub fn dump_config_zone() -> Result<[u8; 128], i32>{
    let se = AteccSession::new()?;
    se.read_config_zone()
}

//helper for dump_config_zone
pub fn dump_slot_keycfg(cfg: &[u8; 128]) {
    for s in 0..16u8 {
        let sc_off = 20 + 2 * (s as usize);
        let kc_off = 96 + 2 * (s as usize);

        let slotcfg = u16::from_le_bytes([cfg[sc_off], cfg[sc_off + 1]]);
        let keycfg  = u16::from_le_bytes([cfg[kc_off], cfg[kc_off + 1]]);

        log::info!("slot {:02}: SlotConfig=0x{:04X}  KeyConfig=0x{:04X}", s, slotcfg, keycfg);
    }
}


pub fn test_ecc_identity(slot: u16) -> Result<(), i32>{
    let se = AteccSession::new()?;

    let rev = se.info()?;
    let sn = se.serial_number()?;
    log::info!("rev={:02X?}", rev);
    log::info!("sn={:02X?}", sn);

    match se.gen_ecc_keypair(slot){
        Ok(pubkey) => {
            log::info!("GenKey OK (slot {})", slot);
            log::info!("pubkey(X||Y)={:02X?}", pubkey);
        }
        Err(rc) => {
            log::warn!("GenKey failed rc={} (slot {} maybe already provisioned or not allowed). Trying GetPubKey...", rc, slot);
            let pubkey = se.get_pubkey(slot)?;
            log::info!("GetPubKey OK (slot {})", slot);
            log::info!("pubkey(X||Y)={:02X?}", pubkey);
        }
    }

    Ok(())
}

pub fn provisionning_lock_config() -> Result<(), i32>{
    let se = AteccSession::new()?;
    se.lock_config_zone()?;
    let (cfg_locked, data_locked) = se.lock_status()?;
    log::info!("locked cfg={} data={}", cfg_locked, data_locked);
    Ok(())
}


pub fn test_get_pub_key(slot: u16) -> Result<(), i32>{
    let se = AteccSession::new()?;
    let pk = se.get_pubkey(slot)?;
    log::info!("GetPubKey({})={:02X?}", slot, pk);
    Ok(())
}

pub fn test_identity_sign() -> Result<(), i32>{
    let se = AteccSession::new()?;
    let challenge = [0x42u8; 32];
    let sig = se.sign(0, &challenge)?;
    log::info!("ECDSA signature (slot0)={:02X?}", sig);
    Ok(())
}

//helpers
pub fn slotcfg(cfg: &[u8; 128], slot: usize) -> u16{
    let off = 20 + 2 * slot;
    u16::from_le_bytes([cfg[off], cfg[off + 1]])
}
pub fn keycfg(cfg: &[u8; 128], slot: usize) -> u16{
    let off = 96 + 2 * slot;
    u16::from_le_bytes([cfg[off], cfg[off + 1]])
}

pub fn scan_slots_readonly() -> Result<(), i32>{
    let se = AteccSession::new()?;
    log::info!("Scanning DATA slots READ-only (32B @ offset0)...");
    let mut buf = [0u8; 32];
    for slot in 0u16..16u16{
        if slot == 0{
            continue; //don't test identity slot
        }
        let r = se.read_data_slot(slot, 0, &mut buf);
        match r{
            Ok(()) => log::info!("slot {:02}: READ OK  first8={:02X?}", slot, &buf[..8]),
            Err(rc) => log::info!("slot {:02}: READ fail rc={}", slot, rc)
        }
    }
    Ok(())
}

pub fn scan_slots_write_read_data_like() -> Result<(), i32>{
    let se = AteccSession::new()?;
    let cfg = se.read_config_zone()?;

    log::info!("Scanning DATA-like slots (8..14) WRITE+READ 32B...");
    let pattern = [0xA5u8; 32];
    let mut buf = [0u8; 32];

    for slot in 8u16..=14u16{
        let sc = slotcfg(&cfg, slot as usize);
        let kc = keycfg(&cfg, slot as usize);
        log::info!("slot {:02}: SlotConfig=0x{:04X} KeyConfig=0x{:04X}", slot, sc, kc);

        let w = se.write_data_slot(slot, 0, &pattern);
        match w {
            Ok(()) => log::info!("slot {:02}: WRITE OK", slot),
            Err(rc) =>{
                log::info!("slot {:02}: WRITE fail rc={}", slot, rc);
                continue;
            }
        }

        let r = se.read_data_slot(slot, 0, &mut buf);
        match r{
            Ok(()) => log::info!("slot {:02}: READ OK match={}", slot, buf == pattern),
            Err(rc) => log::info!("slot {:02}: READ fail rc={}", slot, rc)
        }
    }

    Ok(())
}

pub fn provision_root_secret(slot: u16) -> Result<(), i32>{
    let se = AteccSession::new()?;
    let secret = se.random32()?;
    se.write_data_slot(slot, 0, &secret)?;
    log::info!("Root secret provisioned in slot {} (write-only)", slot);
    Ok(())
}

pub fn derive_volume_key_example(se: &AteccSession, volume_id: [u8; 16]) -> Result<[u8; 32], i32>{
    let sn = se.serial_number()?; //9 bytes

    let mut msg = [0u8; 9 + 16 + 16];
    msg[0..9].copy_from_slice(&sn);
    msg[9..25].copy_from_slice(&volume_id);
    msg[25..].copy_from_slice(b"bindkey-volume-v1");

    let k = se.kdf_hkdf_from_slot(9, &msg)?;

    //voir comment effacer la mémoire de l'esp pour enlever la clef
    Ok(k)
}