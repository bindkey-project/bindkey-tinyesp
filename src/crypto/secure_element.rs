use core::ffi::c_int;

//error code CryptoAuthLib: 0 = ATCA_SUCCESS
pub const ATCA_SUCCESS: i32 = 0;

//zones/lock zones (CryptoAuthLib)
pub const ATCA_ZONE_DATA: u8 = 0x02;

//is_locked zones (CryptoAuthLib: 0=config, 1=data)
pub const LOCK_ZONE_CONFIG: u8 = 0;
pub const LOCK_ZONE_DATA: u8 = 1;

//sizes
pub const ATCA_SERIAL_NUM_SIZE: usize = 9;
pub const ATCA_PUBKEY_SIZE: usize = 64;
pub const ATCA_SIG_SIZE: usize = 64;

pub const SHA_MODE_TARGET_OUT_ONLY: u8  = 0xC0;

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
    fn atcab_is_locked(zone: u8, is_locked: *mut bool) -> c_int;
    fn atcab_read_config_zone(config_data: *mut u8) -> c_int;

    fn atcab_lock_config_zone() -> c_int;
    fn atcab_lock_data_zone() -> c_int;
    
    fn atcab_genkey(key_id: u16, public_key: *mut u8) -> c_int;
    fn atcab_get_pubkey(key_id: u16, public_key: *mut u8) -> c_int;

    fn atcab_sign(key_id: u16, msg: *const u8, sig: *mut u8) -> c_int;

    fn atcab_write_bytes_zone(zone: u8, slot: u16, offset_bytes: usize, data: *const u8, length: usize) -> c_int;

    fn atcab_sha_hmac(data: *const u8, data_size: usize, key_slot: u16, digest: *mut u8, target: u8,) -> c_int;
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

    pub fn write_data_slot(&self, slot: u16, offset: usize, data: &[u8]) -> Result<(), i32>{
        unsafe{
            let rc = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, offset, data.as_ptr(), data.len());
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(())
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

    pub fn lock_data_zone(&self) -> Result<(), i32>{
        let (_, data_locked) = self.lock_status()?;
        if data_locked{
            log::info!("Data zone already locked");
            return Ok(());
        }

        log::warn!("Locking DATA zone (IRREVERSIBLE)...");
        unsafe{
            let rc = atcab_lock_data_zone();
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

    pub fn provision_root_secret_dev(&self, slot: u16) -> Result<(), i32>{
        let secret = self.random32()?;
        self.write_data_slot(slot, 0, &secret)?;
        log::warn!("root secret written in slot {} (derived keys will change if rewritten)", slot);
        Ok(())
    }

    pub fn sha_hmac(&self, key_slot: u16, msg: &[u8]) -> Result<[u8; 32], i32>{
        let mut out = [0u8; 32];
        unsafe{
            let rc = atcab_sha_hmac(msg.as_ptr(), msg.len(), key_slot, out.as_mut_ptr(), SHA_MODE_TARGET_OUT_ONLY);
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(out)
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

pub fn test_ecc_identity(slot: u16) -> Result<(), i32>{
    let se = AteccSession::new()?;

    let rev = se.info()?;
    let sn = se.serial_number()?;
    log::info!("rev={:02X?}", rev);
    log::info!("sn={:02X?}", sn);

    match se.get_pubkey(slot){
        Ok(pubkey) =>{
            log::info!("Identity already provisioned (slot {})", slot);
            log::info!("GetPubKey OK (slot {})", slot);
            log::info!("pubkey(X||Y)={:02X?}", pubkey);
            return Ok(());
        }
        Err(rc) =>{
            log::warn!("GetPubKey failed rc={} (slot {}). Will try GenKey (provisioning)...", rc, slot);
        }
    }

    let pubkey = se.gen_ecc_keypair(slot)?;
    log::info!("GenKey OK (slot {}) => identity created", slot);
    log::info!("pubkey(X||Y)={:02X?}", pubkey);
    
    Ok(())
}

pub fn test_identity_sign(slot: u16) -> Result<(), i32>{
    let se = AteccSession::new()?;
    let challenge = [0x42u8; 32];
    let sig = se.sign(slot, &challenge)?;
    log::info!("ECDSA signature (slot{})={:02X?}", slot, sig);
    Ok(())
}


pub fn derive_volume_key_hmac(se: &AteccSession, root_slot: u16, volume_id: [u8; 16]) -> Result<[u8; 32], i32>{
    let sn = se.serial_number()?;

    let mut msg = [0u8; 32];
    msg[0..9].copy_from_slice(&sn);
    msg[9..25].copy_from_slice(&volume_id);
    msg[25..].copy_from_slice(b"bindkey"); 

    se.sha_hmac(root_slot, &msg)
}

pub fn test_hmac_volume_derivation(root_slot: u16) -> Result<(), i32>{
    let se = AteccSession::new()?;
    let (_cfg_locked, data_locked) = se.lock_status()?;

    if !data_locked {
        log::warn!("DEV: data not locked => if you rewrite slot {}, derived key will change!", root_slot);
        
        //se.provision_root_secret_dev(root_slot)?; commented because done once
    }

    let vol_a = *b"VOLID-EXAMPLE-00";
    let vol_b = *b"VOLID-EXAMPLE-01";

    let k_a1 = derive_volume_key_hmac(&se, root_slot, vol_a)?;
    let k_a2 = derive_volume_key_hmac(&se, root_slot, vol_a)?;
    let k_b  = derive_volume_key_hmac(&se, root_slot, vol_b)?;

    log::info!("K(vol A) = {:02X?}", k_a1);
    log::info!("K(vol B) = {:02X?}", k_b);
    log::info!("stability check A: {}", k_a1 == k_a2);
    log::info!("difference check A vs B: {}", k_a1 != k_b);

    Ok(())
}

pub fn test_secure_element() -> Result<(), i32>{
    log::info!("Testing ATECC608...");
    match atecc_smoke() {
        Ok(rev) => log::info!("ATECC revision: {:02X?}", rev),
        Err(rc) => log::error!("ATECC failed rc={}", rc),
    }

    match AteccSession::new(){
        Ok(se) => match se.lock_status(){
            Ok((cfg_locked, data_locked)) =>{
                log::info!("ATECC lock status: cfg_locked={} data_locked={}", cfg_locked, data_locked);
            }
            Err(rc) => log::warn!("ATECC lock_status failed rc={}", rc)
        },
        Err(rc) => log::warn!("AteccSession::new failed rc={}", rc)
    }

    match test_ecc_identity(0) {
        Ok(()) => log::info!("ECC identity test OK (slot 0)"),
        Err(rc) =>{
            log::warn!("ECC test failed on slot 0 rc={}, trying slot 1...", rc);
            match test_ecc_identity(1) {
                Ok(()) => log::info!("ECC identity test OK (slot 1)"),
                Err(rc2) => log::error!("ECC identity test failed rc={} (slot0) rc={} (slot1)", rc, rc2),
            }
        }
    }

    match test_identity_sign(0){
        Ok(()) => log::info!("Signature OK"),
        Err(rc) => log::error!("Signature error rc={}", rc)
    }

    match test_hmac_volume_derivation(9){
        Ok(()) => log::info!("HMAC volume derivation OK"),
        Err(rc) => log::error!("HMAC volume derivation FAILED rc={}", rc)
    }

    Ok(())
}
