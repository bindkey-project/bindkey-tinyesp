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

    fn atcab_genkey(key_id: u16, public_key: *mut u8) -> c_int;
    fn atcab_get_pubkey(key_id: u16, public_key: *mut u8) -> c_int;

    fn atcab_write_bytes_zone(zone: u8, slot: u16, offset_bytes: usize, data: *const u8, length: usize) -> c_int;
    fn atcab_read_bytes_zone(zone: u8, slot: u16, offset_bytes: usize, data: *mut u8, length: usize) -> c_int;

    fn atcab_ecdh(key_id: u16, public_key: *const u8, pms: *mut u8) -> c_int;
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
