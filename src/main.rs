use esp_idf_svc::sys::link_patches;
use esp_idf_svc::log::EspLogger;
use esp_idf_sys::*;

mod usb_emulation;
mod spi_link;
mod crypto;
mod fingerprint;

use crate::usb_emulation::fake_usb::*;
use crate::spi_link::spi_master::SpiMaster;
use crate::spi_link::api_spi::set_global_spi;
use crate::crypto::secure_element::*;

fn main() {
    // Obligatoire pour esp-idf-sys
    link_patches();

    // Logs ESP
    EspLogger::initialize_default();

    log::info!("Starting fake USB MSC + SPI...");

    let mut spi = match SpiMaster::new() {
        Ok(s) => s,
        Err(err) => {
            log::error!(
                "SpiMaster::new failed {} ({})",
                err,
                unsafe { core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy() }
            );
            return;
        }
    };

    if let Err(err) = spi.init(){
        log::error!("SpiMaster::init failed {} ({})",
            err,
            unsafe{
                core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy()
            }
        );
        return;
    }

    set_global_spi(&mut spi);

    unsafe {
        let err = init_fake_usb_msc();
        if err != ESP_OK {
            log::error!(
                "TinyUSB init failed: {} ({})",
                err,
                core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy()
            );
            return;
        }
    }

    log::info!("Testing ATECC608...");

    /*unsafe {
        i2c_init_legacy(i2c_port_t_I2C_NUM_0, 6, 7, 100_000);
        i2c_scan_legacy(i2c_port_t_I2C_NUM_0);
    }*/

    match atecc_smoke() {
        Ok(rev) => log::info!("ATECC revision: {:02X?}", rev),
        Err(rc) => log::error!("ATECC failed rc={}", rc),
    }

    match se_dump_and_master_dev(){
        Ok(()) => log::info!("ATECC test ok"),
        Err(rc) => log::info!("ATECC failed rc={}", rc)
    }

    match provisionning_lock_config(){
        Ok(()) =>{
            log::info!("✅ Lock config OK");

            match dump_config_zone(){
                Ok(cfg) =>{
                    log::info!("config zone dump (128B):");
                    for (i, chunk) in cfg.chunks(16).enumerate(){
                        log::info!("{:02}: {:02X?}", i, chunk);
                    }
                    dump_slot_keycfg(&cfg);
                }
                Err(rc) => log::error!("dump_config_zone failed rc={}", rc),
            }
        }
        Err(rc) =>{
            log::error!("❌ Lock config failed rc={}", rc);
        }
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

    match test_get_pub_key(0){
        Ok(()) => log::info!("Pubkey is well obtained"),
        Err(rc) => log::error!("Pubkey obtention is failed rc={}", rc)
    }

    match test_identity_sign(){
        Ok(()) => log::info!("Signature OK"),
        Err(rc) => log::error!("Signature error rc={}", rc)
    }

    match scan_slots_readonly(){
        Ok(()) => log::info!("scan read-only done"),
        Err(rc) => log::error!("scan read-only failed rc={}", rc),
    }

    match scan_slots_write_read_data_like(){
        Ok(()) => log::info!("scan write/read done"),
        Err(rc) => log::error!("scan write/read failed rc={}", rc),
    }






    match test_fingerprint(){
        Ok(()) => log::info!("Fingerprint ok"),
        Err(e) => log::error!("Fingerprint failed : {}", e)
    }

    log::info!("Fake MSC ready. Plug USB to host.");

    // IMPORTANT: ne jamais sortir de main
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn test_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    fingerprint::init()?;
    fingerprint::wipe_templates()?;
    fingerprint::enroll_user()?;

    // On exige 3 reconnaissances OK
    for i in 1..=3 {
        log::info!("🖐️ Test empreinte {i}/3 — pose ton doigt");

        match fingerprint::check_once(5_000)? {
            true => log::info!("✅ Doigt reconnu"),
            false => return Err("Doigt non reconnu".into()),
        }
    }

    log::info!("🎉 Fingerprint validé 3/3");
    Ok(())
}
