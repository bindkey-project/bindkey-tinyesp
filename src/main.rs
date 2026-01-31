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
use crate::crypto::aes::*;

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

    match test_secure_element(){
        Ok(()) => log::info!("Secure Element ok"),
        Err(e) => log::error!("Secure Element failed : {}", e)
    }

    match test_aes_gcm(){
        Ok(()) => log::info!("AES ok"),
        Err(e) => log::error!("AES failed : {}", e)
    }

    match test_aes_gcm_with_se(9) {
        Ok(()) => log::info!("AES-GCM(SE) ok"),
        Err(rc) => log::error!("AES-GCM(SE) failed rc={}", rc),
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
