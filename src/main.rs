use esp_idf_svc::sys::link_patches;
use esp_idf_svc::log::EspLogger;
use esp_idf_sys::*;

mod usb_emulation;
mod spi_link;
mod crypto;
mod fingerprint;
mod software_link;

use crate::usb_emulation::fake_usb::*;
use crate::spi_link::spi_master::SpiMaster;
use crate::spi_link::api_spi::set_global_spi;
use crate::fingerprint::*;
use crate::crypto::secure_element::*;
use crate::crypto::aes::*;
use crate::crypto::encrypted_disk::{EncryptedDisk, set_global_disk};
use crate::software_link::*;

fn main() {
    // Obligatoire pour esp-idf-sys
    link_patches();

    // Logs ESP
    EspLogger::initialize_default();

    log::info!("Fingerprint authentication required...");
    /*match fingerprint_validation(){
        Ok(()) => log::info!("Fingerprint authenticated !"),
        Err(e) => {
            log::error!("Fingerprint error : {}", e);
            return;
        }
    }*/
    match fingerprint::init(){
        Ok(()) => log::info!("Fingerprint init ok"),
        Err(e) => {
            log::error!("Fingerprint error : {}", e);
            return;
        }
    }

    match test_fingerprint_once(){
        Ok(()) => log::info!("Fingerprint authenticated !"),
        Err(e) => {
            log::error!("Fingerprint error : {}", e);
            return;
        }
    }
    

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
    
    let key = match(|| -> Result<[u8; 32], i32>{
        let se = AteccSession::new()?;
        let volume_id: [u8; 16] = *b"bindkey-vol-0001";
        derive_volume_key_hmac(&se, 9, volume_id)
    })(){
        Ok(k) => {
            log::info!("Derived disk key from SE ok");
            k
        },
        Err(err) => {
            log::error!("derive_volume_key_hmac failed {} ({})", 
                err,
                unsafe{
                    core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy()
                } 
            );
            return;
        }
    };

    let mut disk_box: Box<EncryptedDisk> = match EncryptedDisk::new(&key){
        Ok(d) => Box::new(d),
        Err(err) => {
            log::error!(
                "EncryptedDisk::new failed {} ({})",
                err,
                unsafe{core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy()}
            );
            return;
        }
    };

    let disk_ref: &'static mut EncryptedDisk = Box::leak(disk_box);
    set_global_disk(disk_ref);
    log::info!("EncryptedDisk initialized (heap)");

    unsafe{
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

    /*match test_fingerprint(){
        Ok(()) => log::info!("Ok"),
        Err(e) => log::error!("{}", e)
    }*/

    /*match uart_proto_task(){
        Ok(()) => log::info!("valid"),
        Err(e) => log::info!("invalid : {}", e)
    }*/

    match start_uart_task(1){
        Ok(()) => log::info!("valid"),
        Err(e) => log::info!("invalid : {}", e)
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

        match fingerprint::check_once(25_000)? {
            true => log::info!("✅ Doigt reconnu"),
            false => return Err("Doigt non reconnu".into()),
        }
    }

    log::info!("🎉 Fingerprint validé 3/3");
    Ok(())
}
