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

// ======================================================================
// Fingerprint sensor selection flag
// 0 = BM-Lite (FPC, SPI2)
// 1 = R503 (Grow, UART2)
// ======================================================================
const USE_R503: u8 = 1;

fn main() {
    // Obligatoire pour esp-idf-sys
    link_patches();

    // Logs ESP
    EspLogger::initialize_default();

    log::info!("Fingerprint authentication required...");

    if USE_R503 == 1 {
        // ---------- R503 path ----------
        use crate::fingerprint::fingerprint_r503 as r503;
        match r503::init() {
            Ok(()) => log::info!("R503 init ok"),
            Err(e) => {
                log::error!("R503 error: {}", e);
                return;
            }
        }
        // Skip auth if no template enrolled (enroll via UART "enroll" command first)
        match r503::is_user_enrolled() {
            Ok(true) => {
                match r503::test_fingerprint_once() {
                    Ok(()) => log::info!("R503 authenticated!"),
                    Err(e) => {
                        log::error!("R503 error: {}", e);
                        return;
                    }
                }
            }
            Ok(false) => {
                log::warn!("R503: no template enrolled, skipping auth (use 'enroll' command)");
                // No auth needed — green = unlocked
                let _ = r503::led_on(r503::LedColor::Green);
            }
            Err(e) => {
                log::error!("R503 is_user_enrolled error: {}", e);
                return;
            }
        }
    } else {
        // ---------- BM-Lite path ----------
        match fingerprint::init(){
            Ok(()) => log::info!("Fingerprint init ok"),
            Err(e) => {
                log::error!("Fingerprint error : {}", e);
                return;
            }
        }
        // Skip auth if no template enrolled
        match fingerprint::is_user_enrolled() {
            Ok(true) => {
                match test_fingerprint_once(){
                    Ok(()) => log::info!("Fingerprint authenticated !"),
                    Err(e) => {
                        log::error!("Fingerprint error : {}", e);
                        return;
                    }
                }
            }
            Ok(false) => {
                log::warn!("BM-Lite: no template enrolled, skipping auth (use 'enroll' command)");
            }
            Err(e) => {
                log::error!("BM-Lite is_user_enrolled error: {}", e);
                return;
            }
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
    
    let (gpt_key, vol_key) = match(|| -> Result<([u8; 32], [u8; 32]), i32>{
        let se = AteccSession::new()?;
        let gpt_key = derive_volume_key_hmac(&se, 9, GPT_VOLUME_ID)?;
        let vol_id: [u8; 16] = *b"bindkey-vol-0001";
        let vol_key = derive_volume_key_hmac(&se, 9, vol_id)?;
        Ok((gpt_key, vol_key))
    })(){
        Ok(k) => {
            log::info!("Derived GPT key and volume key from SE ok");
            k
        },
        Err(err) => {
            log::error!("derive_volume_key_from_hmac failed {} ({})", 
                        err, 
                        unsafe{core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy()});
            return;
        }
    };
    let _gpt_key = gpt_key;

    let mut disk_box: Box<EncryptedDisk> = match EncryptedDisk::new(&vol_key){
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

    // Diagnostic: vérifier que le R503 répond toujours après toutes les inits
    if USE_R503 == 1 {
        use crate::fingerprint::fingerprint_r503 as r503;
        match r503::handshake() {
            Ok(()) => log::info!("R503 diagnostic: still alive after all inits"),
            Err(e) => log::error!("R503 diagnostic: DEAD after all inits: {}", e),
        }
    }

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
