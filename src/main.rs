use esp_idf_svc::sys::link_patches;
use esp_idf_svc::log::EspLogger;
use esp_idf_sys::*;

mod usb_emulation;
mod spi_link;
mod crypto;
mod fingerprint;
mod software_link;
mod led;

use crate::crypto::{
    BkTable, set_global_bk_table,
    read_bk_table_from_storage, restore_volumes_from_bk_table,
};
use crate::usb_emulation::fake_usb::*;
use crate::spi_link::spi_master::SpiMaster;
use crate::spi_link::api_spi::set_global_spi;
use crate::fingerprint::*;
use crate::crypto::secure_element::*;
use crate::crypto::aes::*;
use crate::crypto::encrypted_disk::{EncryptedDisk, set_global_disk};
use crate::software_link::*;
use crate::led::*;

// ======================================================================
// Fingerprint sensor selection flag
// 0 = BM-Lite (FPC, SPI2) // attention si on remet le bmlite à changer spi3 -> spi2!
// 1 = R503 (Grow, UART2)
// ======================================================================
const USE_R503: u8 = 1;

fn main() {
    // Obligatoire pour esp-idf-sys
    link_patches();

    // Logs ESP
    EspLogger::initialize_default();

    let _led = LedGuard::new();
    
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

    // Check media presence avant de tenter quoi que ce soit qui dépend du média.
    // Si pas de clé USB branchée côté slave, skip le BkTable read et le warm-up :
    // ils tomberaient sur du junk (le slave répond avec du bruit quand il n'a pas
    // de disque) → CRC fail / timeouts inutiles.
    let mut media_ready = false;
    for attempt in 0..5u32 {
        match spi.get_status() {
            Ok((_, 2)) => {
                log::info!("Media ready at boot (attempt {})", attempt);
                media_ready = true;
                break;
            }
            Ok((_, bd)) => {
                log::info!("Media not ready at boot (bd={}, attempt {})", bd, attempt);
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err(e) => {
                log::warn!("get_status attempt {} failed err={}", attempt, e);
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }

    let bk_table = if media_ready {
        // Retry : le slave SPI peut prendre quelques secondes à démarrer après le boot
        let mut table = BkTable::new();
        for attempt in 0..5u32 {
            match read_bk_table_from_storage(&mut spi) {
                Ok(t) => {
                    table = t;
                    log::info!("BK Table: {} volume(s), attempt {}", table.num_volumes, attempt);
                    break;
                }
                Err(e) => {
                    log::warn!("BK Table read attempt {} failed err={}, retrying...", attempt, e);
                    if attempt < 4 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            }
        }
        table
    } else {
        log::info!("Skipping BK Table read — no media at boot");
        BkTable::new()
    };

    mark_bk_table_late_load_done();

    // Warm-up SPI uniquement si on a un média : permet au slave de se synchroniser
    // avant que TinyUSB ne démarre. Sinon le 1er capacity_cb appelé par l'OS pendant
    // l'énumération SCSI peut tomber sur un SPI pas encore prêt → fallback 4096
    // secteurs (2 MB) commit définitivement par l'OS.
    if media_ready {
        for i in 0..5u32 {
            match spi.get_capacity() {
                Ok((bs, bc)) if bs != 0 && bc != 0 => {
                    log::info!("SPI warm-up ok (bc={} bs={})", bc, bs);
                    break;
                }
                _ => {
                    log::warn!("SPI warm-up attempt {} not ready, retrying...", i);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }

    match AteccSession::new() {
        Ok(se) => {
            if let Err(err) = provision_config_zone(&se) {
                log::error!("SE provision_config_zone failed rc={}", err);
                return;
            }
            /*// One-shot : lock data zone (débloque Sign, slots 10-14 restent inscriptibles via WriteConfig=Always)
            // Idempotent : lock_data_zone() vérifie déjà si lockée
            if let Err(rc) = se.lock_data_zone() {
                log::error!("SE lock_data_zone failed rc={}", rc);
                return;
            }*/
            // Test : vérifie que slot 10 est toujours inscriptible après data lock (WriteConfig=Always)
            /*let dummy = [0xABu8; 32];
            match se.write_data_slot(10, 0, &dummy) {
                Ok(()) => log::info!("SE: slot 10 write OK — WriteConfig=Always confirmé"),
                Err(rc) => log::error!("SE: slot 10 write FAILED rc={} — PROBLÈME WriteConfig", rc),
            }
            match se.write_data_slot(8, 0, &dummy) {
                Ok(()) => log::info!("SE: slot 8 write OK — WriteConfig=Always confirmé"),
                Err(rc) => log::error!("SE: slot 8 write FAILED rc={} — PROBLÈME WriteConfig", rc),
            }*/
            // Lecture config zone pour vérifier SlotConfig[0/1], KeyConfig[0/1], ChipOptions
            match se.read_config_zone() {
                Ok(cfg) => {
                    log::info!("SE SlotConfig[0] (bytes 20-21) = {:02X?}", &cfg[20..22]);
                    log::info!("SE SlotConfig[1] (bytes 22-23) = {:02X?}", &cfg[22..24]);
                    log::info!("SE KeyConfig[0]  (bytes 96-97) = {:02X?}", &cfg[96..98]);
                    log::info!("SE KeyConfig[1]  (bytes 98-99) = {:02X?}", &cfg[98..100]);
                    log::info!("SE ChipOptions  (bytes 90-91) = {:02X?}", &cfg[90..92]);
                    log::info!("SE ChipMode     (byte 19)     = {:02X?}", cfg[19]);
                    // Détail ChipOptions (byte 90 low):
                    //   bit 0 = POST enable, bit 1 = IO Protection Key Enable
                    //   bit 2 = KDF AES Enable, bit 3 = ECDH Output Protection
                    let chipopts_lo = cfg[90];
                    log::info!("  ChipOptions.IOProt={} ECDH_Prot={}",
                        (chipopts_lo >> 1) & 1,
                        (chipopts_lo >> 3) & 1);
                }
                Err(rc) => log::error!("SE read_config_zone failed rc={}", rc),
            }
            // Diagnostique clé slot 0 : pubkey + force GenKey (Lockable=1) + test sign
            drop(se);
        }
        Err(err) => {
            log::error!("AteccSession::new failed rc={} (provisioning)", err);
            return;
        }
    }

    // === Pré-test ECDH round-trip (à retirer après validation) ===
    // Wrap puis unwrap d'une clef AAA...A en utilisant la pubkey ECDH locale comme peer_pub.
    // Si OK : atcab_ecdh + wrap_volume_key + unwrap_volume_key fonctionnent.
    match (|| -> Result<(), i32> {
        let se = AteccSession::new()?;

        // Diagnostic : état de lock des deux zones
        let (cfg_locked, data_locked) = se.lock_status()?;
        log::info!("ECDH test: lock_status cfg={} data={}", cfg_locked, data_locked);

        let my_pub = se.get_pubkey(1)?;
        log::info!("ECDH test: my_pub[0..4]={:02X?}", &my_pub[..4]);

        let original_key = [0xAAu8; 32];
        let aad: [u8; 0] = [];

        let wrapped = wrap_volume_key(&se, 1, &my_pub, &original_key, &aad)?;
        log::info!("ECDH test: wrapped[0..8]={:02X?}", &wrapped[..8]);

        let recovered = unwrap_volume_key(&se, 1, &my_pub, &wrapped, &aad)?;
        log::info!("ECDH test: recovered[0..4]={:02X?}", &recovered[..4]);

        if original_key == recovered {
            log::info!("ECDH round-trip OK");
        } else {
            log::error!("ECDH round-trip MISMATCH");
        }
        Ok(())
    })() {
        Ok(()) => {}
        Err(rc) => log::error!("ECDH round-trip failed rc={}", rc),
    }

    // Default key: identique sur toutes les BindKeys → la MBR/GPT et toute zone hors
    // BkTable est lisible cross-device. Aucune protection cryptographique réelle ici
    // (la BkTable au LBA 0 leake déjà la layout des volumes en clair). Les VRAIS volumes
    // déclarés dans la BkTable utilisent leur propre clé via derive_volume_key_hmac (owner)
    // ou via un slot ATECC (shared).
    const DEFAULT_VOLUME_KEY: [u8; 32] = *b"bindkey-default-key-shared!!!!v1";
    let vol_key = DEFAULT_VOLUME_KEY;
    log::info!("default vol_key[0..4] = {:02X?} (constant)", &vol_key[..4]);

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

    // BK Table en RAM globale (leak sur le heap — lifetime 'static)
    let bk_table_ref: &'static mut BkTable = Box::leak(Box::new(bk_table));
    set_global_bk_table(bk_table_ref);

    if let Err(e) = restore_volumes_from_bk_table(bk_table_ref, disk_ref){
        log::error!("BK Table volume restore failed: {}", e);
    }

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

    /*match test_secure_element(){
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
    }*/

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
