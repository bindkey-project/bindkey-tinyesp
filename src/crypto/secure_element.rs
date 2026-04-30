use core::ffi::c_int;
use esp_idf_sys::*;

use crate::crypto::aes::AesGcm;

//error code CryptoAuthLib: 0 = ATCA_SUCCESS
pub const ATCA_SUCCESS: i32 = 0;

//zones/lock zones (CryptoAuthLib)
pub const ATCA_ZONE_CONFIG: u8 = 0x00;
pub const ATCA_ZONE_DATA: u8   = 0x02;

// SlotConfig (2 bytes par slot, little-endian)
// Pour les slots "data", le low byte est:
//   [IsSecret(7)][EncryptRead(6)][LimitedUse(5)][NoMac(4)][ReadKey(3:0)]
// Pour les slots ECC privés, le low byte change complètement:
//   [IsSecret(7)][unused(6:4)][WriteEcdh(3)][Ecdh(2)][IntSign(1)][ExtSign(0)]
// High byte : [WriteConfig(7:4)][WriteKey(3:0)]
// WriteConfig : 0x0=Always (écrasable même après data lock), 0x2=Never (protégé après data lock)
// 0x8F = slot ECC privé + autorise ExtSign/IntSign/ECDH/WriteEcdh.
// 0x80 était invalide pour l'usage ECDSA: ExtSign=0 empêchait Sign.
const SC_ECC_PRIV: [u8; 2] = [0x83, 0x20];
const SC_ECDH:     [u8; 2] = [0x8F, 0x20];
const SC_CERT:     [u8; 2] = [0x00, 0x00]; // Public (cert lisible), WriteConfig=Always
const SC_HMAC:     [u8; 2] = [0x80, 0x20]; // IsSecret, WriteConfig=Never
const SC_AES_KEY:  [u8; 2] = [0x00, 0x00]; // Readable, WriteConfig=Always (révocable)
const SC_DISABLED: [u8; 2] = [0x80, 0x20]; // IsSecret, WriteConfig=Never

// KeyConfig (2 bytes par slot, little-endian)
// Low byte  : [ReqAuth(7)][ReqRandom(6)][Lockable(5)][KeyType(4:2)][PubInfo(1)][Private(0)]
// High byte : [X509id(7:5)][IntrusionDisable(4)][AuthKey(3:0)]
// KeyType : 4=P256 ECC, 6=AES-128, 7=SHA/HMAC
const KC_P256:     [u8; 2] = [0x33, 0x00]; // Private=1, PubInfo=1, KeyType=P256(4), Lockable=1
const KC_AES:      [u8; 2] = [0x18, 0x00]; // KeyType=AES(6)
const KC_HMAC:     [u8; 2] = [0x1C, 0x00]; // KeyType=SHA/HMAC(7)
const KC_DATA:     [u8; 2] = [0x00, 0x00]; // Stockage pur (slot cert, pas une clef)
const KC_DISABLED: [u8; 2] = [0x1C, 0x00]; // SHA/HMAC, non private, non lockable

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

    fn atcab_read_bytes_zone(zone: u8, slot: u16, offset: usize, data: *mut u8, length: usize) -> c_int;
    fn atcab_write_bytes_zone(zone: u8, slot: u16, offset_bytes: usize, data: *const u8, length: usize) -> c_int;

    fn atcab_sha_hmac(data: *const u8, data_size: usize, key_slot: u16, digest: *mut u8, target: u8,) -> c_int;

    fn atcab_ecdh(key_id: u16, public_key: *const u8, pms: *mut u8) -> c_int;
    fn atcab_ecdh_base(mode: u8, key_id: u16, public_key: *const u8, pms: *mut u8, out_nonce: *mut u8) -> c_int;
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

    pub fn read_data_slot(&self, slot: u16, offset: usize, len: usize, out: &mut [u8]) -> Result<(), i32>{
        if out.len() < len{
            return Err(ESP_ERR_INVALID_SIZE);
        }
        unsafe{
            let rc = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, offset, out.as_mut_ptr(), len);
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
            Ok(())
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

    pub fn ecdh(&self, slot: u16, peer_pub: &[u8; 64]) -> Result<[u8; 32], i32>{
        // Mode 0x0C = ECDH_MODE_COPY_OUTPUT_BUFFER
        // Force la sortie du PMS dans le buffer de réponse, indépendamment de
        // SlotConfig.WriteEcdh. Notre SC_ECDH = 0x8F a WriteEcdh=1 (mode "écrit
        // dans le slot N+1") donc atcab_ecdh() (mode 0x00 = COMPATIBLE) tenterait
        // d'écrire dans slot 2 (désactivé) → rejet du chip avec rc=-46.
        const ECDH_MODE_COPY_OUTPUT_BUFFER: u8 = 0x0C;
        let mut pms = [0u8; 32];
        unsafe{
            let rc = atcab_ecdh_base(
                ECDH_MODE_COPY_OUTPUT_BUFFER,
                slot,
                peer_pub.as_ptr(),
                pms.as_mut_ptr(),
                core::ptr::null_mut(),
            );
            if rc != ATCA_SUCCESS{
                return Err(rc);
            }
        }
        Ok(pms)
    }

    pub fn provision_root_secret_dev(&self, slot: u16) -> Result<(), i32>{
        let secret = self.random32()?;
        self.write_data_slot(slot, 0, &secret)?;
        log::warn!("root secret written in slot {} (derived keys will change if rewritten)", slot);
        Ok(())
    }

    // TODO: ajouter read_aes_key(slot: u16) -> Result<[u8; 32], i32>
    //   Lire en clair une clef AES partagée depuis les slots 10-14 (IsSecret=0, readable).
    //   Utiliser atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 0, buf, 32).
    //   Appelé au boot pour charger les clefs des volumes partagés reçus du serveur.
    //   La clef doit être consommée immédiatement et non gardée dans un global.

    // TODO: ajouter la logique certificat (slot 8, atcacert)
    //   - Binder atcacert_write_cert() et atcacert_read_cert() depuis cryptoauthlib
    //   - Définir le template atcacert_def_t en flash (issuer=CA BindKey, subject=SN device)
    //   - write_device_cert(sig_compressed: &[u8]) : écriture de la signature dans slot 8
    //     après que le serveur CA a signé la pubkey slot 0 (flow provisioning UART)
    //   - read_device_cert() -> DER : reconstruction du X.509 complet pour auth serveur
    //   - X509id dans KC_DATA (slot 8) à mettre à jour pour matcher le template (0=désactivé pour l'instant)

    pub fn read_config_zone(&self) -> Result<[u8; 128], i32> {
        let mut buf = [0u8; 128];
        unsafe {
            let rc = atcab_read_config_zone(buf.as_mut_ptr());
            if rc != ATCA_SUCCESS {
                return Err(rc);
            }
        }
        Ok(buf)
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

pub fn wrap_volume_key(se: &AteccSession, my_slot: u16, peer_pub: &[u8; 64], volume_key: &[u8; 32], aad: &[u8]) -> Result<[u8; 60], i32>{
    // ECDH(my_priv, peer_pub) => KEK 32 bytes
    let kek = se.ecdh(my_slot, peer_pub)?;

    // Nonce 12 bytes via SE random
    let r = se.random32()?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&r[..12]);

    // AES-GCM encrypt
    let mut gcm = AesGcm::new(&kek)?;
    let mut ciphertext = [0u8; 32];
    let mut tag = [0u8; 16];
    gcm.encrypt_and_tag(&nonce, aad, volume_key, &mut ciphertext, &mut tag)?;

    // Pack nonce(12) || ct(32) || tag(16) = 60 bytes
    let mut bundle = [0u8; 60];
    bundle[0..12].copy_from_slice(&nonce);
    bundle[12..44].copy_from_slice(&ciphertext);
    bundle[44..60].copy_from_slice(&tag);

    Ok(bundle)
}

pub fn unwrap_volume_key(se: &AteccSession, my_slot: u16, peer_pub: &[u8; 64], bundle: &[u8; 60], aad: &[u8]) -> Result<[u8; 32], i32>{
    let kek = se.ecdh(my_slot, peer_pub)?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bundle[0..12]);
    let ciphertext = &bundle[12..44];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&bundle[44..60]);

    let mut gcm = AesGcm::new(&kek)?;
    let mut volume_key = [0u8; 32];
    gcm.auth_decrypt(&nonce, aad, ciphertext, &tag, &mut volume_key)?;

    Ok(volume_key)
}

/// Configure la config zone de l'ATECC608 et la verrouille.
/// Idempotente : ne fait rien si la config zone est déjà lockée.
///
/// Layout des slots :
///   0        : ECC P256 private key (identité device)
///   1        : ECC P256 réservé
///   2–7      : désactivés
///   8        : device certificate compressé (416 bytes, public)
///   9        : root HMAC secret (dérive les clefs volumes)
///   10–14    : AES keys partage volumes (WriteConfig=Always → révocables)
///   15       : désactivé
pub fn provision_config_zone(se: &AteccSession) -> Result<(), i32> {
    let (cfg_locked, _) = se.lock_status()?;
    if cfg_locked {
        log::info!("SE: config zone already locked, skip");
        return Ok(());
    }

    // SlotConfig : bytes 20-51 de la config zone (2 bytes × 16 slots)
    #[rustfmt::skip]
    let slot_configs: [u8; 32] = [
        SC_ECC_PRIV[0],  SC_ECC_PRIV[1],  // slot  0 : ECC P256 private key
        SC_ECDH[0],      SC_ECDH[1],      // slot  1 : ECDH P256
        SC_DISABLED[0],  SC_DISABLED[1],  // slot  2 : désactivé
        SC_DISABLED[0],  SC_DISABLED[1],  // slot  3 : désactivé
        SC_DISABLED[0],  SC_DISABLED[1],  // slot  4 : désactivé
        SC_DISABLED[0],  SC_DISABLED[1],  // slot  5 : désactivé
        SC_DISABLED[0],  SC_DISABLED[1],  // slot  6 : désactivé
        SC_DISABLED[0],  SC_DISABLED[1],  // slot  7 : désactivé
        SC_CERT[0],      SC_CERT[1],      // slot  8 : device certificate
        SC_HMAC[0],      SC_HMAC[1],      // slot  9 : HMAC root secret
        SC_AES_KEY[0],   SC_AES_KEY[1],   // slot 10 : AES vol partagé
        SC_AES_KEY[0],   SC_AES_KEY[1],   // slot 11 : AES vol partagé
        SC_AES_KEY[0],   SC_AES_KEY[1],   // slot 12 : AES vol partagé
        SC_AES_KEY[0],   SC_AES_KEY[1],   // slot 13 : AES vol partagé
        SC_AES_KEY[0],   SC_AES_KEY[1],   // slot 14 : AES vol partagé
        SC_DISABLED[0],  SC_DISABLED[1],  // slot 15 : désactivé
    ];

    // KeyConfig : bytes 96-127 de la config zone (2 bytes × 16 slots)
    #[rustfmt::skip]
    let key_configs: [u8; 32] = [
        KC_P256[0],     KC_P256[1],     // slot  0 : P256 ECC
        KC_P256[0],     KC_P256[1],     // slot  1 : P256 ECC réservé
        KC_DISABLED[0], KC_DISABLED[1], // slot  2 : désactivé
        KC_DISABLED[0], KC_DISABLED[1], // slot  3 : désactivé
        KC_DISABLED[0], KC_DISABLED[1], // slot  4 : désactivé
        KC_DISABLED[0], KC_DISABLED[1], // slot  5 : désactivé
        KC_DISABLED[0], KC_DISABLED[1], // slot  6 : désactivé
        KC_DISABLED[0], KC_DISABLED[1], // slot  7 : désactivé
        KC_DATA[0],     KC_DATA[1],     // slot  8 : stockage cert
        KC_HMAC[0],     KC_HMAC[1],     // slot  9 : HMAC root
        KC_AES[0],      KC_AES[1],      // slot 10 : AES key
        KC_AES[0],      KC_AES[1],      // slot 11 : AES key
        KC_AES[0],      KC_AES[1],      // slot 12 : AES key
        KC_AES[0],      KC_AES[1],      // slot 13 : AES key
        KC_AES[0],      KC_AES[1],      // slot 14 : AES key
        KC_DISABLED[0], KC_DISABLED[1], // slot 15 : désactivé
    ];

    unsafe {
        // SlotConfig → bytes 20-51 de la config zone
        let rc = atcab_write_bytes_zone(
            ATCA_ZONE_CONFIG, 0, 20,
            slot_configs.as_ptr(), slot_configs.len(),
        );
        if rc != ATCA_SUCCESS {
            log::error!("SE: write SlotConfig failed rc={}", rc);
            return Err(rc);
        }

        // KeyConfig → bytes 96-127 de la config zone
        let rc = atcab_write_bytes_zone(
            ATCA_ZONE_CONFIG, 0, 96,
            key_configs.as_ptr(), key_configs.len(),
        );
        if rc != ATCA_SUCCESS {
            log::error!("SE: write KeyConfig failed rc={}", rc);
            return Err(rc);
        }
    }

    log::info!("SE: SlotConfig + KeyConfig written");

    // Verrouillage config zone (irréversible — lock_config_zone() vérifie déjà l'état)
    se.lock_config_zone()?;
    log::info!("SE: config zone provisioned and locked");

    // Génération de la paire ECC identité dans slot 0.
    // get_pubkey() permet de détecter si une clef existe déjà (data zone non lockée).
    // Si ça échoue on génère — sur un chip neuf c'est toujours le cas.
    match se.get_pubkey(0) {
        Ok(pk) => log::info!("SE: slot 0 ECC already present pubkey[0..4]={:02X?}", &pk[..4]),
        Err(_) => {
            let pk = se.gen_ecc_keypair(0)?;
            log::info!("SE: slot 0 ECC keypair generated pubkey[0..4]={:02X?}", &pk[..4]);
        }
    }

    // écriture de la clef pour ECDH
    match se.get_pubkey(1) {
        Ok(pk) => log::info!("SE: slot 1 ECC already present pubkey[0..4]={:02X?}", &pk[..4]),
        Err(_) => {
            let pk = se.gen_ecc_keypair(1)?;
            log::info!("SE: slot 1 ECC keypair generated pubkey[0..4]={:02X?}", &pk[..4]);
        }
    }

    // Écriture du root HMAC secret dans slot 9 (aléa via atcab_random).
    // CRITIQUE : ce secret dérive TOUTES les clefs volumes via HMAC-SHA256.
    // Il ne peut pas être lu (IsSecret=1) — il est irrécouvrable si perdu.
    // On l'écrit une seule fois ici, protégé par le guard cfg_locked en tête de fonction.
    se.provision_root_secret_dev(9)?;
    log::info!("SE: slot 9 root HMAC secret written");

    // Lock data zone : nécessaire pour que Sign fonctionne sur ATECC608A.
    // Slots 10-14 restent inscriptibles (WriteConfig=Always).
    se.lock_data_zone()?;
    log::info!("SE: data zone locked");

    log::info!("SE: provisioning complete — device ready");
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
