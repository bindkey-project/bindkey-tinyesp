use core::ffi::{c_int, c_uint};
use esp_idf_sys::*;

use crate::crypto::secure_element::{AteccSession, derive_volume_key_hmac};

pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub struct AesGcm{
    ctx: esp_gcm_context
}

impl AesGcm{
    pub fn new(key: &[u8]) -> Result<Self, i32>{
        let keybits: u32 = match key.len(){
            16 => 128,
            24 => 192,
            32 => 256,
            _ => return Err(ESP_ERR_INVALID_SIZE)
        };

        let mut s = Self{
            ctx: esp_gcm_context::default()
        };

        unsafe{
            esp_aes_gcm_init(&mut s.ctx as *mut _);

            let cipher = mbedtls_cipher_id_t_MBEDTLS_CIPHER_ID_AES;

            let rc = esp_aes_gcm_setkey(&mut s.ctx as *mut _, cipher, key.as_ptr(), keybits as c_uint);
            if rc != 0{
                return Err(rc);
            }
        }

        Ok(s)
    }

    pub fn encrypt_and_tag(&mut self, iv: &[u8; IV_LEN], aad: &[u8], plaintext: &[u8], ciphertext_out: &mut [u8], tag_out: &mut [u8; TAG_LEN]) -> Result<(), i32>{
        if ciphertext_out.len() != plaintext.len(){
            return Err(ESP_ERR_INVALID_SIZE);
        }

        unsafe{
            let mode: c_int = MBEDTLS_GCM_ENCRYPT as c_int;

            let rc = esp_aes_gcm_crypt_and_tag(&mut self.ctx as *mut _, mode, plaintext.len(), iv.as_ptr(), IV_LEN, aad.as_ptr(), aad.len(), plaintext.as_ptr(), ciphertext_out.as_mut_ptr(), TAG_LEN, tag_out.as_mut_ptr());
            if rc != 0{
                return Err(rc);
            }

        }

        Ok(())
    }

    pub fn auth_decrypt(&mut self, iv: &[u8; IV_LEN], aad: &[u8], ciphertext: &[u8], tag: &[u8; TAG_LEN], plaintext_out: &mut [u8]) -> Result<(), i32>{
        if plaintext_out.len() != ciphertext.len(){
            return Err(ESP_ERR_INVALID_SIZE);
        }

        let in_ptr = ciphertext.as_ptr() as usize;
        let out_ptr = plaintext_out.as_ptr() as usize;
        if in_ptr == out_ptr{
            return Err(ESP_ERR_INVALID_ARG);
        }

        unsafe{
            let rc = esp_aes_gcm_auth_decrypt(&mut self.ctx as *mut _, ciphertext.len(), iv.as_ptr(), IV_LEN, aad.as_ptr(), aad.len(), tag.as_ptr(), TAG_LEN, ciphertext.as_ptr(), plaintext_out.as_mut_ptr());

            if rc != 0{
                return Err(rc);
            }
        }

        Ok(())
    }
}

impl Drop for AesGcm{
    fn drop(&mut self){
        unsafe{
            esp_aes_gcm_free(&mut self.ctx as *mut _);
        }
    }
}

pub fn test_aes_gcm() -> Result<(), i32>{
    log::info!("Testing AES-GCM...");
    //AES 256 32B key
    let key = [0x11u8; 32];
    // IV 12B
    let iv: [u8; IV_LEN] = [0x22u8; IV_LEN];

    let aad: [u8; 8] = *b"hdr-aad!"; //8 bytes

    let plaintext: [u8; 64] = {
        let mut p = [0u8; 64];
        for (i, b) in p.iter_mut().enumerate(){
            *b = i as u8;
        }
        p
    };

    let mut gcm = AesGcm::new(&key)?;

    let mut ciphertext = [0u8; 64];
    let mut tag = [0u8; TAG_LEN];

    gcm.encrypt_and_tag(&iv, &aad, &plaintext, &mut ciphertext, &mut tag)?;
    log::info!("AES-GCM encrypt OK");

    let mut decrypted = [0u8; 64];
    gcm.auth_decrypt(&iv, &aad, &ciphertext, &tag, &mut decrypted)?;
    log::info!("AES-GCM decrypt OK");

    if decrypted != plaintext{
        log::error!("AES-GCM mismatch!");
        return Err(ESP_ERR_INVALID_RESPONSE);
    }

    // integrity test => 1 bit flip
    let mut ct_corrupt = ciphertext;
    ct_corrupt[0] ^= 0x01;

    let mut out = [0u8; 64];
    let rc = gcm.auth_decrypt(&iv, &aad, &ct_corrupt, &tag, &mut out);
    if rc.is_ok(){
        log::error!("AES-GCM auth should have failed but succeeded");
        return Err(ESP_ERR_INVALID_RESPONSE);
    } 
    else{
        log::info!("AES-GCM auth failure OK (corrupted ciphertext)");
    }

    Ok(())
}

pub fn test_aes_gcm_with_se(root_slot: u16) -> Result<(), i32>{
    log::info!("Testing AES-GCM with SE-derived key (slot {})...", root_slot);
    let se = AteccSession::new()?;
    let volume_id: [u8; 16] = *b"bindkey-vol-0001"; //16 bytes

    let key = derive_volume_key_hmac(&se, root_slot, volume_id)?;
    log::info!("Derived volume key OK (32B)");

    
    let iv: [u8; IV_LEN] = [0x33u8; IV_LEN];
    let aad: [u8; 12] = *b"spi-header!!"; 

    let plaintext: [u8; 128] = {
        let mut p = [0u8; 128];
        for (i, b) in p.iter_mut().enumerate(){
            *b = (i as u8).wrapping_mul(7);
        }
        p
    };

    let mut gcm = AesGcm::new(&key)?;
    let mut ciphertext = [0u8; 128];
    let mut tag = [0u8; TAG_LEN];

    gcm.encrypt_and_tag(&iv, &aad, &plaintext, &mut ciphertext, &mut tag)?;
    log::info!("AES-GCM encrypt OK");

    let mut decrypted = [0u8; 128];
    gcm.auth_decrypt(&iv, &aad, &ciphertext, &tag, &mut decrypted)?;
    if decrypted != plaintext{
        log::error!("AES-GCM(SE) mismatch!");
        return Err(ESP_ERR_INVALID_RESPONSE);
    }
    log::info!("AES-GCM decrypt OK, plaintext matches");

    let mut ct_corrupt = ciphertext;
    ct_corrupt[0] ^= 0x01;

    let mut out = [0u8; 128];
    let r = gcm.auth_decrypt(&iv, &aad, &ct_corrupt, &tag, &mut out);
    if r.is_ok(){
        log::error!("AES-GCM(SE) auth should have failed but succeeded");
        return Err(ESP_ERR_INVALID_RESPONSE);
    }
    log::info!("AES-GCM(SE) auth failure OK (ciphertext corrupted)");

    Ok(())
}