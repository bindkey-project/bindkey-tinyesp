use esp_idf_sys::*;

use super::aes::{AesGcm, IV_LEN, TAG_LEN};
use super::disk_layout::SECTOR_SIZE;

const IV_CONST: [u8; 4] = [0x42, 0x4B, 0x00, 0x01]; //"BK\0\1"

#[inline]
fn make_iv(lba_logical: u32, counter: u32) -> [u8; IV_LEN]{
    let mut iv = [0u8; IV_LEN];
    iv[0..4].copy_from_slice(&lba_logical.to_le_bytes());
    iv[4..8].copy_from_slice(&counter.to_le_bytes());
    iv[8..12].copy_from_slice(&IV_CONST);
    iv
}

#[inline]
fn make_aad(lba_logical: u32, counter: u32) -> [u8; 8]{
    let mut aad = [0u8; 8];
    aad[0..4].copy_from_slice(&lba_logical.to_le_bytes());
    aad[4..8].copy_from_slice(&counter.to_le_bytes());
    aad
}

#[inline]
pub fn encrypt_sector(gcm: &mut AesGcm, lba_logical: u32, counter: u32, plaintext: &[u8], ciphertext_out: &mut [u8], tag_out: &mut [u8; TAG_LEN]) -> Result<(), i32>{
    if plaintext.len() != SECTOR_SIZE || ciphertext_out.len() != SECTOR_SIZE{
        return Err(ESP_ERR_INVALID_SIZE);
    }

    if counter == 0{
        return Err(ESP_ERR_INVALID_ARG);
    }

    let iv = make_iv(lba_logical, counter);
    let aad = make_aad(lba_logical, counter);

    gcm.encrypt_and_tag(&iv, &aad, plaintext, ciphertext_out, tag_out)
}

#[inline]
pub fn decrypt_sector(gcm: &mut AesGcm, lba_logical: u32, counter: u32, ciphertext: &[u8], tag: &[u8; TAG_LEN], plaintext_out: &mut [u8]) -> Result<(), i32>{
    if ciphertext.len() != SECTOR_SIZE || plaintext_out.len() != SECTOR_SIZE{
        return Err(ESP_ERR_INVALID_SIZE);
    }

    if counter == 0{
        return Err(ESP_ERR_INVALID_ARG);
    }

    let iv = make_iv(lba_logical, counter);
    let aad = make_aad(lba_logical, counter);

    gcm.auth_decrypt(&iv, &aad, ciphertext, tag, plaintext_out)
}
