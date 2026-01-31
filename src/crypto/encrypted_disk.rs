use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use esp_idf_sys::*;

use super::aes::{AesGcm, TAG_LEN};
use super::disk_layout::*;
use super::disk_crypto::*;
use super::disk_meta::*;

use crate::spi_link::spi_master::SpiMaster;

const MAX_BATCH_BLOCKS: usize = 8;
const BATCH_BYTES: usize = MAX_BATCH_BLOCKS * SECTOR_SIZE;

static GLOBAL_DISK: AtomicPtr<EncryptedDisk> = AtomicPtr::new(ptr::null_mut());

pub fn set_global_disk(disk: &mut EncryptedDisk){
    GLOBAL_DISK.store(disk as *mut _, Ordering::Release);
}

pub fn get_global_disk() -> Option<&'static mut EncryptedDisk>{
    let p = GLOBAL_DISK.load(Ordering::Acquire);
    if p.is_null(){
        None
    }
    else{
        unsafe{
            Some(&mut *p)
        }
    }
}

pub struct EncryptedDisk{
    gcm: AesGcm,

    cached_meta_lba: Option<u32>,
    cached_meta: MetaSector,
    cached_meta_dirty: bool,
    meta_buf: [u8; SECTOR_SIZE],

    cipher_buf: [u8; SECTOR_SIZE]
}

impl EncryptedDisk{
    pub fn new(key: &[u8]) -> Result<Self, i32>{
        Ok(Self{
            gcm: AesGcm::new(key)?,
            cached_meta_lba: None,
            cached_meta: MetaSector::default(),
            cached_meta_dirty: false,
            meta_buf: [0u8; SECTOR_SIZE],
            cipher_buf: [0u8; SECTOR_SIZE]
        })
    }

    pub fn capacity_logical(&mut self, spi: &mut SpiMaster) -> Result<(u32, u32), i32>{
        let (bs, bc_phys) = spi.get_capacity()?;
        validate_block_size(bs)?;
        let bc_log = logical_block_count_from_physical(bc_phys);
        Ok((bs, bc_log))
    }

    pub fn flush_all(&mut self, spi: &mut SpiMaster) -> Result<(), i32>{
        self.flush_all(spi)?;
        spi.flush()
    }

    pub fn read10(&mut self, spi: &mut SpiMaster, lba_start: u32, nblocks: u32, out: &mut [u8]) -> Result<(), i32>{
        let total = (nblocks as usize) * SECTOR_SIZE;
        if out.len() != total{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        for i in 0..(nblocks as usize){
            let lba = lba_start.wrapping_add(i as u32);
            let (data_phys, meta_phys, idx) = map_lba(lba);

            self.load_meta(spi, meta_phys)?;
            let entry = self.cached_meta.entries[idx];

            let out_sector = &mut out[i * SECTOR_SIZE..(i+1) * SECTOR_SIZE];

            if entry.is_empty(){
                out_sector.fill(0);
                continue;
            }

            spi.read(data_phys, 1, SECTOR_SIZE as u32, &mut self.cipher_buf)?;

            decrypt_sector(&mut self.gcm, lba, entry.counter, &self.cipher_buf, &entry.tag, out_sector)?;
        }

        Ok(())
    }

    pub fn write10(&mut self, spi: &mut SpiMaster, lba_start: u32, nblocks: u32, data: &[u8]) -> Result<(), i32>{
        let total = (nblocks as usize) * SECTOR_SIZE;
        if data.len() != total{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        let mut tag = [0u8; TAG_LEN];

        for i in 0..(nblocks as usize){
            let lba = lba_start.wrapping_add(i as u32);
            let (data_phys, meta_phys, idx) = map_lba(lba);

            self.load_meta(spi, meta_phys)?;
            let old = self.cached_meta.entries[idx];

            let mut counter = old.counter.wrapping_add(1);
            if counter == 0{
                return Err(ESP_ERR_INVALID_STATE); //overflow u32
            }
            if old.counter == 0{
                counter = 1;
            }

            let in_sector = &data[i * SECTOR_SIZE..(i+1) * SECTOR_SIZE];

            encrypt_sector(&mut self.gcm, lba, counter, in_sector, &mut self.cipher_buf, &mut tag)?;

            spi.write(data_phys, 1, SECTOR_SIZE as u32, &self.cipher_buf)?;

            self.cached_meta.entries[idx].counter = counter;
            self.cached_meta.entries[idx].tag = tag;
            self.cached_meta_dirty = true;
        }

        self.flush_meta(spi)?;

        Ok(())
    }


    fn load_meta(&mut self, spi: &mut SpiMaster, meta_lba_phys: u32) -> Result<(), i32>{
        if self.cached_meta_lba == Some(meta_lba_phys){
            return Ok(());
        }

        self.flush_meta(spi)?;

        spi.read(meta_lba_phys, 1, SECTOR_SIZE as u32, &mut self.meta_buf)?;

        self.cached_meta = MetaSector::decode_or_default(&self.meta_buf)?;
        self.cached_meta_lba = Some(meta_lba_phys);
        self.cached_meta_dirty = false;

        Ok(())
    }

    fn flush_meta(&mut self, spi: &mut SpiMaster) -> Result<(), i32>{
        let Some(meta_lba) = self.cached_meta_lba else{
            return Ok(());
        };

        if !self.cached_meta_dirty{
            return Ok(());
        }

        self.cached_meta.seq = self.cached_meta.seq.wrapping_add(1); //seq++ optionnal

        self.cached_meta.encode(&mut self.meta_buf)?;
        spi.write(meta_lba, 1, SECTOR_SIZE as u32, &self.meta_buf)?;

        self.cached_meta_dirty = false;

        Ok(())
    }
}