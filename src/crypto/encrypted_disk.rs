use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use esp_idf_sys::*;

use super::aes::{AesGcm, TAG_LEN};
use super::disk_layout::*;
use super::disk_crypto::*;
use super::disk_meta::*;

use crate::spi_link::spi_master::SpiMaster;

// max sectors encrypted/decrypted in a single batch + its size in bytes
const MAX_BATCH_BLOCKS: usize = 8;
const BATCH_BYTES: usize = MAX_BATCH_BLOCKS * SECTOR_SIZE;

// max extra volumes besides the default one
pub const MAX_EXTRA_VOLUMES: usize = 5;

// define a VolumeSlot with its encryption/decryption info + logical sectors addresses
pub struct VolumeSlot{
    pub gcm: AesGcm,
    pub lba_start: u32, 
    pub lba_end: u32
}

// make the disk accessible from anywhere
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

// this struct ciphers/deciphers sectors and stores the matching metadata on the disk
pub struct EncryptedDisk{
    default_gcm: AesGcm,
    volumes: [Option<VolumeSlot>; MAX_EXTRA_VOLUMES],
    num_volumes: usize,

    cached_meta_lba: Option<u32>,
    cached_meta: MetaSector,
    cached_meta_dirty: bool,
    meta_buf: [u8; SECTOR_SIZE],

    cipher_buf: [u8; BATCH_BYTES]
}

const NONE_VOL: Option<VolumeSlot> = None;

impl EncryptedDisk{
    // builds a disk with its default volume key
    pub fn new(key: &[u8]) -> Result<Self, i32>{
        Ok(Self{
            default_gcm: AesGcm::new(key)?,
            volumes: [NONE_VOL; MAX_EXTRA_VOLUMES],
            num_volumes: 0,
            cached_meta_lba: None,
            cached_meta: MetaSector::default(),
            cached_meta_dirty: false,
            meta_buf: [0u8; SECTOR_SIZE],
            cipher_buf: [0u8; BATCH_BYTES]
        })
    }

    // finds the right volume for a given lba
    fn volume_index_for_lba(&self, lba: u32) -> Option<usize>{
        for i in 0..self.num_volumes{
            if let Some(ref v) = self.volumes[i]{
                // lba_end is inclusive (software sends last sector of partition)
                if lba >= v.lba_start && lba <= v.lba_end{
                    return Some(i);
                }
            }
        }
        None
    }
    
    // adds a volume to the list
    pub fn add_volume(&mut self, lba_start: u32, lba_end: u32, key: &[u8]) -> Result<(), i32>{
        if self.num_volumes >= MAX_EXTRA_VOLUMES{
            return Err(ESP_ERR_NO_MEM);
        }
        let gcm = AesGcm::new(key)?;
        self.volumes[self.num_volumes] = Some(VolumeSlot{gcm, lba_start, lba_end});
        self.num_volumes += 1;
        Ok(())
    }
    
    // logs the current volume table for debugging
    pub fn log_volume_table(&self){                                                                                                                                                                                                      
        log::info!("=== Volume Table ({} volumes) ===", self.num_volumes);
        log::info!("  vol0 [default] → constant key (cross-device)");
        for i in 0..self.num_volumes{                                                                                                                                                                                                        
            if let Some(ref v) = self.volumes[i]{                                                                                                                                                                                            
                log::info!("  vol{} lba={}..{}", i + 1, v.lba_start, v.lba_end);                                                                                                                                                              
            }                                                                                                                                                                                                                                 
        }                                                                                                                                                                                                                                        
        log::info!("================================");
    }     

    // clears all the current volumes
    pub fn clear_volumes(&mut self){
        for i in 0..self.num_volumes{
            self.volumes[i] = None;
        }
        self.num_volumes = 0;
        self.invalidate_meta_cache();
    }

    // drops the cached meta sector so it gets re-read from disk
    pub fn invalidate_meta_cache(&mut self){
        self.cached_meta_lba = None;
        self.cached_meta_dirty = false;
    }

    // translating real capacity to logical capacity
    pub fn capacity_logical(&mut self, spi: &mut SpiMaster) -> Result<(u32, u32), i32>{
        let (bs, bc_phys) = spi.get_capacity()?;
        validate_block_size(bs)?;
        let bc_log = logical_block_count_from_physical(bc_phys);
        Ok((bs, bc_log))
    }

    // flushes pending meta then the physical disk
    pub fn flush_all(&mut self, spi: &mut SpiMaster) -> Result<(), i32>{
        self.flush_meta(spi)?;
        spi.flush()
    }

    // read command to the SPI bus with decryption
    pub fn read10(&mut self, spi: &mut SpiMaster, lba_start: u32, nblocks: u32, out: &mut [u8]) -> Result<(), i32>{
        let total = (nblocks as usize) * SECTOR_SIZE;
        if out.len() != total{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        let mut done: usize = 0;
        while done < nblocks as usize{
            let lba = lba_start.wrapping_add(done as u32);
            let (data_phys, meta_phys, idx) = map_lba(lba);

            self.load_meta(spi, meta_phys)?;

            let remaining = (nblocks as usize) - done;
            let max_in_group = (G as usize) - idx;
            let run = remaining.min(max_in_group).min(MAX_BATCH_BLOCKS);    

            let out_chunk = &mut out[done * SECTOR_SIZE..(done + run) * SECTOR_SIZE];

            let all_empty = self.cached_meta.entries[idx..idx + run].iter().all(|e| e.is_empty());
            if all_empty{
                //log::warn!("read10: lba={} run={} all_empty → returning zeros (never written?)", lba, run);
                out_chunk.fill(0);
                done += run;
                continue;
            }

            // reading the ciphertext from the hard drive
            let ct_len = run * SECTOR_SIZE;
            if let Err(e) = spi.read(data_phys, run as u32, SECTOR_SIZE as u32, &mut self.cipher_buf[..ct_len]){
                log::error!("disk read10: spi.read failed lba_phys={} run={} err={}", data_phys, run, e);
                return Err(e);
            }

            // decryption and tag verification
            for j in 0..run{
                let lba_j = lba.wrapping_add(j as u32); 
                let entry = self.cached_meta.entries[idx + j];
                let out_sector = &mut out_chunk[j * SECTOR_SIZE..(j+1) * SECTOR_SIZE];

                if entry.is_empty(){
                    out_sector.fill(0);
                    continue;
                }

                let vol_idx = self.volume_index_for_lba(lba_j);

                let ct_sector = &self.cipher_buf[j * SECTOR_SIZE..(j+1) * SECTOR_SIZE];

                let gcm = match vol_idx{
                    Some(i) => &mut self.volumes[i].as_mut().unwrap().gcm,
                    None => &mut self.default_gcm
                };
                if let Err(e) = decrypt_sector(gcm, lba_j, entry.counter, ct_sector, &entry.tag, out_sector){
                    // GCM auth failure: corrupted sector, return zeros so the OS does not unmount the disk
                    log::debug!("disk read10: GCM decrypt failed lba={} counter={} err={}", lba_j, entry.counter, e);
                    out_sector.fill(0);
                }
            }
            done += run;
        }

        Ok(())
    }

    // write command to the SPI bus with encryption
    pub fn write10(&mut self, spi: &mut SpiMaster, lba_start: u32, nblocks: u32, data: &[u8]) -> Result<(), i32>{
        let total = (nblocks as usize) * SECTOR_SIZE;
        if data.len() != total{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        let mut done: usize = 0;
        let mut tag = [0u8; TAG_LEN];

        while done < nblocks as usize{
            let lba = lba_start.wrapping_add(done as u32);
            let (data_phys, meta_phys, idx) = map_lba(lba);

            self.load_meta(spi, meta_phys)?;

            let remaining = (nblocks as usize) - done;
            let max_in_group = (G as usize) - idx;
            let run = remaining.min(max_in_group).min(MAX_BATCH_BLOCKS);

            let in_chunk = &data[done * SECTOR_SIZE..(done + run) * SECTOR_SIZE];

            // encryption and tagging
            for j in 0..run{
                let lba_j = lba.wrapping_add(j as u32);
                let old = self.cached_meta.entries[idx + j];

                let mut counter = old.counter.wrapping_add(1);
                if old.counter == 0{
                    counter = 1;
                }
                if counter == 0{
                    return Err(ESP_ERR_INVALID_STATE); // counter u32 overflow
                }

                let vol_idx = self.volume_index_for_lba(lba_j);

                let pt_sector = &in_chunk[j * SECTOR_SIZE..(j+1) * SECTOR_SIZE];
                let ct_sector = &mut self.cipher_buf[j * SECTOR_SIZE..(j+1) * SECTOR_SIZE];

                let gcm = match vol_idx{
                    Some(i) => &mut self.volumes[i].as_mut().unwrap().gcm,
                    None => &mut self.default_gcm
                };
                encrypt_sector(gcm, lba_j, counter, pt_sector, ct_sector, &mut tag)?;

                self.cached_meta.entries[idx + j].counter = counter;
                self.cached_meta.entries[idx + j].tag = tag;
                self.cached_meta_dirty = true;
            }

            // write data FIRST: if data fails, meta stays old = state is consistent
            let ct_len = run * SECTOR_SIZE;
            if let Err(e) = spi.write(data_phys, run as u32, SECTOR_SIZE as u32, &self.cipher_buf[..ct_len]){
                log::error!("write10: data write failed lba={} err={}, invalidating cache", lba, e);
                self.cached_meta_lba = None;
                self.cached_meta_dirty = false;
                return Err(e);
            }

            // then flush meta (counter + tag)
            if let Err(e) = self.flush_meta(spi){
                // meta flush failed after data write: invalidate cache so next write re-reads meta from disk
                log::error!("write10: meta flush failed after data write lba={} err={}", lba, e);
                self.cached_meta_lba = None;
                self.cached_meta_dirty = false;
                return Err(e);
            }

            done += run;
        }

        Ok(())
    }


    // loads the meta sector for a physical LBA into cache (flushing the previous one first)
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

    // writes the cached meta sector back to disk if it is dirty
    fn flush_meta(&mut self, spi: &mut SpiMaster) -> Result<(), i32>{
        let Some(meta_lba) = self.cached_meta_lba else{
            return Ok(());
        };

        if !self.cached_meta_dirty{
            return Ok(());
        }

        self.cached_meta.seq = self.cached_meta.seq.wrapping_add(1); // seq++ optional

        self.cached_meta.encode(&mut self.meta_buf)?;
        spi.write(meta_lba, 1, SECTOR_SIZE as u32, &self.meta_buf)?;

        self.cached_meta_dirty = false;

        Ok(())
    }
}