use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicBool, Ordering};
use esp_idf_sys::*;
use super::disk_layout::SECTOR_SIZE;                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
pub const BK_TABLE_MAGIC: [u8; 4] = *b"BKVT";                                                                                                                                                                                             
pub const BK_TABLE_VERSION: u8 = 1;                                                                                                                                                                                                       
pub const MAX_VOLUMES: usize = 6;                                                                                                                                                                                                         
pub const MAX_SHARED: usize = 5;                                                                                                                                                                                                          
pub const SN_LEN: usize = 9;

#[derive(Clone, Copy)]
pub struct SharedAccess{
    pub sn: [u8; SN_LEN],
    pub slot: u8
}

impl Default for SharedAccess{
    fn default() -> Self {
        Self{
            sn: [0u8; SN_LEN],
            slot: 0
        }
    }
}

#[derive(Clone, Copy)]
pub struct VolumeEntry{
    pub volume_id: [u8; 16],
    pub lba_start: u32,
    pub lba_end: u32,
    pub owner_sn: [u8; SN_LEN],
    pub num_shared: u8,
    pub shared: [SharedAccess; MAX_SHARED]
}

impl Default for VolumeEntry{
    fn default() -> Self {
        Self{
            volume_id: [0u8; 16],
            lba_start: 0,
            lba_end: 0,
            owner_sn: [0u8; SN_LEN],
            num_shared: 0,
            shared: [SharedAccess::default(); MAX_SHARED]
        }
    }
}

pub struct BkTable{
    pub num_volumes: u8,
    pub entries: [VolumeEntry; MAX_VOLUMES],
    /// true if this table was successfully decoded from persistent storage (valid magic).
    /// false if it is a fresh default (first boot or decode failure).
    /// Used to distinguish "never formatted" (show disk) from "explicitly wiped" (hide disk).
    pub initialized: bool,
}

impl BkTable{
    pub fn new() -> Self{
        Self{
            num_volumes: 0,
            entries: [VolumeEntry::default(); MAX_VOLUMES],
            initialized: false,
        }
    }

    pub fn add_volume(&mut self, volume_id: [u8; 16], lba_start: u32, lba_end: u32, owner_sn: [u8; SN_LEN]) -> Result<usize, i32>{
        if self.num_volumes as usize >= MAX_VOLUMES{
            return Err(ESP_ERR_NO_MEM);
        }
        let idx = self.num_volumes as usize;
        self.entries[idx] = VolumeEntry{
            volume_id,
            lba_start,
            lba_end,
            owner_sn,
            num_shared: 0,
            shared: [SharedAccess::default(); MAX_SHARED]
        };
        self.num_volumes += 1;
        Ok(idx)
    }

    pub fn find_volume_for_lba(&self, lba: u32) -> Option<usize>{
        for i in 0..self.num_volumes as usize{
            let e = &self.entries[i];
            // lba_end is inclusive (software sends last sector of partition)
            if lba >= e.lba_start && lba <= e.lba_end{
                return Some(i)
            }
        }
        None
    }

    pub fn encode(&self, buf: &mut [u8; SECTOR_SIZE]){
        buf.fill(0);
        buf[0..4].copy_from_slice(&BK_TABLE_MAGIC);
        buf[4] = BK_TABLE_VERSION;
        buf[5] = self.num_volumes;

        let mut off = 8; //header 8 bytes
        for i in 0..self.num_volumes as usize{
            let e = &self.entries[i];
            buf[off..off + 16].copy_from_slice(&e.volume_id);
            off += 16;
            buf[off..off + 4].copy_from_slice(&e.lba_start.to_le_bytes());
            off += 4;
            buf[off..off + 4].copy_from_slice(&e.lba_end.to_le_bytes());
            off += 4;
            buf[off..off + SN_LEN].copy_from_slice(&e.owner_sn);
            off += SN_LEN;
            buf[off] = e.num_shared;
            off += 1;
            for s in 0..MAX_SHARED{
                buf[off..off + SN_LEN].copy_from_slice(&e.shared[s].sn);
                off += SN_LEN;
                buf[off] = e.shared[s].slot;
                off += 1;
            }
        }
    }

    pub fn decode(buf: &[u8; SECTOR_SIZE]) -> Result<Self, i32>{
        if buf[0..4] != BK_TABLE_MAGIC{ 
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if buf[4] != BK_TABLE_VERSION{ 
            return Err(ESP_ERR_INVALID_VERSION);
        }

        let num_volumes = buf[5];
        if num_volumes as usize > MAX_VOLUMES{ 
            return Err(ESP_ERR_INVALID_SIZE); 
        }

        let mut table = BkTable::new();
        table.num_volumes = num_volumes;
        table.initialized = true; // decoded from valid persistent storage

        let mut off = 8;
        for i in 0..num_volumes as usize{
            let e = &mut table.entries[i];
            e.volume_id.copy_from_slice(&buf[off..off + 16]); 
            off += 16;
            e.lba_start = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()); 
            off += 4;
            e.lba_end   = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            off += 4;
            e.owner_sn.copy_from_slice(&buf[off..off + SN_LEN]);
            off += SN_LEN;
            e.num_shared = buf[off]; 
            off += 1;
            for s in 0..MAX_SHARED{
                e.shared[s].sn.copy_from_slice(&buf[off..off + SN_LEN]); 
                off += SN_LEN;
                e.shared[s].slot = buf[off]; 
                off += 1;
            }
        }
        Ok(table)
    }

    pub fn decode_or_default(buf: &[u8; SECTOR_SIZE]) -> Self{
        Self::decode(buf).unwrap_or_else(|_| Self::new())
    }
}

// ── Global BkTable en RAM ────────────────────────────────────────────────────
// La BK Table est lue depuis le disque au boot et maintenue en RAM.
// Le flush vers le disque est différé au prochain test_unit_ready_cb
// (TinyUSB task, SCSI séquentiel → pas de concurrent access SPI).

static GLOBAL_BK_TABLE: AtomicPtr<BkTable> = AtomicPtr::new(ptr::null_mut());
static BK_TABLE_DIRTY: AtomicBool = AtomicBool::new(false);

pub fn set_global_bk_table(t: &mut BkTable){
    GLOBAL_BK_TABLE.store(t as *mut _, Ordering::Release);
}

pub fn get_global_bk_table() -> Option<&'static mut BkTable>{
    let p = GLOBAL_BK_TABLE.load(Ordering::Acquire);
    if p.is_null() { None } else { unsafe { Some(&mut *p) } }
}

pub fn mark_bk_table_dirty(){
    BK_TABLE_DIRTY.store(true, Ordering::Release);
}

pub fn is_bk_table_dirty() -> bool{
    BK_TABLE_DIRTY.load(Ordering::Acquire)
}

pub fn clear_bk_table_dirty(){
    BK_TABLE_DIRTY.store(false, Ordering::Release);
}
