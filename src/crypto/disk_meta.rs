// Layout (512 bytes):
//   [0..4]   magic "BKMD"
//   [4]      version = 1
//   [5]      G (sanity)
//   [6..8]   reserved
//   [8..12]  seq (u32) (optional)
//   [12..16] crc32 (optional, 0 at the moment)
//   [16..32] reserved
//   [32..]   entries (G * 20 bytes) = 480 bytes for G=24

use esp_idf_sys::*;

use super::aes::TAG_LEN;
use super::disk_layout::{G, SECTOR_SIZE};

pub const META_MAGIC: [u8; 4] = *b"BKMD";
pub const META_VERSION: u8 = 1;
pub const META_HEADER_LEN: usize = 32;
pub const META_ENTRY_LEN: usize = 4 + TAG_LEN; //counter + tag

#[derive(Clone, Copy, Debug, Default)]
pub struct MetaEntry{
    pub counter: u32,
    pub tag: [u8; TAG_LEN]
}

impl MetaEntry{
    #[inline]
    pub fn is_empty(&self) -> bool{
        self.counter == 0 && self.tag == [0u8; TAG_LEN]
    }
}


#[derive(Clone, Debug)]
pub struct MetaSector{
    pub seq: u32,
    pub entries: [MetaEntry; G as usize]
}

impl Default for MetaSector{
    fn default() -> Self{
        Self{ 
            seq: 0, 
            entries: [MetaEntry::default(); G as usize]
        }
    }
}

impl MetaSector{
    pub fn decode(buf: &[u8]) -> Result<Self, i32>{
        if buf.len() != SECTOR_SIZE{
            return Err(ESP_ERR_INVALID_SIZE);
        }
        if buf[0..4] != META_MAGIC{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if buf[4] != META_VERSION{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if buf[5] != (G as u8){
            return Err(ESP_ERR_INVALID_RESPONSE);
        }

        let seq = u32::from_le_bytes(buf[8..12].try_into().unwrap());

        let mut out = MetaSector::default();
        out.seq = seq;

        let mut off = META_HEADER_LEN;
        for i in 0..(G as usize){
            let counter = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            off += 4;

            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&buf[off..off + TAG_LEN]);

            off += TAG_LEN;

            out.entries[i] = MetaEntry{
                counter,
                tag
            };
        }

        Ok(out)
    }

    #[inline]
    pub fn decode_or_default(buf: &[u8]) -> Result<Self, i32>{
        match Self::decode(buf){
            Ok(m) => Ok(m),
            Err(_) => Ok(Self::default())
        }
    }

    pub fn encode(&self, buf: &mut [u8]) -> Result<(), i32>{
        if buf.len() != SECTOR_SIZE{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        buf.fill(0);

        //Header
        buf[0..4].copy_from_slice(&META_MAGIC);
        buf[4] = META_VERSION;
        buf[5] = G as u8;
        //[6..8] reserved = 0;
        buf[8..12].copy_from_slice(&self.seq.to_le_bytes());
        //[12..16] crc32 = 0 (implement later)


        //Entries
        let mut off = META_HEADER_LEN;
        for e in self.entries.iter(){
            buf[off..off + 4].copy_from_slice(&e.counter.to_le_bytes());
            off += 4;
            buf[off..off + TAG_LEN].copy_from_slice(&e.tag);
            off += TAG_LEN;
        }

        Ok(())
    }
}


//helpers
#[inline]
pub fn get_entry(meta: &MetaSector, idx: usize) -> Result<MetaEntry, i32>{
    if idx >= G as usize{
        return Err(ESP_ERR_INVALID_ARG);
    }
    Ok(meta.entries[idx])
}

#[inline]
pub fn set_entry(meta: &mut MetaSector, idx: usize, counter: u32, tag: &[u8; TAG_LEN]) -> Result<(), i32>{
    if idx >= G as usize{
        return Err(ESP_ERR_INVALID_ARG);
    }
    meta.entries[idx].counter = counter;
    meta.entries[idx].tag = *tag;
    Ok(())
}

