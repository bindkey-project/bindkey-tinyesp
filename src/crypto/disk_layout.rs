use esp_idf_sys::*;

pub const SECTOR_SIZE: usize = 512;
pub const G: u32 = 24;
pub const GROUP_PHYS: u32 = G + 1;

#[inline]
pub fn map_lba(lba_logical: u32) -> (u32, u32, usize){
    let group = lba_logical / G;
    let idx = (lba_logical % G) as usize;

    let base = group * GROUP_PHYS;
    
    let data_lba_phys = base + (idx as u32);
    let meta_lba_phys = base + G;

    (data_lba_phys, meta_lba_phys, idx)
}

#[inline]
pub fn logical_block_count_from_physical(physical_bc: u32) -> u32{
    let groups = physical_bc / GROUP_PHYS;
    groups * G
}

#[inline]
pub fn physical_block_count_needed_for_logical(logical_bc: u32) -> u32{
    let groups = (logical_bc + (G - 1)) / G;
    groups * GROUP_PHYS
}

#[inline]
pub fn validate_block_size(block_size: u32) -> Result<(), i32>{
    if block_size as usize != SECTOR_SIZE{
        return Err(ESP_ERR_INVALID_SIZE);
    }
    Ok(())
}