use esp_idf_sys::*;

// constants to compute the mapping of metadata with respect of data and physical sectors
pub const SECTOR_SIZE: usize = 512;
pub const G: u32 = 24;
pub const GROUP_PHYS: u32 = G + 1;
pub const BK_TABLE_SECTORS: u32 = 1;

// maps all logical LBAs to physical LBAs
#[inline]
pub fn map_lba(lba_logical: u32) -> (u32, u32, usize){
    let group = lba_logical / G;
    let idx = (lba_logical % G) as usize;

    let base = group * GROUP_PHYS;
    
    let data_lba_phys = base + (idx as u32) + BK_TABLE_SECTORS;
    let meta_lba_phys = base + G + BK_TABLE_SECTORS;

    (data_lba_phys, meta_lba_phys, idx)
}

// convert a physical block count into the logical exposed to OS
#[inline]
pub fn logical_block_count_from_physical(physical_bc: u32) -> u32{
    let usable = physical_bc.saturating_sub(BK_TABLE_SECTORS);
    let groups = usable / GROUP_PHYS;
    groups * G
}

// inverse: physical blocks needed to expose logical_bc sectors
#[inline]
pub fn physical_block_count_needed_for_logical(logical_bc: u32) -> u32{
    let groups = (logical_bc + (G - 1)) / G;
    groups * GROUP_PHYS
}

// reject any block size other than 512B, the whole layout assumes SECTOR_SIZE
#[inline]
pub fn validate_block_size(block_size: u32) -> Result<(), i32>{
    if block_size as usize != SECTOR_SIZE{
        return Err(ESP_ERR_INVALID_SIZE);
    }
    Ok(())
}