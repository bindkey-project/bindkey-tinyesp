#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use core::ptr;
use esp_idf_sys::esp_tinyusb::{
    tinyusb_config_t, tinyusb_desc_config_t, tinyusb_phy_config_t, tinyusb_task_config_t,
    tinyusb_driver_install, tinyusb_port_t_TINYUSB_PORT_FULL_SPEED_0,
    tusb_desc_device_t, tusb_desc_device_qualifier_t,
};
use esp_idf_sys::*;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::spi_link::api_spi::get_global_spi;

use crate::crypto::encrypted_disk::get_global_disk;
use crate::crypto::volume_table::{get_global_bk_table, is_bk_table_dirty, clear_bk_table_dirty};

//fake disk parameters, 4096 blocs = 2MiB => ok for the os to see a disk and mount/format it
const BLOCK_SIZE: u16 = 512;
const BLOCK_COUNT: u32 = 4096;

static ACTIVE_BS: AtomicU32 = AtomicU32::new(BLOCK_SIZE as u32);
static ACTIVE_BC: AtomicU32 = AtomicU32::new(BLOCK_COUNT);
static MEDIA_WAS_READY: AtomicU32 = AtomicU32::new(0);
static DISK_LOGGED: AtomicU32 = AtomicU32::new(0);
/// Set to 1 once we log "hiding disk — no volumes configured" to avoid log spam.
/// Reset to 0 when volumes become available so the "first Ready" log fires again.
static GATE_LOGGED: AtomicU32 = AtomicU32::new(0);
/// Set to true by reset_disk_state(). Consumed in TUR once the gate lifts (volumes ready):
/// signals UNIT_ATTENTION MEDIUM_CHANGED so the OS discards its cached disk state.
static NEEDS_UNIT_ATTENTION: AtomicBool = AtomicBool::new(false);

/// Set to true by enter_format_mode() (action=init_format UART command).
/// While true, the gate that hides the disk when num_volumes==0 is bypassed,
/// so the OS can still write the msdos partition table via force_format.
/// Cleared by exit_format_mode() once the first volume is created.
static DISK_FORMATTING: AtomicBool = AtomicBool::new(false);

// debug du problème des medium not ready + callback suppressed
static BD0_CONSECUTIVE: AtomicU32 = AtomicU32::new(0);
const BD0_MEDIUM_ABSENT_THRESHOLD: u32 = 30;
// vTaskDelay() takes FreeRTOS ticks, not milliseconds.
// This repo sets CONFIG_FREERTOS_HZ=1000, so 50 ticks = 50 ms.
const BD0_BOOT_RETRY_DELAY_TICKS: u32 = 50;

/// Called by UART task on `action=init_format` so the OS sees the disk as a new medium
/// when volumes are re-configured, instead of the old stale state.
pub fn reset_disk_state() {
    MEDIA_WAS_READY.store(0, Ordering::Relaxed);
    DISK_LOGGED.store(0, Ordering::Relaxed);
    BD0_CONSECUTIVE.store(0, Ordering::Relaxed);
    GATE_LOGGED.store(0, Ordering::Relaxed);
    NEEDS_UNIT_ATTENTION.store(true, Ordering::Relaxed);
    log::info!("disk state reset: disk hidden until volumes re-configured via UART");
}

/// Called by UART task on `action=init_format`.
/// Bypasses the num_volumes==0 gate so the OS can still write the msdos partition table
/// via force_format while volumes are being reconfigured via UART.
/// The disk remains visible to the OS during the format session.
pub fn enter_format_mode() {
    DISK_FORMATTING.store(true, Ordering::Relaxed);
    GATE_LOGGED.store(0, Ordering::Relaxed);
    log::info!("enter_format_mode: gate bypassed, disk stays visible for force_format");
}

/// Called after the first volume is successfully created during a format session.
/// Clears the format bypass — no UNIT_ATTENTION here because mkfs.vfat is still
/// running at this point; partprobe+udevadm settle (called by the software) are
/// sufficient for the OS to discover the new partition.
pub fn exit_format_mode() {
    DISK_FORMATTING.store(false, Ordering::Relaxed);
    DISK_LOGGED.store(0, Ordering::Relaxed);
    log::info!("exit_format_mode: gate re-enabled");
}

pub fn is_disk_formatting() -> bool {
    DISK_FORMATTING.load(Ordering::Relaxed)
}

extern "C" {
    fn tud_msc_set_sense(lun: u8, sense_key: u8, asc: u8, ascq: u8);
}

//sense keys scsi spc
const SCSI_SENSE_NOT_READY: u8 = 0x02;
const SCSI_SENSE_ILLEGAL_REQUEST: u8 = 0x05;
const SCSI_ASC_LUN_NOT_READY: u8 = 0x04;
const SCSI_ASCQ_BECOMING_READY: u8 = 0x01;
const SCSI_SENSE_MEDIUM_ERROR: u8 = 0x03;
const SCSI_ASC_UNRECOVERED_READ_ERROR: u8 = 0x11;
const SCSI_SENSE_UNIT_ATTENTION: u8 = 0x06;                                                                                                                                                                                               
const SCSI_ASC_MEDIUM_CHANGED: u8 = 0x28; 


//asc/ascq required
const SCSI_ASC_MEDIUM_NOT_PRESENT: u8 = 0x3A; // Not Ready - Medium Not Present
const SCSI_ASC_INVALID_FIELD_IN_CDB: u8 = 0x24; // Illegal Request - Invalid field in CDB
const SCSI_ASCQ: u8 = 0x00;

//usb device + config descriptors
static DEVICE_DESC: tusb_desc_device_t = tusb_desc_device_t {
    bLength: 18,
    bDescriptorType: 0x01,
    bcdUSB: 0x0200,
    bDeviceClass: 0x00,
    bDeviceSubClass: 0x00,
    bDeviceProtocol: 0x00,
    bMaxPacketSize0: 64,
    idVendor: 0x303A,
    idProduct: 0x4001,
    bcdDevice: 0x0100,
    iManufacturer: 0,
    iProduct: 0,
    iSerialNumber: 0,
    bNumConfigurations: 1,
};

//descriptor FS MSC (bulk-only transport)
//interface class = 0x08 (MSC), subclass = 0x06 (SCSI), protocol = 0x50 (BOT)
static FS_CONFIG_DESC: [u8; 32] = [
    //configuration descriptor
    9, 0x02, 0x20, 0x00, //wTotalLength=32
    0x01, 0x01, 0x00, 0x80, 50,

    //interface descriptor
    9, 0x04,
    0x00, 0x00, 0x02,
    0x08, 0x06, 0x50,
    0x00,

    //endpoint OUT (Bulk) EP1
    7, 0x05,
    0x01, 0x02,
    0x40, 0x00,
    0x00,

    //endpoint IN (Bulk) EP1
    7, 0x05,
    0x81, 0x02,
    0x40, 0x00,
    0x00,
];

//init TinyUSB in device mode with msc interface
pub unsafe fn init_fake_usb_msc() -> esp_err_t{
    let desc = tinyusb_desc_config_t{
        device: &DEVICE_DESC as *const tusb_desc_device_t,
        qualifier: ptr::null::<tusb_desc_device_qualifier_t>(),
        string: ptr::null_mut(),
        string_count: 0,
        full_speed_config: FS_CONFIG_DESC.as_ptr(),
        high_speed_config: ptr::null(),
    };

    let cfg = tinyusb_config_t{
        port: tinyusb_port_t_TINYUSB_PORT_FULL_SPEED_0,
        phy: tinyusb_phy_config_t{ 
            skip_setup: false,
            self_powered: false,
            vbus_monitor_io: 0,
        },
        task: tinyusb_task_config_t{
            size: 32768,
            priority: 5,
            xCoreID: 0,
        },
        descriptor: desc,
        event_cb: None,
        event_arg: ptr::null_mut(),
    };

    tinyusb_driver_install(&cfg)
}

//msc callbacks rewritten

//inquiry: vendor/product/rev strings
#[no_mangle]
pub extern "C" fn tud_msc_inquiry_cb(_lun: u8, vendor_id: *mut u8, product_id: *mut u8, product_rev: *mut u8){
    unsafe{
        let vid = b"BindKey\0";            // <= 8 chars recommended
        let pid = b"BINDKEY\0";            // <= 16 chars recommended à modif
        let rev = b"0.1\0";                // <= 4 chars recommended

        ptr::copy_nonoverlapping(vid.as_ptr(), vendor_id, 8.min(vid.len()));
        ptr::copy_nonoverlapping(pid.as_ptr(), product_id, 16.min(pid.len()));
        ptr::copy_nonoverlapping(rev.as_ptr(), product_rev, 4.min(rev.len()));
    }
}

//test unit ready
// Once the disk has been seen as ready, transient SPI errors should NOT
// make us report "medium not present" — that causes the OS to unmount.
// We only report medium absent when the slave explicitly says bd_status==0
// AND we can confirm it with a retry.
#[no_mangle]
pub extern "C" fn tud_msc_test_unit_ready_cb(_lun: u8) -> bool{
    let Some(spi) = get_global_spi() else{
        unsafe{
            tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
        }
        return false;
    };

    match spi.get_status(){
        Ok((st, bd_status)) if st == ESP_OK && bd_status == 2 => {
            BD0_CONSECUTIVE.store(0, Ordering::Relaxed);

            // Flush BK Table first (deferred from UART task).
            // Must run even when we're about to gate the disk hidden, so that
            // action=init_format (num_volumes=0) is persisted before a reboot.
            if is_bk_table_dirty() {
                if let Some(table) = get_global_bk_table() {
                    let mut buf = [0u8; 512];
                    table.encode(&mut buf);
                    match spi.write(0, 1, 512, &buf) {
                        Ok(()) => {
                            clear_bk_table_dirty();
                            log::info!("BK Table flushed to disk");
                        }
                        Err(e) => log::error!("BK Table flush failed: {}", e)
                    }
                }
            }

            // Gate: if the BK Table was explicitly initialized (valid magic on disk)
            // but has no volumes, the user ran action=init_format and hasn't configured
            // volumes yet — keep the disk hidden from the OS until UART completes the setup.
            // This prevents the OS from formatting with the wrong/missing key.
            //
            // Exception: while DISK_FORMATTING is set (active format session started by
            // action=init_format), the gate is bypassed so the OS can still write the msdos
            // partition table via force_format before volumes are declared.
            if let Some(table) = get_global_bk_table() {
                if table.initialized && table.num_volumes == 0
                    && !DISK_FORMATTING.load(Ordering::Relaxed)
                {
                    if GATE_LOGGED.swap(1, Ordering::Relaxed) == 0 {
                        log::warn!("TUR: BkTable wiped (0 volumes) — hiding disk from OS. \
                                    Send volume_name/volume_id/lba_start/lba_end via UART first.");
                    }
                    unsafe { tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY); }
                    return false;
                }
            }
            // Volumes exist (or first boot with no BK Table yet) — disk is visible.
            GATE_LOGGED.store(0, Ordering::Relaxed);

            // Signal UNIT_ATTENTION MEDIUM_CHANGED once after init_format+volume_create:
            // forces the OS to discard any cached disk state and re-read the partition table.
            if NEEDS_UNIT_ATTENTION.swap(false, Ordering::Relaxed) {
                log::info!("TUR: signaling UNIT_ATTENTION MEDIUM_CHANGED to OS");
                unsafe { tud_msc_set_sense(_lun, SCSI_SENSE_UNIT_ATTENTION, SCSI_ASC_MEDIUM_CHANGED, SCSI_ASCQ); }
                return false;
            }

            MEDIA_WAS_READY.store(1, Ordering::Relaxed);
            if DISK_LOGGED.swap(1, Ordering::Relaxed) == 0 {
                log::info!("TUR: first Ready — disk now visible to OS");
                if let Some(disk) = get_global_disk(){
                    disk.log_volume_table();
                }
            }
            true
        }
        Ok((st, bd_status)) if st == ESP_OK && bd_status == 0 => {
            let count = BD0_CONSECUTIVE.fetch_add(1, Ordering::Relaxed) + 1;
            let was_ready = MEDIA_WAS_READY.load(Ordering::Relaxed) == 1;

            if was_ready && count < BD0_MEDIUM_ABSENT_THRESHOLD{
                log::warn!("TUR: bd_status=0 while media was ready (count={}/{}) -> BECOMING_READY, not MEDIUM_NOT_PRESENT", count, BD0_MEDIUM_ABSENT_THRESHOLD);
                unsafe{
                    tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
                }
                return false;
            }

            // si le disque n'était jamais READY, on garde une confirmation avec délai pour éviter le glitch 
            if !was_ready{
                unsafe{
                    vTaskDelay(BD0_BOOT_RETRY_DELAY_TICKS);
                }
                match spi.get_status(){
                    Ok((s, d)) if s == ESP_OK && d == 0 => {}
                    _ => {
                        log::warn!("TUR: bd_status=0 before first ready was transient -> BECOMING_READY"); 
                        unsafe{
                            tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
                        }
                        return false;
                    }
                }
            }

            // genuinely not present (confirmed twice)
            log::warn!("TUR: bd_status=0 confirmed count={} -> declaring MEDIUM_NOT_PRESENT", count);
            MEDIA_WAS_READY.store(0, Ordering::Relaxed);
            
            unsafe{
                tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_MEDIUM_NOT_PRESENT, SCSI_ASCQ);
            }
            false
        }
        Ok((st, bd_status)) if st == ESP_OK && bd_status == 1 => {
            BD0_CONSECUTIVE.store(0, Ordering::Relaxed);

            // slave NotReady (drive reconnecting, block_count=0) — legitimate transient state,
            // NOT a SPI error: never pretend ready here or reads will immediately fail
            log::info!("TUR: slave NotReady (bd=1) → BECOMING_READY");
            unsafe { tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY); }
            false
        }
        Err(_) | Ok(_) => {
            // SPI error (timeout, desync, etc.) — if disk was previously ready,
            // report as ready to prevent OS from unmounting
            if MEDIA_WAS_READY.load(Ordering::Relaxed) == 1{
                return true;
            }
            unsafe{
                tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
            }
            false
        }
    }
}

//capacity
#[no_mangle]
pub extern "C" fn tud_msc_capacity_cb(_lun: u8, block_count: *mut u32, block_size: *mut u16){                                                                                                                                           
    let cached_bs = ACTIVE_BS.load(Ordering::Relaxed);                                                                                                                                                                                    
    let cached_bc = ACTIVE_BC.load(Ordering::Relaxed);                                                                                                                                                  
                                                                                                                                                                                                                                            
    let (bs, bc) = if cached_bs != BLOCK_SIZE as u32 || cached_bc != BLOCK_COUNT{                                                                                                                                                        
        (cached_bs, cached_bc)                                                                                                                                                                                                            
    }
    else if let (Some(spi), Some(disk)) = (get_global_spi(), get_global_disk()){                                                                                                                                                       
        match disk.capacity_logical(spi) {                                                                                                                                                                                                
            Ok((real_bs, logical_bc)) if real_bs != 0 && logical_bc != 0 => {                                                                                                                                                             
                ACTIVE_BS.store(real_bs, Ordering::Relaxed);                                                                                                                                                                              
                ACTIVE_BC.store(logical_bc, Ordering::Relaxed);                                                                                                                                                                           
                (real_bs, logical_bc)                                                                                                                                                                                                     
            }                                                                                                                                                                                                                             
            _ => (BLOCK_SIZE as u32, BLOCK_COUNT),
        }                                                                                                                                                                                                                                 
    }
    else if let Some(spi) = get_global_spi(){
        match spi.get_capacity() {
            Ok((real_bs, real_bc)) if real_bs != 0 && real_bc != 0 => {                                                                                                                                                                   
                ACTIVE_BS.store(real_bs, Ordering::Relaxed);
                ACTIVE_BC.store(real_bc, Ordering::Relaxed);                                                                                                                                                                              
                (real_bs, real_bc)
            }                                                                                                                                                                                                                             
            _ => (BLOCK_SIZE as u32, BLOCK_COUNT),
        }
    }
    else{
        (BLOCK_SIZE as u32, BLOCK_COUNT)
    };                                                                                                                                                                                                                                    
   
    //log::info!("CAPACITY: bs={} bc={}", bs, bc);
    unsafe{
        if !block_count.is_null(){
            *block_count = bc;
        }
        if !block_size.is_null(){
            *block_size = bs as u16;
        }
    }
}

//start-stop: if load_eject && !start => flush spi
#[no_mangle]
pub extern "C" fn tud_msc_start_stop_cb(_lun: u8, _power_condition: u8, _start: bool, _load_eject: bool) -> bool{
    if _load_eject && !_start{
        DISK_LOGGED.store(0, Ordering::Relaxed);
        if let (Some(spi), Some(disk)) = (get_global_spi(), get_global_disk()){
            let _ = disk.flush_all(spi);
        }
        else if let Some(spi) = get_global_spi(){
            let _ = spi.flush();
        }
    }
    true
}

//read10: fills the buffer 
#[no_mangle]
pub extern "C" fn tud_msc_read10_cb(lun: u8, _lba: u32, offset: u32, buffer: *mut core::ffi::c_void, bufsize: u32) -> i32{
    if buffer.is_null(){
        unsafe{
            tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_IN_CDB, SCSI_ASCQ);
        }
        return -1;
    }

    if offset != 0 || (bufsize as usize) % (BLOCK_SIZE as usize) != 0{
        unsafe{ 
            tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_IN_CDB, SCSI_ASCQ) 
        };
        return -1;
    }

   let Some(spi) = get_global_spi() else{
        unsafe{
            tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
            return -1;
        }
    };

    let nblocks = (bufsize as u32) / (BLOCK_SIZE as u32);
    //log::info!("READ10 lba={} nblocks={}", _lba, nblocks);

    let out = unsafe{
        core::slice::from_raw_parts_mut(buffer as *mut u8, bufsize as usize)
    };

    if let Some(disk) = get_global_disk(){
        match disk.read10(spi, _lba, nblocks, out){
            Ok(()) => bufsize as i32,
            Err(first_err) => {
                log::warn!("MSC read10: first attempt failed lba={} nblocks={} err={}, retrying with cache invalidation", _lba, nblocks, first_err);
                disk.invalidate_meta_cache();
                match disk.read10(spi, _lba, nblocks, out){
                    Ok(()) => bufsize as i32,
                    Err(_e) => {
                        log::error!("MSC read10: retry failed lba={} nblocks={} err={}", _lba, nblocks, _e);
                        unsafe{
                            tud_msc_set_sense(lun, SCSI_SENSE_MEDIUM_ERROR, SCSI_ASC_UNRECOVERED_READ_ERROR, SCSI_ASCQ);
                        }
                        -1
                    }
                }
            }
        }
    } 
    else{
        match spi.read(_lba, nblocks, BLOCK_SIZE as u32, out){
            Ok(()) => bufsize as i32,
            Err(_e) => {
                unsafe{
                    tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
                }
                -1
            }
        }
    }


}

//write10: accepts & drop data
#[no_mangle]
pub extern "C" fn tud_msc_write10_cb(lun: u8, _lba: u32, offset: u32, _buffer: *mut u8, bufsize: u32) -> i32{
    if _buffer.is_null(){
        unsafe{ 
            tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_IN_CDB, SCSI_ASCQ)
        };
        return -1;
    }

    if offset != 0 || (bufsize as usize) % (BLOCK_SIZE as usize) != 0{
         unsafe{
            tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_IN_CDB, SCSI_ASCQ);
        }
        return -1;
    }
    
    let Some(spi) = get_global_spi() else{
        unsafe{
            tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY)
        }
        return -1;
    };

    let nblocks = (bufsize as u32) / (BLOCK_SIZE as u32);
    //log::info!("WRITE10 lba={} nblocks={}", _lba, nblocks);

    let data = unsafe{
        core::slice::from_raw_parts(_buffer as *const u8, bufsize as usize)
    };

    if let Some(disk) = get_global_disk(){
        match disk.write10(spi, _lba, nblocks, data){
            Ok(()) => {
                //log::info!("WRITE10 OK lba={} nblocks={}", _lba, nblocks);
                bufsize as i32
            }
            Err(first_err) => {
                log::warn!("MSC write10: first attempt failed lba={} nblocks={} err={}, retrying with cache invalidation", _lba, nblocks, first_err);
                disk.invalidate_meta_cache();
                match disk.write10(spi, _lba, nblocks, data){
                    Ok(()) => bufsize as i32,
                    Err(_e) => {
                        log::error!("MSC write10: retry failed lba={} nblocks={} err={}", _lba, nblocks, _e);
                        log::error!("SENSE_SOURCE=WRITE10_FAILED setting MEDIUM_ERROR/UNRECOVERED_READ_ERROR lba={} nblocks={} err={}", _lba, nblocks, _e);
                        unsafe{
                            tud_msc_set_sense(lun, SCSI_SENSE_MEDIUM_ERROR, SCSI_ASC_UNRECOVERED_READ_ERROR, SCSI_ASCQ);
                        }
                        -1
                    }
                }
            }
        }
    }
    else{
        match spi.write(_lba, nblocks, BLOCK_SIZE as u32, data){
            Ok(()) => bufsize as i32,
            Err(_e) => {
                log::error!("WRITE10 (no-disk) FAILED lba={} nblocks={} err={}", _lba, nblocks, _e);
                unsafe{
                    tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
                }
                -1
            }
        }
    }
}

//optionnal : hook if OS asks non defined things
#[no_mangle]
pub extern "C" fn tud_msc_scsi_cb(lun: u8, _scsi_cmd: *const u8, _buf: *mut core::ffi::c_void, _bufsize: u16) -> i32 {
    if _scsi_cmd.is_null(){
        unsafe{
            tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_IN_CDB, SCSI_ASCQ);
            return -1;
        }
    }

    let op = unsafe{
        *_scsi_cmd
    };
    //0x1E = PREVENT_ALLOW_MEDIUM_REMOVAL
    if op == 0x1E{
        return 0;
    }

    unsafe{ 
        tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_FIELD_IN_CDB, SCSI_ASCQ)
    };
    return -1;
}
