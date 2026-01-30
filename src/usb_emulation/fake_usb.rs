#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use core::{mem, ptr};
use esp_idf_sys::esp_tinyusb::{
    tinyusb_config_t, tinyusb_desc_config_t, tinyusb_phy_config_t, tinyusb_task_config_t,
    tinyusb_driver_install, tinyusb_port_t_TINYUSB_PORT_FULL_SPEED_0,
    tusb_desc_device_t, tusb_desc_device_qualifier_t,
};
use esp_idf_sys::*;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::spi_link::api_spi::get_global_spi;

//fake disk parameters, 4096 blocs = 2MiB => ok for the os to see a disk and mount/format it
const BLOCK_SIZE: u16 = 512;
const BLOCK_COUNT: u32 = 4096;

static ACTIVE_BS: AtomicU32 = AtomicU32::new(BLOCK_SIZE as u32);
static ACTIVE_BC: AtomicU32 = AtomicU32::new(BLOCK_COUNT);

extern "C" {
    fn tud_msc_set_sense(lun: u8, sense_key: u8, asc: u8, ascq: u8);
}

//sense keys scsi spc
const SCSI_SENSE_NOT_READY: u8 = 0x02;
const SCSI_SENSE_ILLEGAL_REQUEST: u8 = 0x05;
const SCSI_ASC_LUN_NOT_READY: u8 = 0x04;
const SCSI_ASCQ_BECOMING_READY: u8 = 0x01;


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
            size: 4096,
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
        let pid = b"SPI Tunnel MSC\0";     // <= 16 chars recommended
        let rev = b"0.1\0";               // <= 4 chars recommended

        ptr::copy_nonoverlapping(vid.as_ptr(), vendor_id, 8.min(vid.len()));
        ptr::copy_nonoverlapping(pid.as_ptr(), product_id, 16.min(pid.len()));
        ptr::copy_nonoverlapping(rev.as_ptr(), product_rev, 4.min(rev.len()));
    }
}

//test unit ready 
#[no_mangle]
pub extern "C" fn tud_msc_test_unit_ready_cb(_lun: u8) -> bool{
    let Some(spi) = get_global_spi() else{
        unsafe{
            tud_msc_set_sense(_lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
        }
        return false;
    };

    match spi.get_status(){
        Ok((st, bd_status)) if st == ESP_OK && bd_status == 2 => true,
        _ => {
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
    //fallback fake
    let mut bs: u32 = BLOCK_SIZE as u32;
    let mut bc: u32 = BLOCK_COUNT;

    if let Some(spi) = get_global_spi(){
        if let Ok((real_bs, real_bc)) = spi.get_capacity(){
            if real_bs != 0 && real_bc != 0{
                bs = real_bs;
                bc = real_bc;
            }
        }
    }

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
        if let Some(spi) = get_global_spi(){
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
    //log::info!("MSC_CB: READ10 lun={} lba={} nblocks={} bufsize={} offset={}", lun, _lba, nblocks, bufsize, offset);

    let out = unsafe{
        core::slice::from_raw_parts_mut(buffer as *mut u8, bufsize as usize)
    };

    match spi.read(_lba, nblocks, BLOCK_SIZE as u32, out){
        Ok(()) => bufsize as i32,
        Err(_e) => {
            unsafe{
                tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
            }
            return -1;
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
    //log::info!("MSC_CB: WRITE10 lun={} lba={} nblocks={} bufsize={} offset={}", lun, _lba, nblocks, bufsize, offset);

    let data = unsafe{
        core::slice::from_raw_parts(_buffer as *const u8, bufsize as usize)
    };

    match spi.write(_lba, nblocks, BLOCK_SIZE as u32, data){
        Ok(()) => bufsize as i32,
        Err(_e) => {
            unsafe{
                tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, SCSI_ASC_LUN_NOT_READY, SCSI_ASCQ_BECOMING_READY);
            }
            return -1;
        }
    }
}

//optionnal : hook if OS asks non defined things
/*#[no_mangle]
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
}*/
