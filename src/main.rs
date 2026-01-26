use esp_idf_svc::sys::link_patches;
use esp_idf_svc::log::EspLogger;
use esp_idf_sys::*;

mod usb_emulation;
mod spi_link;
mod crypto;

use crate::usb_emulation::fake_usb::*;
use crate::spi_link::spi_master::SpiMaster;
use crate::spi_link::api_spi::set_global_spi;
use crate::crypto::secure_element::*;

fn main() {
    // Obligatoire pour esp-idf-sys
    link_patches();

    // Logs ESP
    EspLogger::initialize_default();

    log::info!("Starting fake USB MSC + SPI...");

    let mut spi = match SpiMaster::new() {
    Ok(s) => s,
    Err(err) => {
        log::error!(
            "SpiMaster::new failed {} ({})",
            err,
            unsafe { core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy() }
        );
        return;
    }
};

    if let Err(err) = spi.init(){
        log::error!("SpiMaster::init failed {} ({})",
            err,
            unsafe{
                core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy()
            }
        );
        return;
    }

    set_global_spi(&mut spi);

    unsafe {
        let err = init_fake_usb_msc();
        if err != ESP_OK {
            log::error!(
                "TinyUSB init failed: {} ({})",
                err,
                core::ffi::CStr::from_ptr(esp_err_to_name(err)).to_string_lossy()
            );
            return;
        }
    }

    log::info!("Testing ATECC608...");

    /*unsafe {
        i2c_init_legacy(i2c_port_t_I2C_NUM_0, 6, 7, 100_000);
        i2c_scan_legacy(i2c_port_t_I2C_NUM_0);
    }*/

    match atecc_smoke() {
        Ok(rev) => log::info!("ATECC revision: {:02X?}", rev),
        Err(rc) => log::error!("ATECC failed rc={}", rc),
    }

    match se_dump_and_master_dev(){
        Ok(()) => log::info!("ATECC test ok"),
        Err(rc) => log::info!("ATECC failed rc={}", rc),
    }

    
    log::info!("Fake MSC ready. Plug USB to host.");

    // IMPORTANT: ne jamais sortir de main
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}