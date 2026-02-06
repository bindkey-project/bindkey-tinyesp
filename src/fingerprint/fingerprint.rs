use anyhow::{anyhow, Result};
use core::{ffi::c_char, ptr};
use lazy_static::lazy_static;
use std::sync::Mutex;

use esp_idf_svc::sys::bmlite::{
    // GPIO / SPI types et constantes
    gpio_num_t_GPIO_NUM_16,
    gpio_num_t_GPIO_NUM_35,
    gpio_num_t_GPIO_NUM_36,
    gpio_num_t_GPIO_NUM_37,
    gpio_num_t_GPIO_NUM_45,
    gpio_num_t_GPIO_NUM_48,
    interface_t,
    interface_t_SPI_INTERFACE,
    pin_config_t,
    spi_host_device_t_SPI2_HOST,

    // Plateforme BM-Lite
    platform_deinit,
    platform_init,

    // Résultats / status
    fpc_bep_result_t_FPC_BEP_RESULT_OK,

    // MTU fourni par ESP-IDF
    MTU,
};

// ======================================================
// 1) Structs BM-Lite corrigées (d'après hcp_tiny.h)
// ======================================================

#[repr(C)]
pub struct HCP_arg_t {
    pub size: u32,
    pub data: *mut u8,
}

#[repr(C)]
pub struct HCP_comm_t {
    pub write: Option<unsafe extern "C" fn(u16, *const u8, u32) -> i32>,
    pub read:  Option<unsafe extern "C" fn(u16, *mut u8, u32) -> i32>,
    pub phy_rx_timeout: u32,
    pub pkt_buffer: *mut u8,
    pub pkt_size_max: u32,
    pub pkt_size: u32,
    pub txrx_buffer: *mut u8,
    pub arg: HCP_arg_t,
    pub bep_result: i32,
}

// ======================================================
// 2) console_initparams_t équivalent Rust
// ======================================================

#[repr(C)]
pub struct Params {
    pub iface: interface_t,
    pub port: *mut c_char,
    pub baudrate: u32,
    pub timeout: u32,
    pub hcp_comm: *mut HCP_comm_t,
    pub pins: *mut pin_config_t,
}

// ======================================================
// 3) Déclarations externes C (bmlite_if.h)
// ======================================================

extern "C" {
    pub fn bep_enroll_finger(chain: *mut HCP_comm_t) -> i32;

    pub fn bep_identify_finger(
        chain: *mut HCP_comm_t,
        timeout: u32,
        template_id: *mut u16,
        matched: *mut bool,
    ) -> i32;

    pub fn bep_sensor_calibrate(chain: *mut HCP_comm_t) -> i32;
    pub fn bep_sw_reset(chain: *mut HCP_comm_t) -> i32;

    pub fn bep_template_get_count(chain: *mut HCP_comm_t, count: *mut u16) -> i32;
    pub fn bep_template_remove_all(chain: *mut HCP_comm_t) -> i32;
    pub fn bep_template_save(chain: *mut HCP_comm_t, id: u16) -> i32;
    pub fn sensor_wait_finger_not_present(chain: *mut HCP_comm_t, timeout: u16) -> i32;
    pub fn sensor_wait_finger_present(chain: *mut HCP_comm_t, timeout: u16) -> i32;
}

// ======================================================
// 4) Contexte global du capteur
// ======================================================

struct SensorCtx {
    params: *mut Params,
    pins: *mut pin_config_t,
    chain: *mut HCP_comm_t,
    initialized: bool,
}

unsafe impl Send for SensorCtx {}
unsafe impl Sync for SensorCtx {}

impl SensorCtx {
    const fn new() -> Self {
        Self {
            params: ptr::null_mut(),
            pins: ptr::null_mut(),
            chain: ptr::null_mut(),
            initialized: false,
        }
    }

    fn set(&mut self, params: *mut Params, pins: *mut pin_config_t, chain: *mut HCP_comm_t) {
        self.params = params;
        self.pins = pins;
        self.chain = chain;
        self.initialized = true;
    }

    fn reset(&mut self) {
        self.params = ptr::null_mut();
        self.pins = ptr::null_mut();
        self.chain = ptr::null_mut();
        self.initialized = false;
    }

    fn is_set(&self) -> bool {
        self.initialized && !self.chain.is_null()
    }
}

lazy_static! {
    static ref SENSOR_CTX: Mutex<SensorCtx> = Mutex::new(SensorCtx::new());
}

// ======================================================
// 5) Helper pour erreurs
// ======================================================

fn check_bep(res: i32, what: &str) -> Result<()> {
    if res == fpc_bep_result_t_FPC_BEP_RESULT_OK {
        Ok(())
    } else {
        Err(anyhow!("{what} failed with code {res}"))
    }
}

// ======================================================
// 6) Création des structs C (Params + HCP_comm + pin_config)
// ======================================================

unsafe fn alloc_config() -> Result<(*mut Params, *mut pin_config_t, *mut HCP_comm_t)> {
    let pkt_buffer = Box::into_raw(Box::new([0u8; 1024 * 3])) as *mut u8;
    let txrx_buffer = Box::into_raw(Box::new([0u8; MTU as usize])) as *mut u8;

    let chain = Box::into_raw(Box::new(HCP_comm_t {
        write: None,
        read: None,
        phy_rx_timeout: 2000,
        pkt_buffer,
        pkt_size_max: 1024 * 3,
        pkt_size: 0,
        txrx_buffer,
        arg: HCP_arg_t { size: 0, data: ptr::null_mut() },
        bep_result: 0,
    }));

    let pins = Box::into_raw(Box::new(pin_config_t {
        spi_host: spi_host_device_t_SPI2_HOST,
        cs_n_pin: gpio_num_t_GPIO_NUM_45,
        miso_pin: gpio_num_t_GPIO_NUM_37,
        rst_pin: gpio_num_t_GPIO_NUM_48,
        mosi_pin: gpio_num_t_GPIO_NUM_35,
        irq_pin: gpio_num_t_GPIO_NUM_16,
        spi_clk_pin: gpio_num_t_GPIO_NUM_36,
    }));

    let params = Box::into_raw(Box::new(Params {
        iface: interface_t_SPI_INTERFACE,
        port: ptr::null_mut(),
        baudrate: 1_000_000, // plus stable pour test
        timeout: 3000,
        hcp_comm: chain,
        pins,
    }));

    Ok((params, pins, chain))
}

// ======================================================
// 7) API Publique
// ======================================================

pub fn init() -> Result<()> {
    let mut ctx = SENSOR_CTX.lock().unwrap();

    if ctx.is_set() {
        return Ok(());
    }

    unsafe {
        let (params, pins, chain) = alloc_config()?;

        check_bep(platform_init(params.cast()), "platform_init")?;

        ctx.set(params, pins, chain);

        log::info!("sizeof(HCP_comm_t) = {}", core::mem::size_of::<HCP_comm_t>());
        log::info!("chain ptr      = {:p}", chain);
        log::info!("pkt_buffer     = {:p}", (*chain).pkt_buffer);
        log::info!("txrx_buffer    = {:p}", (*chain).txrx_buffer);
        log::info!("pkt_size_max   = {}", (*chain).pkt_size_max);
        log::info!("After platform_init:");
        log::info!("write ptr = {:?}", (*chain).write);
        log::info!("read ptr  = {:?}", (*chain).read);

        log::info!("Calibration du capteur...");
    //unsafe { check_bep(bep_sensor_calibrate(ctx.chain), "bep_sensor_calibrate")?; }
    }

    log::info!("BM-Lite: init OK");
    Ok(())
}

pub fn is_user_enrolled() -> Result<bool> {
    let ctx = SENSOR_CTX.lock().unwrap();
    if !ctx.is_set() {
        return Err(anyhow!("BM-Lite not initialized"));
    }
    let mut count: u16 = 0;
    unsafe { check_bep(bep_template_get_count(ctx.chain, &mut count), "bep_template_get_count")?; }
    Ok(count > 0)
}

pub fn wipe_templates() -> Result<()> {
    let ctx = SENSOR_CTX.lock().unwrap();
    if !ctx.is_set() {
        return Ok(());
    }
    unsafe { check_bep(bep_template_remove_all(ctx.chain), "bep_template_remove_all")?; }
    Ok(())
}
//il faudra changer ça de place
use std::{thread, time::Duration};

pub fn enroll_user() -> Result<()> {
    let ctx = SENSOR_CTX.lock().unwrap();
    if !ctx.is_set() {
        return Err(anyhow!("BM-Lite not initialized"));
    }

    log::info!("Enrôlement : pose ton doigt...");

    // 1) Enrôlement
    unsafe {
        check_bep(
            bep_enroll_finger(ctx.chain),
            "bep_enroll_finger",
        )?;

        // 2) Sauvegarde du template
        check_bep(
            bep_template_save(ctx.chain, 1),
            "bep_template_save",
        )?;
    }

    // 3) Vérification que le template est bien stocké
    let mut count: u16 = 0;
    unsafe {
        check_bep(
            bep_template_get_count(ctx.chain, &mut count),
            "bep_template_get_count après save",
        )?;
    }
    log::info!("Templates après save: {}", count);

    // 4) TRÈS IMPORTANT :
    // attendre que le doigt soit retiré avant toute identification
    log::info!("Enrôlement terminé. Lève ton doigt...");
    unsafe {
        check_bep(
            sensor_wait_finger_not_present(ctx.chain, 5000),
            "sensor_wait_finger_not_present",
        )?;
    }

    // 5) Petite pause pour laisser le module se stabiliser
    thread::sleep(Duration::from_millis(150));

    Ok(())
}

pub fn check_once(timeout_ms: u32) -> Result<bool> {
    let ctx = SENSOR_CTX.lock().unwrap();
    if !ctx.is_set() {
        return Err(anyhow!("BM-Lite not initialized"));
    }

    // 1) Attendre que le doigt soit posé
    let t: u16 = timeout_ms.min(65_535) as u16;
    unsafe {
        check_bep(
            sensor_wait_finger_present(ctx.chain, t),
            "sensor_wait_finger_present",
        )?;
    }

    // 2) Identifier
    let mut tid: u16 = 0;
    let mut matched = false;
    unsafe {
        check_bep(
            bep_identify_finger(ctx.chain, timeout_ms, &mut tid, &mut matched),
            "bep_identify_finger",
        )?;
    }

    // 3) Attendre que le doigt soit retiré 
    unsafe {
        let _ = sensor_wait_finger_not_present(ctx.chain, 5000);
    }

    if matched {
        log::info!("Matched template id = {}", tid);
    }

    Ok(matched)
}

pub fn test_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    // On exige 3 reconnaissances OK
    for i in 1..=3 {
        log::info!("🖐️ Test empreinte {i}/3 — pose ton doigt");

        match check_once(15_000)? {
            true => log::info!("✅ Doigt reconnu"),
            false => return Err("Doigt non reconnu".into()),
        }
    }

    log::info!("🎉 Fingerprint validé 3/3");
    Ok(())
}

pub fn fingerprint_validation() -> Result<(), Box<dyn std::error::Error>>{
    init()?;
    //wipe_templates()?;
    //enroll_user()?;
    match is_user_enrolled(){
        Ok(true) => log::info!("User already enrolled, please verify yourself 3 times..."),
        Ok(false) => {
            log::warn!("No user enrolled, please enroll yourself...");
            wipe_templates()?;
            enroll_user()?;
        }
        Err(e) => return Err(e.into())
    }

    match test_fingerprint(){
        Ok(()) => log::info!("User authenticated !"),
        Err(e) => return Err(e.into())
    }

    Ok(())
}

pub fn test_fingerprint_once() -> Result<(), Box<dyn std::error::Error>> {

    log::info!("Test empreinte - pose ton doigt");

    let matched = wait_and_identify_sliced(
        25_000, // temps max pour poser le doigt
        200,    // slice attente doigt (200-500ms conseillé)
        10_000, // temps pour l'identification (scan)
    )?;

    if matched {
        log::info!("Doigt reconnu");
    } else {
        return Err("Doigt non reconnu".into());
    }

    log::info!("Fingerprint validé");
    Ok(())
}

pub fn wait_and_identify_sliced(
    wait_total_ms: u32,
    wait_slice_ms: u16,
    identify_ms: u32,
) -> Result<bool> {
    let ctx = SENSOR_CTX.lock().unwrap();
    if !ctx.is_set() {
        return Err(anyhow!("BM-Lite not initialized"));
    }

    let start_us = unsafe { esp_idf_sys::esp_timer_get_time() } as i64;
    let total_timeout_us = (wait_total_ms as i64) * 1000;

    // --- Phase A: attendre doigt en tranches courtes ---
    loop {
        let now_us = unsafe { esp_idf_sys::esp_timer_get_time() } as i64;
        if now_us - start_us >= total_timeout_us {
            return Ok(false); // pas de doigt dans le temps imparti
        }

        let rc = unsafe { sensor_wait_finger_present(ctx.chain, wait_slice_ms) };
        if rc == 0 {
            break; // doigt détecté
        }

        // laisse respirer (anti-WDT)
        unsafe { esp_idf_sys::vTaskDelay(1) };
    }

    // --- Phase B: identify (laisser le temps de scanner) ---
    let mut tid: u16 = 0;
    let mut matched = false;
    unsafe {
        check_bep(
            bep_identify_finger(ctx.chain, identify_ms, &mut tid, &mut matched),
            "bep_identify_finger",
        )?;
    }

    // --- Phase C: attendre retrait (optionnel) ---
    unsafe {
        let _ = sensor_wait_finger_not_present(ctx.chain, 5000);
    }

    if matched {
        log::info!("Matched template id = {}", tid);
    }

    Ok(matched)
}

pub fn enroll_once() -> Result<(), i32>{
    let mut wiped = 0;
    let mut enrolled = 0;
    
    while wiped != 1{
        match wipe_templates(){
            Ok(()) => {
                log::info!("OK wipe_templates");
                wiped = 1;
            }
            Err(rc) => {
                log::error!("Erreur wipe_templates: rc={}", rc);
            }
        }
    }
    while enrolled != 1{
        match enroll_user(){
            Ok(()) => {
                log::info!("OK enroll_user");
                enrolled = 1;
            }
            Err(rc) => {
                log::error!("Erreur enroll_user rc={}", rc);
            }
        }
    }

    Ok(())
}
