use core::{ptr, slice, sync::atomic::{AtomicU32, Ordering}};
use esp_idf_sys::*;
use super::pins::*;
use super::protocol::{Cmd, Header, MAGIC, MAX_PAYLOAD, RESP_FLAG, VERSION, CRC_LEN, spi_crc32};
pub const HDR_LEN: usize = core::mem::size_of::<Header>();
pub const FRAME_LEN: usize = HDR_LEN + MAX_PAYLOAD + CRC_LEN;

extern "C" {                                                                                                                                                                                                                              
      fn ets_delay_us(us: u32);
}

static IDLE_FEED_CTR: AtomicU32 = AtomicU32::new(0);
const ENABLE_SPI_PROF_LOGS: bool = true;

#[derive(Default)]
struct Perf{
    ops: u64,
    req_us: u64,
    wait_us: u64,
    resp_us: u64,
    tx_bytes: u64,
    rx_bytes: u64
}

impl Perf{
    #[inline]
    fn add_xfer_bytes(&mut self, nbytes: usize){
        self.tx_bytes += nbytes as u64;
        self.rx_bytes += nbytes as u64;
    }

    fn log_if_needed(&self){
        if !ENABLE_SPI_PROF_LOGS || self.ops == 0 || (self.ops % 256) != 0 {
            return;
        }
        let ops = self.ops as f64;

        let req_avg = self.req_us as f64 / ops;
        let wait_avg = self.wait_us as f64 / ops;
        let resp_avg = self.resp_us as f64 / ops;

        let total_us = (self.req_us + self.wait_us + self.resp_us) as f64;
        let tx_mb_s = (self.tx_bytes as f64) / total_us; // bytes/us == MB/s approx
        let rx_mb_s = (self.rx_bytes as f64) / total_us;

        log::info!(
            "SPI PROF avg/op: req={:.1}us wait={:.1}us resp={:.1}us | TX~{:.2}MB/s RX~{:.2}MB/s | ops={}",
            req_avg, wait_avg, resp_avg, tx_mb_s, rx_mb_s, self.ops
        );
    }
}

struct DmaBuf{
    ptr: *mut u8,
    len: usize,
}

impl DmaBuf{
    fn alloc(len: usize) -> Result<Self, i32>{
        unsafe {
            let p = heap_caps_malloc(len,(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL) as u32,) as *mut u8;
            if p.is_null(){
                return Err(ESP_ERR_NO_MEM);
            }

            //4-byte align min (DMA friendly)
            if (p as usize) & 0x3 != 0{
                heap_caps_free(p as *mut _);
                return Err(ESP_ERR_INVALID_STATE);
            }

            Ok(Self{ptr: p, len})
        }
    }

    #[inline]
    fn as_mut(&mut self) -> &mut [u8]{
        unsafe{slice::from_raw_parts_mut(self.ptr, self.len)}
    }

    #[inline]
    fn as_ref(&self) -> &[u8]{
        unsafe{slice::from_raw_parts(self.ptr, self.len)}
    }
}

impl Drop for DmaBuf{
    fn drop(&mut self){
        unsafe{
            if !self.ptr.is_null(){
                heap_caps_free(self.ptr as *mut _);
                self.ptr = ptr::null_mut();
                self.len = 0;
            }
        }
    }
}

pub struct SpiMaster{
    dev: spi_device_handle_t,
    seq: u16,
    needs_resync: bool,

    //persistant buffers (DMA-capable) : nothing on the stack
    tx: DmaBuf,
    rx: DmaBuf,

    perf: Perf
}

impl SpiMaster{
    pub fn new() -> Result<Self, i32>{
        Ok(Self{dev: ptr::null_mut(), seq: 1, needs_resync: false, tx: DmaBuf::alloc(FRAME_LEN)?, rx: DmaBuf::alloc(FRAME_LEN)?, perf: Perf::default()})
    }

    //called once at boot
    pub fn init(&mut self) -> Result<(), i32>{
        unsafe{
            // GPIO13 drive test — remove after diagnosis
            /*gpio_reset_pin(PIN_MOSI as gpio_num_t);
            gpio_set_direction(PIN_MOSI as gpio_num_t, gpio_mode_t_GPIO_MODE_OUTPUT);
            gpio_set_level(PIN_MOSI as gpio_num_t, 1);
            log::info!("GPIO13 drive test: HIGH for 5s");
            vTaskDelay(5000);
            gpio_set_level(PIN_MOSI as gpio_num_t, 0);
            log::info!("GPIO13 drive test: done");*/

            // READY pin
            gpio_reset_pin(PIN_READY as gpio_num_t);
            gpio_set_direction(PIN_READY as gpio_num_t, gpio_mode_t_GPIO_MODE_INPUT);

            // Bus cfg
            let mut buscfg: spi_bus_config_t = core::mem::zeroed();
            buscfg.__bindgen_anon_1.mosi_io_num = PIN_MOSI;
            buscfg.__bindgen_anon_2.miso_io_num = PIN_MISO;
            buscfg.sclk_io_num = PIN_SCLK;
            buscfg.__bindgen_anon_3.quadwp_io_num = -1;
            buscfg.__bindgen_anon_4.quadhd_io_num = -1;
            buscfg.data4_io_num = -1;
            buscfg.data5_io_num = -1;
            buscfg.data6_io_num = -1;
            buscfg.data7_io_num = -1;

            //one DMA transaction => one frame_len of bytes
            buscfg.max_transfer_sz = FRAME_LEN as i32;

            let dma: spi_dma_chan_t = spi_common_dma_t_SPI_DMA_CH_AUTO as spi_dma_chan_t;

            // attention si on remet le bmlite à changer !
            let err = spi_bus_initialize(spi_host_device_t_SPI2_HOST, &buscfg, dma);
            //log::info!("spi_bus_initialize ret={}", err);
            if err != ESP_OK{
                return Err(err);
            }

            //device cfg
            let mut devcfg: spi_device_interface_config_t = core::mem::zeroed();
            devcfg.clock_speed_hz = 60_000_000;
            devcfg.mode = 0;
            devcfg.spics_io_num = PIN_CS;
            devcfg.queue_size = 1;

            let mut dev: spi_device_handle_t = ptr::null_mut();
            let err = spi_bus_add_device(spi_host_device_t_SPI2_HOST, &devcfg, &mut dev);
            if err != ESP_OK{
                return Err(err);
            }

            self.dev = dev;
            Ok(())
        }
    }

    #[inline]
    fn ensure_ready(&self) -> Result<(), i32>{
        if self.dev.is_null(){
            Err(ESP_ERR_INVALID_STATE)
        } 
        else{
            Ok(())
        }
    }

    #[inline]
    fn next_seq(&mut self) -> u16{
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    #[inline]
    pub fn tx_buf_mut(&mut self) -> &mut [u8]{
        self.tx.as_mut()
    }

    #[inline]
    pub fn rx_buf(&self) -> &[u8]{
        self.rx.as_ref()
    }

    #[inline]
    fn rx_payload(&self) -> &[u8]{
        &self.rx_buf()[HDR_LEN..]
    }

    pub(crate) fn spi_xfer(&mut self, nbytes: usize) -> Result<(), i32>{
        self.ensure_ready()?;

        if nbytes == 0 || nbytes > FRAME_LEN{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        unsafe{
            let mut t: spi_transaction_t = core::mem::zeroed();
            t.length = (nbytes * 8) as usize;

            t.__bindgen_anon_1.tx_buffer = self.tx.ptr as *const _;
            t.__bindgen_anon_2.rx_buffer = self.rx.ptr as *mut _;

            let err = spi_device_transmit(self.dev, &mut t);
            if err != ESP_OK{
                return Err(err);
            }
        }

        self.perf.add_xfer_bytes(nbytes);
        Ok(())
    }

    pub(crate) fn wait_ready(timeout_ms: u32) -> Result<(), i32>{
        let start = unsafe {esp_timer_get_time() as i64};
        let timeout_us = (timeout_ms as i64) * 1000;
        let mut poll_ctr: u32 = 0;

        while unsafe {gpio_get_level(PIN_READY as gpio_num_t)} == 0{
            let now = unsafe {esp_timer_get_time() as i64};
            if now - start >= timeout_us{
                return Err(ESP_ERR_TIMEOUT);
            }
            unsafe {ets_delay_us(5)};
            poll_ctr = poll_ctr.wrapping_add(1);
            if poll_ctr % 1000 == 0{
                unsafe{vTaskDelay(1)};
            }
        }

        // After READY goes HIGH, the slave has signaled readiness but may not
        // have called spi_slave_xfer yet (DMA not armed). Give it time to
        // enter spi_slave_transmit and configure DMA descriptors before we
        // start clocking data on the bus.
        unsafe{ ets_delay_us(50) };

        if IDLE_FEED_CTR.fetch_add(1, Ordering::Relaxed) % 200 == 0{
            unsafe{vTaskDelay(1)};
        }
        Ok(())
    }

    pub(crate) fn wait_ready_low(timeout_ms: u32) -> Result<(), i32>{
        let start = unsafe{esp_timer_get_time() as i64};
        let timeout_us = (timeout_ms as i64) * 1000;
        
        while unsafe{gpio_get_level(PIN_READY as gpio_num_t)} != 0{
            let now = unsafe{esp_timer_get_time() as i64};
            if now - start >= timeout_us{
                return Err(ESP_ERR_TIMEOUT);
            }
            unsafe{ets_delay_us(5)};
        }
        Ok(())
    }

    pub(crate) fn validate_resp(resp: &Header, seq: u16, chunk_idx: u16) -> Result<(), i32>{
        let resp_reserved = resp.reserved;
        let resp_seq = resp.seq;
        let resp_cmd = resp.cmd;

        if resp.magic != MAGIC || resp.version != VERSION{
            log::error!("validate_resp FAIL: bad magic/ver magic=[{:#04x},{:#04x}] ver={} | expected magic={:?} ver={}",
                resp.magic[0], resp.magic[1], resp.version, MAGIC, VERSION);
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if (resp_cmd & RESP_FLAG) == 0{
            log::error!("validate_resp FAIL: no RESP_FLAG cmd={:#04x}", resp_cmd);
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if resp_seq != seq{
            log::error!("validate_resp FAIL: seq mismatch resp_seq={} expected={} cmd={:#04x}", resp_seq, seq, resp_cmd);
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if resp_reserved != chunk_idx{
            log::error!("validate_resp FAIL: chunk mismatch resp={} expected={} seq={}", resp_reserved, chunk_idx, resp_seq);
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        Ok(())
    }

    #[inline]
    pub fn read_resp_header(&self) -> Header{
        unsafe { ptr::read_unaligned(self.rx.ptr as *const Header) }
    }

    /// Wait for the slave to be idle (READY LOW) before sending a new command.
    /// After the slave finishes send_response (sets READY LOW), it needs a few
    /// microseconds to loop back and call spi_slave_xfer. Without this wait,
    /// the master can send a header before the slave's DMA is set up → lost data → desync.
    #[inline]
    fn wait_slave_idle(&self) -> Result<(), i32>{
        // if READY is already low, slave is idle — just need DMA setup time
        if unsafe{ gpio_get_level(PIN_READY as gpio_num_t) } == 0 {
            unsafe{ ets_delay_us(50) };
            return Ok(());
        }
        // READY is high — slave is still sending previous response, wait for it
        Self::wait_ready_low(2000)?;
        unsafe{ ets_delay_us(50) };
        Ok(())
    }

    /// After an SPI error (timeout, invalid response), the slave may still be
    /// processing the old command. Wait for it to finish, then drain any
    /// pending response by doing a dummy transfer.
    pub fn resync(&mut self){
        if !self.needs_resync{
            return;
        }
        log::warn!("SPI resync: waiting for slave to settle...");

        // give the slave time to finish whatever it's doing (USB write can take >100ms)
        unsafe{ vTaskDelay(200) }; // 200ms

        // wait for READY to go low (slave idle state)
        let _ = Self::wait_ready_low(500);

        // if READY is still high, drain the pending response
        if unsafe{ gpio_get_level(PIN_READY as gpio_num_t) } != 0{
            self.tx_buf_mut()[..HDR_LEN].fill(0);
            let _ = self.spi_xfer(FRAME_LEN);
            unsafe{ vTaskDelay(50) };
        }

        // wait for READY to go low again
        let _ = Self::wait_ready_low(500);

        self.needs_resync = false;
        log::warn!("SPI resync: done");
    }

    pub fn cmd_frame(&mut self, cmd: Cmd, chunk_idx: u16, arg0: u32, arg1: u32, ready_timeout_ms: u32, resp_payload_len: usize) -> Result<(Header, u16), i32>{
        self.resync();
        self.wait_slave_idle()?;
        let seq = self.next_seq();

        //phase 1: REQ
        self.tx_buf_mut().fill(0);

        let mut req = Header::new(cmd, seq, arg0, arg1);
        req.reserved = chunk_idx;

        let req_bytes = unsafe{slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)};
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);

        //log::info!("tx hdr: {:02x} {:02x} {:02x}", self.tx.as_ref()[0], self.tx.as_ref()[1], self.tx.as_ref()[2]);
        let t0 = unsafe { esp_timer_get_time() as i64 };
        self.spi_xfer(HDR_LEN)?;
        let t1 = unsafe { esp_timer_get_time() as i64 };

        //wait READY
        if let Err(e) = Self::wait_ready(ready_timeout_ms){
            self.needs_resync = true;
            return Err(e);
        }
        let t2 = unsafe { esp_timer_get_time() as i64 };

        //phase 2: RESP

        self.spi_xfer(HDR_LEN + resp_payload_len)?;
        let t3 = unsafe { esp_timer_get_time() as i64 };

        self.perf.req_us += (t1 - t0) as u64;
        self.perf.wait_us += (t2 - t1) as u64;
        self.perf.resp_us += (t3 - t2) as u64;
        self.perf.ops += 1;
        self.perf.log_if_needed();

        let resp: Header = unsafe{ptr::read_unaligned(self.rx.ptr as *const Header)};
        if let Err(e) = Self::validate_resp(&resp, seq, chunk_idx){
            self.needs_resync = true;
            return Err(e);
        }

        Ok((resp, seq))
    }

    pub fn write_frame(&mut self, chunk_idx: u16, lba_start: u32, nblocks_total: u32, payload: &[u8], ready_timeout_ms: u32) -> Result<(Header, u16), i32>{
        self.resync();
        self.wait_slave_idle()?;
        let seq = self.next_seq();

        if payload.len() > MAX_PAYLOAD{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        self.tx_buf_mut().fill(0);

        let mut req = Header::new(Cmd::Write, seq, lba_start, nblocks_total);
        req.reserved = chunk_idx;
        let req_bytes = unsafe{slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)};
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);

        let t0 = unsafe { esp_timer_get_time() as i64 };
        self.spi_xfer(HDR_LEN)?;
        let t1 = unsafe { esp_timer_get_time() as i64 };

        if let Err(e) = Self::wait_ready(ready_timeout_ms){
            self.needs_resync = true;
            return Err(e);
        }
        let t2 = unsafe { esp_timer_get_time() as i64 };

        let crc = spi_crc32(payload);
        self.tx_buf_mut()[..payload.len()].copy_from_slice(payload);
        self.tx_buf_mut()[payload.len()..payload.len() + CRC_LEN].copy_from_slice(&crc.to_le_bytes());
        self.spi_xfer(payload.len() + CRC_LEN)?;
        let t3 = unsafe { esp_timer_get_time() as i64 };

        if let Err(e) = Self::wait_ready_low(ready_timeout_ms){
            self.needs_resync = true;
            return Err(e);
        }
        if let Err(e) = Self::wait_ready(ready_timeout_ms){
            self.needs_resync = true;
            return Err(e);
        }
        let t4 = unsafe{ esp_timer_get_time() as i64 };

        self.tx_buf_mut()[..HDR_LEN].fill(0);
        self.spi_xfer(HDR_LEN)?;
        let t5 = unsafe{ esp_timer_get_time() as i64};


        self.perf.req_us += (t1 - t0) as u64;
        self.perf.wait_us += (t2 - t1 + t4 - t3) as u64;
        self.perf.resp_us += (t5 - t4) as u64;
        self.perf.ops += 1;
        self.perf.log_if_needed();

        let resp: Header = unsafe{ptr::read_unaligned(self.rx.ptr as *const Header)};
        if let Err(e) = Self::validate_resp(&resp, seq, chunk_idx){
            self.needs_resync = true;
            return Err(e);
        }

        Ok((resp, seq))
    }

    pub fn read_frame(&mut self, chunk_idx: u16, lba_start: u32, nblocks_total: u32, chunk_len: usize, ready_timeout_ms: u32) -> Result<(Header, u16), i32>{
        self.resync();
        self.wait_slave_idle()?;
        let xfer_len = HDR_LEN + chunk_len + CRC_LEN;
        if xfer_len > FRAME_LEN{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        let seq = self.next_seq();

        self.tx_buf_mut()[..xfer_len].fill(0);

        let mut req = Header::new(Cmd::Read, seq, lba_start, nblocks_total);
        req.reserved = chunk_idx;
        let req_bytes = unsafe{
            slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)
        };
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);

        let t0 = unsafe{ esp_timer_get_time() as i64 };
        self.spi_xfer(HDR_LEN)?;
        let t1 = unsafe{ esp_timer_get_time() as i64 };

        if let Err(e) = Self::wait_ready(ready_timeout_ms){
            self.needs_resync = true;
            return Err(e);
        }
        let t2 = unsafe{ esp_timer_get_time() as i64 };

        self.tx_buf_mut()[..xfer_len].fill(0);
        self.spi_xfer(xfer_len)?;
        let t3 = unsafe{ esp_timer_get_time() as i64 };

        self.perf.req_us += (t1 - t0) as u64;
        self.perf.wait_us += (t2 - t1) as u64;
        self.perf.resp_us += (t3 - t2) as u64;
        self.perf.ops += 1;
        self.perf.log_if_needed();

        let resp: Header = unsafe{ptr::read_unaligned(self.rx.ptr as *const Header)};
        if let Err(e) = Self::validate_resp(&resp, seq, chunk_idx){
            self.needs_resync = true;
            return Err(e);
        }

        // verify CRC32 on payload
        if chunk_len > 0{
            let payload = &self.rx_buf()[HDR_LEN..HDR_LEN + chunk_len];
            let crc_offset = HDR_LEN + chunk_len;
            let received_crc = u32::from_le_bytes([
                self.rx_buf()[crc_offset],
                self.rx_buf()[crc_offset + 1],
                self.rx_buf()[crc_offset + 2],
                self.rx_buf()[crc_offset + 3],
            ]);
            let computed_crc = spi_crc32(payload);
            if received_crc != computed_crc{
                log::error!("spi read_frame: CRC mismatch lba={} chunk={} received=0x{:08x} computed=0x{:08x}", lba_start, chunk_idx, received_crc, computed_crc);
                self.needs_resync = true;
                return Err(ESP_ERR_INVALID_CRC);
            }
        }

        Ok((resp, seq))
    }

    // Helpers utilisés par api_spi.rs
    #[inline]
    pub fn last_rx_payload(&self) -> &[u8]{
        self.rx_payload()
    }
}
