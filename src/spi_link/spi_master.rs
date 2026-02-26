use core::{ptr, slice};
use esp_idf_sys::*;
use super::pins::*;
use super::protocol::{Cmd, Header, MAGIC, MAX_PAYLOAD, RESP_FLAG, VERSION};
pub const HDR_LEN: usize = core::mem::size_of::<Header>();
pub const FRAME_LEN: usize = HDR_LEN + MAX_PAYLOAD;

extern "C"{
    fn ets_delay_us(us: u32);
}

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
        if self.ops == 0 || (self.ops % 256) != 0 {
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

    //persistant buffers (DMA-capable) : nothing on the stack
    tx: DmaBuf,
    rx: DmaBuf,

    perf: Perf
}

impl SpiMaster{
    pub fn new() -> Result<Self, i32>{
        Ok(Self{dev: ptr::null_mut(), seq: 1, tx: DmaBuf::alloc(FRAME_LEN)?, rx: DmaBuf::alloc(FRAME_LEN)?, perf: Perf::default()})
    }

    //called once at boot
    pub fn init(&mut self) -> Result<(), i32>{
        unsafe{
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

            let err = spi_bus_initialize(spi_host_device_t_SPI3_HOST, &buscfg, dma);
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
            let err = spi_bus_add_device(spi_host_device_t_SPI3_HOST, &devcfg, &mut dev);
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

        while unsafe {gpio_get_level(PIN_READY as gpio_num_t)} == 0{
            let now = unsafe {esp_timer_get_time() as i64};
            if now - start >= timeout_us{
                return Err(ESP_ERR_TIMEOUT);
            }
            unsafe {ets_delay_us(50)};
        }
        Ok(())
    }

    pub(crate) fn validate_resp(resp: &Header, seq: u16, chunk_idx: u16) -> Result<(), i32>{
        let resp_reserved = resp.reserved;
        let resp_seq = resp.seq;
        let resp_cmd = resp.cmd;

        if resp.magic != MAGIC || resp.version != VERSION{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if (resp_cmd & RESP_FLAG) == 0{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if resp_seq != seq{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if resp_reserved != chunk_idx{
            log::warn!("spi_master: chunk mismatch resp={} expected={}", resp_reserved, chunk_idx);
        }
        Ok(())
    }

    //ajout helper opti perf
    #[inline]
    pub fn build_read_req(&mut self, chunk_idx: u16, lba_start: u32, nblocks_total: u32) -> u16{
        let seq = self.next_seq();

        self.tx_buf_mut().fill(0);
        self.rx.as_mut().fill(0);

        let mut req = Header::new(Cmd::Read, seq, lba_start, nblocks_total);
        req.reserved = chunk_idx;

        let req_bytes = unsafe {
            slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)
        };
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);

        seq
    }

    pub(crate) fn build_write_req(&mut self, chunk_idx: u16, lba_start: u32, nblocks_total: u32, payload: &[u8]) -> Result<u16, i32>{
        if payload.len() > MAX_PAYLOAD{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        let seq = self.next_seq();
        self.tx_buf_mut().fill(0);
        self.rx.as_mut().fill(0);

        let mut req = Header::new(Cmd::Write, seq, lba_start, nblocks_total);
        req.reserved = chunk_idx;

        let req_bytes = unsafe{
            slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)
        };
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);
        self.tx_buf_mut()[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(payload);

        Ok(seq)
    }

    #[inline]
    pub fn read_resp_header(&self) -> Header{
        unsafe { ptr::read_unaligned(self.rx.ptr as *const Header) }
    }

    pub(crate) fn send_dummy_getstatus(&mut self) -> Result<u16, i32> {
        let seq = self.next_seq();

        self.tx_buf_mut().fill(0);
        self.rx.as_mut().fill(0);

        let mut req = Header::new(Cmd::GetStatus, seq, 0, 0);
        req.reserved = 0;

        let req_bytes = unsafe {
            slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)
        };
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);

        self.spi_xfer(FRAME_LEN)?;
        Ok(seq)
    }

    pub(crate) fn prof_add(&mut self, req_us: u64, wait_us: u64, resp_us: u64){
        self.perf.req_us += req_us;
        self.perf.wait_us += wait_us;
        self.perf.resp_us += resp_us;
        self.perf.ops += 1;
        self.perf.log_if_needed();
    }

    pub fn cmd_frame(&mut self, cmd: Cmd, chunk_idx: u16, arg0: u32, arg1: u32, ready_timeout_ms: u32) -> Result<(Header, u16), i32>{
        let seq = self.next_seq();

        //phase 1: REQ
        self.tx_buf_mut().fill(0);
        self.rx.as_mut().fill(0);

        let mut req = Header::new(cmd, seq, arg0, arg1);
        req.reserved = chunk_idx;

        let req_bytes = unsafe{slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)};
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);

        let t0 = unsafe { esp_timer_get_time() as i64 };
        self.spi_xfer(FRAME_LEN)?;
        let t1 = unsafe { esp_timer_get_time() as i64 };

        //wait READY
        Self::wait_ready(ready_timeout_ms)?;
        let t2 = unsafe { esp_timer_get_time() as i64 };

        //phase 2: RESP
        self.tx_buf_mut().fill(0);
        self.rx.as_mut().fill(0);

        self.spi_xfer(FRAME_LEN)?;
        let t3 = unsafe { esp_timer_get_time() as i64 };

        self.perf.req_us += (t1 - t0) as u64;
        self.perf.wait_us += (t2 - t1) as u64;
        self.perf.resp_us += (t3 - t2) as u64;
        self.perf.ops += 1;
        self.perf.log_if_needed();

        let resp: Header = unsafe{ptr::read_unaligned(self.rx.ptr as *const Header)};
        Self::validate_resp(&resp, seq, chunk_idx)?;

        Ok((resp, seq))
    }

    pub fn write_frame(&mut self, chunk_idx: u16, lba_start: u32, nblocks_total: u32, payload: &[u8], ready_timeout_ms: u32) -> Result<(Header, u16), i32>{
        let seq = self.next_seq();

        if payload.len() > MAX_PAYLOAD{
            return Err(ESP_ERR_INVALID_SIZE);
        }

        self.tx_buf_mut().fill(0);
        self.rx.as_mut().fill(0);

        let mut req = Header::new(Cmd::Write, seq, lba_start, nblocks_total);
        req.reserved = chunk_idx;

        let req_bytes = unsafe{slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)};
        self.tx_buf_mut()[..HDR_LEN].copy_from_slice(req_bytes);
        self.tx_buf_mut()[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(payload);

        let t0 = unsafe { esp_timer_get_time() as i64 };
        self.spi_xfer(FRAME_LEN)?;
        let t1 = unsafe { esp_timer_get_time() as i64 };

        Self::wait_ready(ready_timeout_ms)?;
        let t2 = unsafe { esp_timer_get_time() as i64 };

        self.tx_buf_mut().fill(0);
        self.rx.as_mut().fill(0);

        self.spi_xfer(FRAME_LEN)?;
        let t3 = unsafe { esp_timer_get_time() as i64 };

        self.perf.req_us += (t1 - t0) as u64;
        self.perf.wait_us += (t2 - t1) as u64;
        self.perf.resp_us += (t3 - t2) as u64;
        self.perf.ops += 1;
        self.perf.log_if_needed();

        let resp: Header = unsafe{ptr::read_unaligned(self.rx.ptr as *const Header)};
        Self::validate_resp(&resp, seq, chunk_idx)?;

        Ok((resp, seq))
    }

    // Helpers utilisés par api_spi.rs
    #[inline]
    pub fn last_rx_payload(&self) -> &[u8]{
        self.rx_payload()
    }
}