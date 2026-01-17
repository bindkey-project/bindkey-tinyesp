use core::mem;
use core::ptr;
use std::thread;
use std::time::Duration;

use esp_idf_sys::*;

use super::pins::*;
use super::protocol::{payload, Cmd, Header, MAX_PAYLOAD, RESP_FLAG, MAGIC, VERSION};

pub const HDR_LEN: usize = core::mem::size_of::<Header>();
pub const FRAME_LEN: usize = HDR_LEN + MAX_PAYLOAD;

pub struct SpiMaster{
    dev: spi_device_handle_t,
    seq: u16,
}

impl SpiMaster{
    pub fn new() -> Self{
        Self{
            dev: core::ptr::null_mut(),
            seq: 1,
        }
    }

    //call once at boot
    pub fn init(&mut self) -> Result<(), i32>{
        unsafe{
            gpio_reset_pin(PIN_READY as gpio_num_t);
            gpio_set_direction(PIN_READY as gpio_num_t, gpio_mode_t_GPIO_MODE_INPUT);

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
            buscfg.max_transfer_sz = FRAME_LEN as i32;

            let dma: spi_dma_chan_t = spi_common_dma_t_SPI_DMA_CH_AUTO as spi_dma_chan_t;

            let err = spi_bus_initialize(spi_host_device_t_SPI3_HOST, &buscfg, dma);
            if err != ESP_OK{
                return Err(err);
            }

            //device config
            let mut devcfg: spi_device_interface_config_t = core::mem::zeroed();
            devcfg.clock_speed_hz = 200_000;
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
    pub (crate) fn next_seq(&mut self) -> u16{
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn spi_xfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), i32>{
        if tx.len() != rx.len(){
            return Err(ESP_ERR_INVALID_SIZE);
        }

        unsafe{
            let mut t: spi_transaction_t = core::mem::zeroed();
            t.length = (tx.len() * 8) as usize;
            t.__bindgen_anon_1.tx_buffer = tx.as_ptr() as *const _;
            t.__bindgen_anon_2.rx_buffer = rx.as_mut_ptr() as *mut _;

            let err = spi_device_transmit(self.dev, &mut t);
            if err != ESP_OK{
                return Err(err);
            }
        }

        Ok(())
    }

    fn wait_ready(timeout_ms: u32) -> bool{
        let mut waited = 0u32;
        while unsafe { gpio_get_level(PIN_READY as gpio_num_t) } == 0{
            thread::sleep(Duration::from_millis(1));
            waited += 1;
            if waited >= timeout_ms{
                return false;
            }
        }
        true
    }

    //generic 2-phase command REQ header only, then RESP
    pub(crate) fn do_cmd_frame(&self, tx: &mut [u8; FRAME_LEN], rx: &mut [u8; FRAME_LEN], cmd: Cmd, seq: u16, chunk_idx: u16, arg0: u32, arg1: u32, ready_timeout_ms: u32) -> Result<Header, i32>{
        //Phase 1: REQ
        tx.fill(0);
        rx.fill(0);

        let mut req = Header::new(cmd, seq, arg0, arg1);
        req.reserved = chunk_idx;

        let req_bytes = unsafe{
            core::slice::from_raw_parts((&req as *const Header) as *const u8, HDR_LEN)
        };
        tx[..HDR_LEN].copy_from_slice(req_bytes);

        self.spi_xfer(tx, rx)?;

        //wait READY
        if !Self::wait_ready(ready_timeout_ms){
            return Err(ESP_ERR_TIMEOUT);
        }

        
        //Phase 2: RESP_READ
        tx.fill(0);
        rx.fill(0);
        self.spi_xfer(tx, rx)?;

        let resp: Header = unsafe{
            core::ptr::read_unaligned(rx.as_ptr() as *const Header)
        };

        if resp.magic != MAGIC || resp.version != VERSION{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if (resp.cmd & RESP_FLAG) == 0{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if resp.seq != seq{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        let resp_reserved = resp.reserved;
        if resp.reserved != chunk_idx {
            log::warn!("spi_master: chunk mismatch resp={} expected={}", resp_reserved, chunk_idx);
        }

        Ok(resp)
    }

    pub(crate) fn do_write_frame(&self, tx: &mut [u8; FRAME_LEN], rx: &mut [u8; FRAME_LEN], seq: u16, chunk_idx: u16, lba_start: u32, nblocks_total: u32, chunk_payload: &[u8]) -> Result<Header, i32>{
        tx.fill(0);
        rx.fill(0);

        let mut req = Header::new(Cmd::Write, seq, lba_start, nblocks_total);
        req.reserved = chunk_idx;

        let req_bytes = unsafe{
            core::slice::from_raw_parts(
                (&req as *const Header) as *const u8, HDR_LEN)
        };
        tx[..HDR_LEN].copy_from_slice(req_bytes);

        let n = core::cmp::min(chunk_payload.len(), MAX_PAYLOAD);
        tx[HDR_LEN..HDR_LEN + n].copy_from_slice(&chunk_payload[..n]);

        self.spi_xfer(tx, rx)?;

        if !Self::wait_ready(5000){
            return Err(ESP_ERR_TIMEOUT);
        }

        tx.fill(0);
        rx.fill(0);
        self.spi_xfer(tx, rx)?;

        let resp: Header = unsafe{
            core::ptr::read_unaligned(rx.as_ptr() as *const Header)
        };
        
        if resp.magic != MAGIC || resp.version != VERSION{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if (resp.cmd & RESP_FLAG) == 0{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        if resp.seq != seq{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }
        let resp_reserved = resp.reserved;
        if resp.reserved != chunk_idx{
            log::warn!("spi_master: chunk mismatch resp={} expected={}", resp_reserved, chunk_idx);
        }

        Ok(resp)
    }
}