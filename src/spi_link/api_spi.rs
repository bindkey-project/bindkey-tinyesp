use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use esp_idf_sys::*;
use super::protocol::{Cmd, MAX_PAYLOAD};
use super::spi_master::{HDR_LEN, SpiMaster};

static GLOBAL_SPI: AtomicPtr<SpiMaster> = AtomicPtr::new(ptr::null_mut());

//for stats
static SPI_CMD_COUNT: AtomicU32 = AtomicU32::new(0);
static SPI_TX_BYTES: AtomicU32 = AtomicU32::new(0);
static SPI_RX_BYTES: AtomicU32 = AtomicU32::new(0);
static SPI_TIME_US: AtomicU32 = AtomicU32::new(0);

pub fn set_global_spi(master: &mut SpiMaster){
    GLOBAL_SPI.store(master as *mut _, Ordering::Release);
}

pub fn get_global_spi() -> Option<&'static mut SpiMaster>{
    let p = GLOBAL_SPI.load(Ordering::Acquire);
    if p.is_null(){
        None
    } 
    else{
        unsafe{Some(&mut *p)}
    }
}

#[inline]
fn spi_stats_add(cmd: Cmd, tx_bytes: usize, rx_bytes: usize, dt_us: u64){
    let n = SPI_CMD_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    SPI_TX_BYTES.fetch_add(tx_bytes as u32, Ordering::Relaxed);
    SPI_RX_BYTES.fetch_add(rx_bytes as u32, Ordering::Relaxed);
    SPI_TIME_US.fetch_add(dt_us as u32, Ordering::Relaxed);

    if (n & 127) == 0{
        let tx = SPI_TX_BYTES.load(Ordering::Relaxed);
        let rx = SPI_RX_BYTES.load(Ordering::Relaxed);
        let t = SPI_TIME_US.load(Ordering::Relaxed);
        log::info!("SPI_STATS: n={} tx={}B rx={}B time={}us last_cmd={:?}", n, tx, rx, t, cmd);
    }
}

impl SpiMaster{
    pub fn get_status(&mut self) -> Result<(i32, u8), i32>{
        let t0 = unsafe{esp_timer_get_time() as i64};
        let (resp, _seq) = self.cmd_frame(Cmd::GetStatus, 0, 0, 0, 2000)?;
        let t1 = unsafe{esp_timer_get_time() as i64};

        let st = resp.arg0 as i32;
        //payload[0] = bd_status
        let bd_status = self.last_rx_payload()[0];

        spi_stats_add(Cmd::GetStatus, HDR_LEN, HDR_LEN + 1, (t1 - t0) as u64);
        Ok((st, bd_status))
    }

    pub fn get_capacity(&mut self) -> Result<(u32, u32), i32>{
        let t0 = unsafe{esp_timer_get_time() as i64};
        let (resp, _seq) = self.cmd_frame(Cmd::GetCapacity, 0, 0, 0, 2000)?;
        let t1 = unsafe{esp_timer_get_time() as i64};

        let st = resp.arg0 as i32;
        if st != ESP_OK{
            return Err(st);
        }

        let p = self.last_rx_payload();

        let bs = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
        let bc = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);

        spi_stats_add(Cmd::GetCapacity, HDR_LEN, HDR_LEN + 8, (t1 - t0) as u64);
        Ok((bs, bc))
    }

    //read multi-chunks. out.len() == nblocks_total * block_size
    pub fn read(&mut self, lba_start: u32, nblocks_total: u32, block_size: u32, out: &mut [u8]) -> Result<(), i32>{
        let total_bytes = (nblocks_total as usize) * (block_size as usize);
        if out.len() != total_bytes{
            return Err(ESP_ERR_INVALID_SIZE);
        }
        if block_size == 0 || (block_size as usize) > MAX_PAYLOAD{
            return Err(ESP_ERR_INVALID_SIZE);
        }
        if (MAX_PAYLOAD % (block_size as usize)) != 0{
            return Err(ESP_ERR_INVALID_STATE);
        }

        let chunks_usize = (total_bytes + (MAX_PAYLOAD - 1)) / MAX_PAYLOAD;
        if chunks_usize > (u16::MAX as usize){
            return Err(ESP_ERR_INVALID_SIZE);
        }
        let chunks = chunks_usize as u16;

        for chunk_idx in 0..chunks{
            let t0 = unsafe{esp_timer_get_time() as i64};
            let (resp, _seq) = self.cmd_frame(Cmd::Read, chunk_idx, lba_start, nblocks_total, 5000)?;
            let t1 = unsafe{esp_timer_get_time() as i64};

            let st = resp.arg0 as i32;
            if st != ESP_OK{
                return Err(st);
            }

            let chunk_len = resp.arg1 as usize;
            if chunk_len == 0 || chunk_len > MAX_PAYLOAD{
                return Err(ESP_ERR_INVALID_RESPONSE);
            }
            if (chunk_len % (block_size as usize)) != 0{
                return Err(ESP_ERR_INVALID_RESPONSE);
            }

            let offset = (chunk_idx as usize) * MAX_PAYLOAD;
            if offset + chunk_len > out.len(){
                return Err(ESP_ERR_INVALID_SIZE);
            }

            let payload = &self.last_rx_payload()[..chunk_len];
            out[offset..offset + chunk_len].copy_from_slice(payload);

            spi_stats_add(Cmd::Read, HDR_LEN, HDR_LEN + chunk_len, (t1 - t0) as u64);
        }

        Ok(())
    }

    /// WRITE multi-chunks. data.len() == nblocks_total * block_size
    pub fn write(&mut self, lba_start: u32, nblocks_total: u32, block_size: u32, data: &[u8]) -> Result<(), i32>{
        let total_bytes = (nblocks_total as usize) * (block_size as usize);
        if data.len() != total_bytes{
            return Err(ESP_ERR_INVALID_SIZE);
        }
        if block_size == 0 || (block_size as usize) > MAX_PAYLOAD{
            return Err(ESP_ERR_INVALID_SIZE);
        }
        if (MAX_PAYLOAD % (block_size as usize)) != 0{
            return Err(ESP_ERR_INVALID_STATE);
        }

        let chunks_usize = (total_bytes + (MAX_PAYLOAD - 1)) / MAX_PAYLOAD;
        if chunks_usize > (u16::MAX as usize){
            return Err(ESP_ERR_INVALID_SIZE);
        }
        let chunks = chunks_usize as u16;

        for chunk_idx in 0..chunks{
            let offset = (chunk_idx as usize) * MAX_PAYLOAD;
            let chunk_len = core::cmp::min(MAX_PAYLOAD, total_bytes - offset);

            if (chunk_len % (block_size as usize)) != 0{
                return Err(ESP_ERR_INVALID_SIZE);
            }

            let payload = &data[offset..offset + chunk_len];

            let t0 = unsafe{esp_timer_get_time() as i64};
            let (resp, _seq) = self.write_frame(chunk_idx, lba_start, nblocks_total, payload, 5000)?;
            let t1 = unsafe{esp_timer_get_time() as i64};

            let st = resp.arg0 as i32;
            if st != ESP_OK{
                return Err(st);
            }

            let written = resp.arg1 as usize;
            if written != chunk_len{
                return Err(ESP_ERR_INVALID_RESPONSE);
            }

            spi_stats_add(Cmd::Write, HDR_LEN + payload.len(), HDR_LEN, (t1 - t0) as u64);
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), i32>{
        let t0 = unsafe{esp_timer_get_time() as i64};
        let (resp, _seq) = self.cmd_frame(Cmd::Flush, 0, 0, 0, 5000)?;
        let t1 = unsafe{esp_timer_get_time() as i64};

        let st = resp.arg0 as i32;
        if st != ESP_OK{
            return Err(st);
        }

        spi_stats_add(Cmd::Flush, HDR_LEN, HDR_LEN, (t1 - t0) as u64);
        Ok(())
    }
}
