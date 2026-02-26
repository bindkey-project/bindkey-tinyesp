use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use esp_idf_sys::*;
use super::protocol::{Cmd, MAX_PAYLOAD};
use super::spi_master::{HDR_LEN, SpiMaster, FRAME_LEN};

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

    if (n & 1023) == 0{
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
        if chunks_usize == 0{
            return Ok(());
        }
        if chunks_usize > (u16::MAX as usize){
            return Err(ESP_ERR_INVALID_SIZE);
        }
        let chunks = chunks_usize as u16;

        //prime (init chunk 0)
        let seq0 = self.build_read_req(0, lba_start, nblocks_total);
        let t0 = unsafe{esp_timer_get_time() as i64};
        self.spi_xfer(FRAME_LEN)?;
        let t1 = unsafe{esp_timer_get_time() as i64};
        spi_stats_add(Cmd::Read, HDR_LEN, HDR_LEN, (t1 - t0) as u64);

        let mut prev_seq = seq0;
        let mut prev_chunk: u16 = 0;

        //pipelining
        for chunk_idx in 1..chunks{
            let tw0 = unsafe{esp_timer_get_time() as i64};
            SpiMaster::wait_ready(5000)?;
            let tw1 = unsafe{esp_timer_get_time() as i64};

            let seq_i = self.build_read_req(chunk_idx, lba_start, nblocks_total);

            let tx0 = unsafe{esp_timer_get_time() as i64};
            self.spi_xfer(FRAME_LEN)?;
            let tx1 = unsafe{esp_timer_get_time() as i64};

            let resp = self.read_resp_header();
            SpiMaster::validate_resp(&resp, prev_seq, prev_chunk)?;

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

            let offset = (prev_chunk as usize) * MAX_PAYLOAD;
            if offset + chunk_len > out.len(){
                return Err(ESP_ERR_INVALID_SIZE);
            }

            out[offset..offset + chunk_len].copy_from_slice(&self.last_rx_payload()[..chunk_len]);

            self.prof_add(0, (tw1 - tw0) as u64, (tx1 - tx0) as u64);

            spi_stats_add(Cmd::Read, HDR_LEN, HDR_LEN + chunk_len, (tx1 - tw0) as u64);

            prev_seq = seq_i;
            prev_chunk = chunk_idx;
        }

        //drain: get last chunk response
        let tw0 = unsafe{esp_timer_get_time() as i64};
        SpiMaster::wait_ready(5000)?;
        let tw1 = unsafe{esp_timer_get_time() as i64};


        let tx0 = unsafe{esp_timer_get_time() as i64};
        let _dummy_seq = self.send_dummy_getstatus()?; // fait spi_xfer(FRAME_LEN)
        let tx1 = unsafe{esp_timer_get_time() as i64};

        let resp = self.read_resp_header();
        SpiMaster::validate_resp(&resp, prev_seq, prev_chunk)?;

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

        let offset = (prev_chunk as usize) * MAX_PAYLOAD;
        if offset + chunk_len > out.len(){
            return Err(ESP_ERR_INVALID_SIZE);
        }

        out[offset..offset + chunk_len].copy_from_slice(&self.last_rx_payload()[..chunk_len]);

        self.prof_add(0, (tw1 - tw0) as u64, (tx1 - tx0) as u64);

        spi_stats_add(Cmd::Read, HDR_LEN, HDR_LEN + chunk_len, (tx1 - tw0) as u64);

        Ok(())
    }

    //write multi-chunks => pipelined data.len() == nblocks_total * block_size
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
        if chunks_usize == 0{
            return Ok(());
        }
        if chunks_usize > (u16::MAX as usize){
            return Err(ESP_ERR_INVALID_SIZE);
        }
        let chunks = chunks_usize as u16;

        let chunk_slice = |chunk_idx: u16| -> Result<&[u8], i32>{
            let offset = (chunk_idx as usize) * MAX_PAYLOAD;
            let chunk_len = core::cmp::min(MAX_PAYLOAD, total_bytes - offset);
            if (chunk_len % (block_size as usize)) != 0{
                return Err(ESP_ERR_INVALID_SIZE);
            }
            Ok(&data[offset..offset + chunk_len])
        };

        //prime
        let p0 = chunk_slice(0)?;
        let t0 = unsafe{esp_timer_get_time() as i64};
        let seq0 = self.build_write_req(0, lba_start, nblocks_total, p0)?;
        self.spi_xfer(FRAME_LEN)?;
        let t1 = unsafe{esp_timer_get_time() as i64};
        spi_stats_add(Cmd::Write, HDR_LEN + p0.len(), HDR_LEN, (t1 - t0) as u64);

        let mut prev_seq = seq0;
        let mut prev_chunk: u16 = 0;
        let mut prev_len: usize = p0.len();

        //pipeline
        for chunk_idx in 1..chunks{
            let tw0 = unsafe{esp_timer_get_time() as i64};
            SpiMaster::wait_ready(5000)?;
            let tw1 = unsafe{esp_timer_get_time() as i64};

            let pi = chunk_slice(chunk_idx)?;

            let tx0 = unsafe{esp_timer_get_time() as i64};
            let seq_i = self.build_write_req(chunk_idx, lba_start, nblocks_total, pi)?;
            self.spi_xfer(FRAME_LEN)?;
            let tx1 = unsafe{esp_timer_get_time() as i64};

            let resp = self.read_resp_header();
            SpiMaster::validate_resp(&resp, prev_seq, prev_chunk)?;

            let st = resp.arg0 as i32;
            if st != ESP_OK{
                return Err(st);
            }

            let written = resp.arg1 as usize;
            if written != prev_len{
                return Err(ESP_ERR_INVALID_RESPONSE);
            }

            self.prof_add(0, (tw1 - tw0) as u64, (tx1 - tx0) as u64);
            spi_stats_add(Cmd::Write, HDR_LEN + pi.len(), HDR_LEN, (tx1 - tw0) as u64);

            prev_seq = seq_i;
            prev_chunk = chunk_idx;
            prev_len = pi.len();
        }

        //drain => last chunk
        let tw0 = unsafe{esp_timer_get_time() as i64};
        SpiMaster::wait_ready(5000)?;
        let tw1 = unsafe{esp_timer_get_time() as i64};

        let tx0 = unsafe{esp_timer_get_time() as i64};
        let _ = self.send_dummy_getstatus()?;
        let tx1 = unsafe{esp_timer_get_time() as i64};

        let resp = self.read_resp_header();
        SpiMaster::validate_resp(&resp, prev_seq, prev_chunk)?;

        let st = resp.arg0 as i32;
        if st != ESP_OK{
            return Err(st);
        } 

        let written = resp.arg1 as usize;
        if written != prev_len{
            return Err(ESP_ERR_INVALID_RESPONSE);
        }

        self.prof_add(0, (tw1 - tw0) as u64, (tx1 - tx0) as u64);
        spi_stats_add(Cmd::Write, HDR_LEN, HDR_LEN, (tx1 - tw0) as u64);
        
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
