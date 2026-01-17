use super::protocol::{Cmd, Header, MAX_PAYLOAD, RESP_FLAG, MAGIC, VERSION};
use super::spi_master::{HDR_LEN, FRAME_LEN, SpiMaster};
use esp_idf_sys::*;
use core::ptr;

static mut GLOBAL_SPI: *mut SpiMaster = ptr::null_mut();

pub fn set_global_spi(master: &mut SpiMaster){
    unsafe{
        GLOBAL_SPI = master as *mut _;
    }
}

pub fn get_global_spi() -> Option<&'static mut SpiMaster>{
    unsafe{
        if GLOBAL_SPI.is_null(){
            None
        }
        else{
            Some(&mut *GLOBAL_SPI)
        }
    }
}

impl SpiMaster{
    pub fn get_status(&mut self) -> Result<(i32, u8), i32>{
        let mut tx = [0u8; FRAME_LEN];
        let mut rx = [0u8; FRAME_LEN];

        let seq = self.next_seq();
        let resp = self.do_cmd_frame(&mut tx, &mut rx, Cmd::GetStatus, seq, 0, 0, 0, 2000)?;
        let st = resp.arg0 as i32;

        //payload[0] = bd_status
        let bd_status = rx[HDR_LEN];
        Ok((st, bd_status))
    }

    pub fn get_capacity(&mut self) -> Result<(u32, u32), i32>{
        let mut tx = [0u8; FRAME_LEN];
        let mut rx = [0u8; FRAME_LEN];

        let seq = self.next_seq();
        let resp = self.do_cmd_frame(&mut tx, &mut rx, Cmd::GetCapacity, seq, 0, 0, 0, 2000)?;
        let st = resp.arg0 as i32;
        if st != ESP_OK{
            return Err(st);
        }

        let bs = u32::from_le_bytes([
            rx[HDR_LEN],
            rx[HDR_LEN + 1],
            rx[HDR_LEN + 2],
            rx[HDR_LEN + 3],
        ]);
        let bc = u32::from_le_bytes([
            rx[HDR_LEN + 4],
            rx[HDR_LEN + 5],
            rx[HDR_LEN + 6],
            rx[HDR_LEN + 7],
        ]);

        Ok((bs, bc))
    }

    //read (multi-chunk). out.len() must be exactly nblocks_total * block_size
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

        let chunks: u16 = ((total_bytes + (MAX_PAYLOAD - 1)) / MAX_PAYLOAD) as u16;

        let mut tx = [0u8; FRAME_LEN];
        let mut rx = [0u8; FRAME_LEN];

        for chunk_idx in 0..chunks{
            let seq = self.next_seq();

            let resp = self.do_cmd_frame(&mut tx, &mut rx, Cmd::Read, seq, chunk_idx, lba_start, nblocks_total, 5000)?;

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
            
            out[offset..offset + chunk_len].copy_from_slice(&rx[HDR_LEN..HDR_LEN + chunk_len]);
        }

        Ok(())
    }

    //write (multi-chunk). data.len() must be exactly nblocks_total * block_size
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

        let chunks: u16 = ((total_bytes + (MAX_PAYLOAD - 1)) / MAX_PAYLOAD) as u16;

        let mut tx = [0u8; FRAME_LEN];
        let mut rx = [0u8; FRAME_LEN];

        for chunk_idx in 0..chunks{
            let offset = (chunk_idx as usize) * MAX_PAYLOAD;
            let chunk_len = core::cmp::min(MAX_PAYLOAD, total_bytes - offset);
            if (chunk_len % (block_size as usize)) != 0{
                return Err(ESP_ERR_INVALID_SIZE);
            }

            let seq = self.next_seq();
            let payload = &data[offset..offset + chunk_len];

            let resp = self.do_write_frame(&mut tx, &mut rx, seq, chunk_idx, lba_start, nblocks_total, payload)?;

            let st = resp.arg0 as i32;
            if st != ESP_OK{
                return Err(st);
            }

            let written = resp.arg1 as usize;
            if written != chunk_len{
                return Err(ESP_ERR_INVALID_RESPONSE);
            }
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), i32>{
        let mut tx = [0u8; FRAME_LEN];
        let mut rx = [0u8; FRAME_LEN];

        let seq = self.next_seq();
        let resp = self.do_cmd_frame(&mut tx, &mut rx, Cmd::Flush, seq, 0, 0, 0, 5000)?;
        let st = resp.arg0 as i32;
        if st != ESP_OK{
            return Err(st);
        }
        Ok(())
    }
}

