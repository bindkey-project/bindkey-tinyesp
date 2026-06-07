// 2-byte magic identifying the BindKey SPI protocol
pub const MAGIC: [u8; 2] = *b"BK";

// protocol version
pub const VERSION: u8 = 1;

// OR'd into cmd to mark a frame as a response
pub const RESP_FLAG: u8 = 0x80;

pub const MAX_PAYLOAD: usize = 8192; // 512 tested ok => 4096
pub const CRC_LEN: usize = 4;

// CRC32 IEEE 802.3 over a payload (identical on master and slave)
#[inline]
pub fn spi_crc32(data: &[u8]) -> u32{
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data{
        crc ^= b as u32;
        for _ in 0..8{
            if crc & 1 != 0{
                crc = (crc >> 1) ^ 0xEDB8_8320;
            }
            else{
                crc >>= 1;
            }
        }
    }
    !crc
}

// Payload conventions:
//
// GET_STATUS response payload (1 byte):
//   0 = NotPresent
//   1 = NotReady
//   2 = Ready
//
// GET_CAPACITY response payload (8 bytes):
//   u32 block_size (LE)
//   u32 block_count (LE)
//
// READ response payload:
//   data bytes (nblocks * block_size)
//
// WRITE request payload:
//   data bytes (nblocks * block_size)



// SPI command set (master → slave)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    GetStatus = 1,
    GetCapacity = 2,
    Read = 3,
    Write = 4,
    Flush = 5,
}

impl Cmd {
    // parses a command byte (base value, without the response flag)
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self>{
        match v {
            1 => Some(Cmd::GetStatus),
            2 => Some(Cmd::GetCapacity),
            3 => Some(Cmd::Read),
            4 => Some(Cmd::Write),
            5 => Some(Cmd::Flush),
            _ => None,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Header{ // 16-byte header
    pub magic: [u8; 2], // identifies the BindKey protocol
    pub version: u8, // protocol version
    pub cmd: u8, // requested command, with RESP_FLAG set on responses
    pub seq: u16, // associates a response to its request
    pub reserved: u16, // chunk_idx (0,1,2,...) for multi-block chunking
    pub arg0: u32, // 1st generic parameter (e.g. lba, status...)
    pub arg1: u32, // 2nd generic parameter (e.g. nblocks, block_count, flags...)
}

impl Header {
    // builds a request header
    #[inline]
    pub fn new(cmd: Cmd, seq: u16, arg0: u32, arg1: u32) -> Self{
        Self{
            magic: MAGIC,
            version: VERSION,
            cmd: cmd as u8,
            seq,
            reserved: 0,
            arg0,
            arg1,
        }
    }

    // true if magic and version match
    #[inline]
    pub fn is_valid(&self) -> bool{
        self.magic == MAGIC && self.version == VERSION
    }

    // true if the response flag is set
    #[inline]
    pub fn is_response(&self) -> bool{
        (self.cmd & RESP_FLAG) != 0
    }

    // command value without the response flag
    #[inline]
    pub fn cmd_base(&self) -> u8{
        self.cmd & !RESP_FLAG
    }

    // decodes the base command into the Cmd enum
    #[inline]
    pub fn cmd_enum(&self) -> Option<Cmd>{
        Cmd::from_u8(self.cmd_base())
    }

    // builds the response header matching a request, carrying a status
    #[inline]
    pub fn response_for(req: &Header, status: i32) -> Self{
        Self{
            magic: MAGIC,
            version: VERSION,
            cmd: req.cmd_base() | RESP_FLAG,
            seq: req.seq,
            reserved: 0,
            arg0: status as u32,
            arg1: 0,
        }
    }
}


// payload encoding helpers
pub mod payload{
    // packs (block_size, block_count) as two LE u32 for a GetCapacity response
    #[inline]
    pub fn encode_capacity(block_size: u32, block_count: u32) -> [u8; 8]{
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&block_size.to_le_bytes());
        out[4..8].copy_from_slice(&block_count.to_le_bytes());
        out
    }
}

