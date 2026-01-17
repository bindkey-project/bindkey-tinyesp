pub const MAGIC: [u8; 2] = *b"BK";

pub const VERSION: u8 = 1;

pub const RESP_FLAG: u8 = 0x80;

pub const MAX_PAYLOAD: usize = 512;

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
pub struct Header{ //16 bytes header
    pub magic: [u8; 2], //identify BindKey protocol
    pub version: u8, //protocol version
    pub cmd: u8, //which action asked and req/resp?
    pub seq: u16, //associate response to its request
    pub reserved: u16, //chunk_idx (0,1,2,...) for multi-block chunking
    pub arg0: u32, //1st generic parameter (ex: lba, status...)
    pub arg1: u32, //2st generic parameter (ex: nblocks, block_count, flags...)
}

impl Header {
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

    #[inline]
    pub fn is_valid(&self) -> bool{
        self.magic == MAGIC && self.version == VERSION
    }

    #[inline]
    pub fn is_response(&self) -> bool{
        (self.cmd & RESP_FLAG) != 0
    }

    #[inline]
    pub fn cmd_base(&self) -> u8{
        self.cmd & !RESP_FLAG
    }

    #[inline]
    pub fn cmd_enum(&self) -> Option<Cmd>{
        Cmd::from_u8(self.cmd_base())
    }

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


//module payload utilitaire
pub mod payload{
    #[inline]
    pub fn encode_capacity(block_size: u32, block_count: u32) -> [u8; 8]{
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&block_size.to_le_bytes());
        out[4..8].copy_from_slice(&block_count.to_le_bytes());
        out
    }
}

