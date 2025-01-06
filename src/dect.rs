use bitvec::{order::Msb0, vec::BitVec};

pub const FP_SYNC: u32 = 0xAAE98A;
pub const PP_SYNC: u32 = 0x551675;
pub const GP: u16 = 0x0589;

pub trait Rcrc {
    fn crc(&self) -> u16;
}

impl Rcrc for [u8; 8] {
    fn crc(&self) -> u16 {
        let mut crc = ((self[0] as u16) << 8) | (self[1] as u16);
        let mut next;
        let mut y = 0;
        let mut x;

        while y < 6 {
            next = self[2 + y];
            y += 1;
            x = 0;
            while x < 8 {
                while (crc & 0x8000) == 0 {
                    crc <<= 1;
                    crc |= if (next & 0x80) == 0 { 0 } else { 1 };
                    next <<= 1;
                    x += 1;
                    if x > 7 {
                        break;
                    }
                }
                if x > 7 {
                    break;
                }
                crc <<= 1;
                crc |= if (next & 0x80) == 0 { 0 } else { 1 };
                next <<= 1;
                x += 1;
                crc ^= GP;
            }
        }
        crc ^= 1;
        crc
    }
}

// 7.1 https://www.etsi.org/deliver/etsi_en/300100_300199/30017503/02.08.01_60/en_30017503v020801p.pdf
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum TailIdentificationRFP {
    CtDataPktNum0 = 0b000,
    CtDataPktNum1 = 0b001,
    NtIdentitiesInfoBearer = 0b010,
    NtIdentitiesInfo = 0b011,
    QtMultiFrameSyncAndSysInfo = 0b100,
    CombinedCoding = 0b101,
    MtMACLayerControl = 0b110,
    MtPagingTail = 0b111,
}

impl From<u8> for TailIdentificationRFP {
    fn from(ident: u8) -> Self {
        if ident > TailIdentificationRFP::MtPagingTail as u8 {
            panic!("Invalid TA value")
        }
        unsafe { core::mem::transmute(ident) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum TailIdentificationPP {
    CtDataPktNum0 = 0b000,
    CtDataPktNum1 = 0b001,
    NtULE = 0b010,
    NtIdentitiesInfo = 0b011,
    QtMultiFrameSyncAndSysInfo = 0b100,
    CombinedCoding = 0b101,
    MtMACLayerControl = 0b110,
    MtFirstPPTransmission = 0b111,
}

impl From<u8> for TailIdentificationPP {
    fn from(ident: u8) -> Self {
        if ident > TailIdentificationPP::MtFirstPPTransmission as u8 {
            panic!("Invalid TA value")
        }
        unsafe { core::mem::transmute(ident) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum BFieldIdentification {
    NoValidErrorDetectChanData = 0b000, // CHANGEME
    NoValidINChannelData = 0b001,       // CHANGEME
    DoubleSlotRequired = 0b010,
    NotAllCLFPacketNum1 = 0b011, // CHANGEME
    HalfSlotRequired = 0b100,
    LongSlotRequiredJ640 = 0b101,
    LongSlotRequiredJ672 = 0b110,
    NoSlotRequired = 0b111, // CHANGEME
                            // NOTE: the combined coding of bits in TA have unique encodings.
}

impl From<u8> for BFieldIdentification {
    fn from(ident: u8) -> Self {
        if ident > BFieldIdentification::NoSlotRequired as u8 {
            panic!("invalid BA value")
        }
        unsafe { core::mem::transmute(ident) }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum TailIdentification {
    Rfp(TailIdentificationRFP),
    Pp(TailIdentificationPP),
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct MACHeader {
    pub tail_ident: TailIdentification,
    pub q1_bck_bit: bool,
    pub b_field_ident: BFieldIdentification,
    pub q2_bit: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MACPacket {
    pub header: MACHeader,
    pub tail: [u8; 5],
    pub b_field: Option<BitVec<u8, Msb0>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum MacBody {
    MtMacControl(MtMacControl),
    Escape(BitVec<u8, Msb0>),
    QualityControl(MtQualityControl),
    Empty,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct L2MACPacket {
    pub header: MACHeader,
    pub payload: Option<MacBody>,
}

// DECT defines four message types: N, Q, P, M
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct NtIdentifiesInfo(pub u64);
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct QtMultiFrameAndSysInfo(pub u64);
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct PtPagingTail(pub u64);
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct MtMACControl(pub u64);

#[derive(Debug, Clone)]
#[repr(u64)]
#[allow(dead_code)]
pub enum TailMessage {
    Nt(NtIdentifiesInfo),
    Qt(QtMultiFrameAndSysInfo),
    Pt(PtPagingTail),
    Mt(MtMACControl),
}

// M message type parsing.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum MtMACControlHeader {
    BasicConnectionControl = 0b0000,
    AdvConnectionControl = 0b0001,
    MACLayerTestMessages = 0b0010,
    QualityControl = 0b0011,
    BrdAndConnlessServices = 0b0100,
    EncryptionControl = 0b0101,
    FirstBearerRequest = 0b0110,
    Escape = 0b0111,
    TARIMessage = 0b1000,
    REPConnectionControl = 0b1001,
    AdvConnectionControl2 = 0b1010,
    Reserved,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum MtBasicConnectionControlCommand {
    AccessRequest = 0b0000,
    BearerHandoverRequest = 0b0001,
    BearerHandoverConfirm = 0b0010,
    UnconfirmedAccessRequest = 0b0011,
    BearerConfirm = 0b0100,
    Wait = 0b0101,
    AttributesTRequest = 0b0110,
    AttributesTConfirm = 0b0111,
    Reserved,
    Release = 0b1111,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum MtAdvConnectionControlCommand {
    AccessRequest = 0b0000,
    BearerHandoverRequest = 0b0001,
    BearerHandoverConfirm = 0b0010,
    UnconfirmedAccessRequest = 0b0011,
    BearerConfirm = 0b0100,
    Wait = 0b0101,
    AttributesTRequest = 0b0110,
    AttributesTConfirm = 0b0111,
    BandwidthTRequest = 0b1000,
    BandwidthTConfirm = 0b1001,
    ChannelList = 0b1010,
    UnconfirmedDummy = 0b1011,
    UnconfirmedHandover = 0b1100,
    Reserved = 0b1101,
    Reserved2 = 0b1110,
    Release = 0b1111,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct MtQualityControl {
    pub command: u8,
    pub param_1: u8,
    pub param_2: u8,
    pub check: u16,
}

impl From<u8> for MtAdvConnectionControlCommand {
    fn from(ident: u8) -> Self {
        unsafe { core::mem::transmute::<u8, Self>(ident & 0b1111) }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum MtMacControl {
    BasicConnectionControl(MtBasicConnectionControl),
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct MtFirstPPTransmission {
    pub fmid: u16,
    pub pmid: u32,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum MtBasicConnectionControl {
    AccessRequest(MtFirstPPTransmission),
}

impl From<u8> for MtBasicConnectionControlCommand {
    fn from(ident: u8) -> Self {
        let ident = ident & 0b1111;
        if ident >= MtMACControlHeader::Reserved as u8
            && ident < MtBasicConnectionControlCommand::Release as u8
        {
            MtBasicConnectionControlCommand::Reserved
        } else {
            unsafe { core::mem::transmute::<u8, Self>(ident) }
        }
    }
}

impl From<u8> for MtMACControlHeader {
    fn from(ident: u8) -> Self {
        if ident & 0b1111 >= MtMACControlHeader::Reserved as u8 {
            MtMACControlHeader::Reserved
        } else {
            unsafe { core::mem::transmute::<u8, Self>(ident) }
        }
    }
}
