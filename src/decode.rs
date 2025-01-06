use crate::capture::DataSource;
use crate::capture::FileChannel;
use crate::dect::L2MACPacket;
use crate::dect::MacBody;
use crate::dect::MtAdvConnectionControlCommand;
use crate::dect::MtBasicConnectionControl;
use crate::dect::MtBasicConnectionControlCommand;
use crate::dect::MtFirstPPTransmission;
use crate::dect::MtMACControlHeader;
use crate::dect::MtMacControl;
use crate::dect::MtQualityControl;
use crate::dect::Rcrc;
use crate::dect::TailIdentification;

use anyhow::Result;
use bitvec::field::BitField;
use bitvec::{order::Msb0, vec::BitVec, view::AsBits};
use std::{io::Read, path::PathBuf};

use crate::dect::{BFieldIdentification, MACHeader, TailIdentificationPP, FP_SYNC, PP_SYNC};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Input file to decode.
    #[clap(short, long)]
    input: PathBuf,
}

/// Rolling bit iterator that yields the last 8 bytes.
#[derive(Debug, Clone)]
pub struct BitIterator {
    inner: Vec<u8>,
    bit: u8,
    index: usize,
}

impl BitIterator {
    pub fn new(inner: impl AsRef<[u8]>) -> Self {
        Self {
            inner: inner.as_ref().to_vec(),
            bit: 7,
            index: 0,
        }
    }

    pub fn len(&self) -> usize {
        // TODO: is this correct?
        self.inner[self.index..].len() + self.bit as usize
    }
}

impl Extend<u8> for BitIterator {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.inner.extend(iter);
    }
}

impl BitIterator {
    pub fn peek_bits(&mut self, n: usize) -> Option<BitVec<u8, Msb0>> {
        let start = self.index * 8 + self.bit as usize;

        let bits = &self.inner.as_bits::<Msb0>()[start..];
        if bits.len() < n {
            return None;
        }

        Some(bits[..n].to_bitvec())
    }

    pub fn advance(&mut self, bits: usize) {
        let n = (bits / 8) + self.bit as usize;

        self.index += n / 8;
        self.bit = (n % 8) as u8;
    }
}

impl Iterator for BitIterator {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.index * 8 + self.bit as usize;

        if self.inner.as_bits::<Msb0>()[start..].len() < 64 {
            return None;
        }

        let mut current = &self.inner.as_bits::<Msb0>()[start..start + 64];
        let mut number = [0u8; 8];
        current.read_exact(&mut number).ok()?;
        let number = u64::from_be_bytes(number);

        if self.bit == 0 {
            self.bit = 7;
            self.index += 1;
        } else {
            self.bit -= 1;
        }

        Some(number)
    }
}

#[derive(Debug)]
pub struct Decoder {
    pub bits: BitIterator,
    pub state: ChannelState,
}

#[derive(Debug, Clone, Copy)]
pub enum ChannelState {
    NewMessage,
    AField {
        sync: Sync,
    },
    BField {
        sync: Sync,
        header: MACHeader,
        tail: [u8; 5],
        length: usize,
    },
}

#[derive(Debug, Copy, Clone)]
pub enum Sync {
    Fp,
    Pp,
}

#[derive(Clone, Debug)]
pub enum DecoderState {
    MoreData,
    Partial,
    Full(L2MACPacket),
}

impl Decoder {
    pub async fn parse(&mut self) -> Result<DecoderState> {
        match self.state {
            ChannelState::NewMessage => {
                // Do we have enough data to parse?
                if self.bits.len() < 64 {
                    return Ok(DecoderState::MoreData);
                }

                let sync = self
                    .bits
                    .find(|n| {
                        (*n & 0xffffff) as u32 == FP_SYNC || (*n & 0xffffff) as u32 == PP_SYNC
                    })
                    .map(|n| (n & 0xFFFFFF) as u32);

                match sync {
                    None => return Ok(DecoderState::MoreData),
                    Some(FP_SYNC) => {
                        self.state = ChannelState::AField { sync: Sync::Fp };
                    }
                    Some(PP_SYNC) => {
                        self.state = ChannelState::AField { sync: Sync::Pp };
                    }
                    Some(_) => unreachable!(),
                }

                Ok(DecoderState::Partial)
            }
            ChannelState::AField { sync } => {
                // Do we have enough data to parse?
                if self.bits.len() < 64 {
                    return Ok(DecoderState::MoreData);
                }
                // parse out header
                let data = match self.bits.nth(63) {
                    Some(data) => data,
                    None => return Ok(DecoderState::MoreData),
                };
                let bytes = data.to_be_bytes();

                if bytes.crc() != 0 {
                    self.state = ChannelState::NewMessage;
                    return Ok(DecoderState::Partial);
                }

                let header = bytes[7];
                let tail = [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]];

                let tail_ident = TailIdentification::Pp(TailIdentificationPP::from(header >> 5));
                let b_field_ident = BFieldIdentification::from((header >> 1) & 0b111);
                // Length of B field in bits.
                let mut blen = match b_field_ident {
                    BFieldIdentification::DoubleSlotRequired => 100,
                    BFieldIdentification::HalfSlotRequired => 10,
                    BFieldIdentification::NoSlotRequired => 0,
                    _ => 40, // default B field size.
                };

                if blen != 0 {
                    // 4 bits for X-field and 4 bits for Z-field
                    blen += 1;
                }

                let header = MACHeader {
                    tail_ident,
                    q1_bck_bit: (header >> 4) & 1 == 1,
                    b_field_ident,
                    q2_bit: header & 1 == 1,
                };

                self.state = ChannelState::BField {
                    sync,
                    header,
                    tail,
                    length: blen,
                };

                Ok(DecoderState::Partial)
            }
            ChannelState::BField {
                sync: _sync,
                header,
                tail,
                length,
            } => {
                // Do we have enough data to parse?
                if self.bits.len() < length {
                    return Ok(DecoderState::MoreData);
                }

                let b_field = if length == 0 {
                    None
                } else {
                    let b_field = self
                        .bits
                        .peek_bits(length)
                        .expect("Out of bounds despite check!");
                    self.bits.advance(length);
                    Some(b_field)
                };
                let payload = if let Some(b_field) = &b_field {
                    match &header.tail_ident {
                        TailIdentification::Pp(TailIdentificationPP::MtMACLayerControl) => {
                            let m_t_bits = &b_field[..4];
                            let m_t_header = MtMACControlHeader::from(m_t_bits.load_be::<u8>());

                            match &m_t_header {
                                MtMACControlHeader::QualityControl => {
                                    let command_bits = &b_field[4..8];
                                    let param_1_bits = &b_field[8..16];
                                    let param_2_bits = &b_field[16..24];
                                    let check_bits = &b_field[24..40];

                                    let command = MtQualityControl {
                                        command: command_bits.load_be::<u8>(),
                                        param_1: param_1_bits.load_be::<u8>(),
                                        param_2: param_2_bits.load_be::<u8>(),
                                        check: check_bits.load_be::<u16>(),
                                    };

                                    tracing::info!(
                                        "{:?} {:04b}:{:04b}:{:04b}:{:04b}{:016b}",
                                        m_t_header,
                                        m_t_bits.load_be::<u8>(),
                                        command.command,
                                        command.param_1,
                                        command.param_2,
                                        command.check
                                    );

                                    Some(MacBody::QualityControl(command))
                                }
                                MtMACControlHeader::Escape => {
                                    let bits = b_field[4..40].to_bitvec();

                                    Some(MacBody::Escape(bits))
                                }
                                MtMACControlHeader::AdvConnectionControl => {
                                    let bits = &b_field[4..8];
                                    let header =
                                        MtAdvConnectionControlCommand::from(bits.load_be::<u8>());

                                    tracing::info!(
                                        "{:?} {:04b}:{:04b}",
                                        m_t_header,
                                        m_t_bits.load_be::<u8>(),
                                        bits.load_be::<u8>()
                                    );

                                    None
                                }
                                MtMACControlHeader::BasicConnectionControl => {
                                    let bits = &b_field[4..8];
                                    let header =
                                        MtBasicConnectionControlCommand::from(bits.load_be::<u8>());

                                    tracing::info!(
                                        "{:?} {:04b}:{:04b}",
                                        m_t_header,
                                        m_t_bits.load_be::<u8>(),
                                        bits.load_be::<u8>()
                                    );

                                    match &header {
                                        MtBasicConnectionControlCommand::AccessRequest => {
                                            let fmid_bits = &b_field[8..20];
                                            let pmid_bits = &b_field[20..40];
                                            let first_pp_transmission = MtFirstPPTransmission {
                                                fmid: fmid_bits.load_be::<u16>(),
                                                pmid: pmid_bits.load_be::<u32>(),
                                            };

                                            tracing::info!(
                                                "Access Request: {:08x} => {:08x}",
                                                first_pp_transmission.fmid,
                                                first_pp_transmission.pmid
                                            );

                                            Some(MacBody::MtMacControl(
                                                MtMacControl::BasicConnectionControl(
                                                    MtBasicConnectionControl::AccessRequest(
                                                        first_pp_transmission,
                                                    ),
                                                ),
                                            ))
                                        }
                                        _ => None,
                                    }
                                }
                                _ => None,
                            }
                        }

                        _ => None,
                    }
                } else {
                    None
                };
                self.state = ChannelState::NewMessage;

                Ok(DecoderState::Full(L2MACPacket { header, payload }))
            }
        }
    }
}

impl Extend<u8> for Decoder {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.bits.extend(iter);
    }
}

pub async fn run(args: Args) -> Result<()> {
    let mut data = FileChannel::open(&args.input).await?;

    let mut decoder = Decoder {
        bits: BitIterator::new([]),
        state: ChannelState::NewMessage,
    };

    while let Ok(state) = decoder.parse().await {
        match state {
            DecoderState::MoreData => {
                let buf = data.recv().await?;
                decoder.extend(buf);
            }
            DecoderState::Partial => continue,
            DecoderState::Full(macpacket) => {}
        }
    }

    Ok(())
}
