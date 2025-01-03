use std::{
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
};

use anyhow::Result;

use bitvec::{order::Msb0, vec::BitVec, view::AsBits};
use tokio::net::UdpSocket;

const FP_SYNC: u32 = 0xAAE98A;
const PP_SYNC: u32 = 0x551675;
const GP: u16 = 0x0589;

trait Rcrc {
    fn crc(&self) -> u16;
}

impl Rcrc for [u8; 8] {
    fn crc(&self) -> u16 {
        let mut crc = ((self[0] as u16) << 8) | (self[1] as u16);
        let mut next = 0;
        let mut y = 0;
        let mut x = 0;

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

#[derive(Debug)]
enum Packet {
    Header {
        rxmode: u8,
        channel: u8,
        slot: u16,
        frameno: u8,
        rssi: u8,
        preamble: [u8; 3],
        sync: u16,
    },
    A {
        header: u8,
        tail: [u8; 5],
        crc: u16,
        b: Option<BitVec<u8, Msb0>>,
    },
}

/// Rolling bit iterator that yields the last 8 bytes.
#[derive(Debug, Clone)]
struct BitIterator {
    inner: Vec<u8>,
    bit: u8,
    index: usize,
}

impl BitIterator {
    fn new(inner: impl AsRef<[u8]>) -> Self {
        Self {
            inner: inner.as_ref().to_vec(),
            bit: 7,
            index: 0,
        }
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

#[derive(Debug, Copy, Clone)]
enum Dect {
    Header,
    Payload,
}

const DUMMY_DATA: &[u8] = &[
    59, 41, 164, 181, 19, 51, 75, 178, 75, 106, 139, 40, 178, 139, 76, 166, 139, 9, 182, 122, 102,
    76, 177, 38, 236, 167, 154, 38, 204, 97, 136, 196, 105, 172, 201, 181, 82, 85, 44, 172, 51, 53,
    180, 205, 109, 181, 218, 43, 141, 157, 141, 41, 37, 178, 137, 54, 39, 170, 158, 111, 111, 20,
    108, 88, 0, 219, 138, 170, 163, 230, 42, 179, 32, 1, 34, 82, 146, 215, 132, 76, 112, 242, 214,
    25, 114, 80, 35, 204, 170, 194, 113, 37, 55, 66, 205, 205, 20, 179, 62, 99, 5, 57, 173, 139,
    60, 199, 97, 56, 230, 83, 20, 168, 253, 165, 180, 81, 147, 137, 90, 246, 84, 207, 89, 226, 72,
    198, 148, 204, 204, 42, 234, 197, 147, 21, 205, 136, 233, 166, 107, 66, 75, 109, 147, 57, 44,
    187, 40, 178, 59, 79, 110, 150, 72, 107, 50, 172, 171, 61, 163, 173, 9, 211, 89, 144, 217, 185,
    200, 236, 54, 109, 203, 23, 48, 169, 39, 97, 84, 204, 185, 209, 172, 213, 89, 235, 106, 29,
    121, 107, 37, 61, 18, 245, 106, 118, 100, 85, 170, 55, 96, 168, 105, 76, 172, 171, 60, 37, 74,
    153, 206, 107, 157, 72, 152, 237, 150, 194, 148, 171, 72, 169, 32, 43, 154, 169, 18, 49, 108,
    106, 150, 155, 34, 211, 94, 206, 22, 204, 242, 231, 12, 142, 101, 48, 137, 75, 117, 228, 173,
    99, 237, 57, 92, 122, 206, 177, 170, 116, 87, 69, 205, 83, 142, 197, 181, 201, 85, 100, 133,
    21, 52, 69, 142, 76, 41, 94, 69, 162, 229, 52, 157, 49, 43, 44, 146, 91, 107, 74, 214, 77, 139,
    74, 233, 150, 141, 134, 214, 57, 169, 148, 217, 203, 23, 46, 114, 142, 74, 71, 26, 105, 154,
    75, 87, 56, 234, 162, 162, 133, 76, 167, 40, 201, 106, 241, 204, 217, 202, 141, 108, 217, 193,
    205, 145, 185, 17, 210, 212, 118, 152, 108, 169, 35, 74, 200, 203, 76, 153, 81, 76, 214, 60,
    234, 141, 45, 100, 104, 82, 21, 45, 105, 89, 22, 21, 88, 213, 154, 42, 98, 176, 198, 210, 105,
    195, 85, 56, 163, 142, 77, 36, 152, 248, 187, 158, 213, 218, 140, 218, 113, 19, 97, 41, 167, 4,
    74, 64, 74, 180, 106, 177, 108, 206, 217, 213, 46, 186, 13, 153, 179, 52, 228, 148, 204, 229,
    98, 30, 178, 196, 157, 14, 132, 85, 205, 178, 87, 20, 212, 151, 47, 46, 50, 106, 85, 51, 46,
    84, 186, 170, 103, 244, 193, 197, 75, 86, 148, 188, 40, 245, 184, 225, 226, 117, 152, 141, 178,
    71, 4, 194, 149, 104, 241, 6, 140, 178, 57, 173, 181, 205, 30, 217, 132, 172, 55, 111, 237,
    149, 157, 178, 124, 76, 110, 213, 217, 72, 89, 150, 70, 195, 99, 174, 142, 22, 177, 119, 37,
    229, 228, 236, 164, 137, 204, 148, 205, 84, 199, 85, 115, 45, 136, 179, 26, 104, 178, 170, 24,
    147, 91, 106, 153, 142, 39, 28, 108, 68, 212, 154, 136, 147, 100, 107, 42, 53, 102, 153, 147,
    89, 67, 167, 88, 238, 93, 39, 172, 89, 21, 165, 57, 140, 154, 203, 151, 73, 156, 242, 18, 111,
    55, 71, 115, 87, 5, 138, 202, 133, 171, 50, 57, 52, 211, 115, 156, 228, 155, 45, 85, 108, 100,
    142, 141, 95, 86, 153, 162, 179, 98, 160, 98, 108, 203, 38, 41, 98, 30, 106, 108, 173, 218, 46,
    59, 146, 107, 59, 195, 41, 215, 41, 169, 51, 206, 179, 43, 39, 107, 21, 219, 145, 175, 134,
    112, 151, 27, 78, 178, 186, 95, 85, 85, 85, 93, 49, 76, 34, 5, 94, 37, 129, 167, 154, 190, 38,
    137, 181, 165, 227, 38, 94, 210, 136, 242, 52, 162, 1, 211, 67, 105, 172, 47, 22, 143, 150, 56,
    216, 106, 172, 63, 126, 187, 244, 79, 131, 84, 29, 31, 133, 52, 136, 62, 142, 255, 231, 34,
    169, 140, 213, 74, 49, 83, 170, 167, 154, 243, 178, 207, 28, 57, 99, 89, 211, 53, 177, 233, 57,
    245, 195, 163, 204, 221, 143, 54, 150, 112, 198, 107, 61, 47, 115, 5, 22, 181, 211, 187, 51,
    55, 89, 202, 153, 28, 78, 139, 50, 93, 232, 217, 27, 20, 211, 51, 93, 42, 237, 77, 182, 18,
    135, 155, 130, 148, 117, 99, 19, 218, 171, 162, 204, 230, 228, 228, 102, 217, 197, 117, 49,
    119, 122, 85, 214, 14, 186, 152, 207, 29, 78, 22, 75, 99, 35, 22, 41, 219, 86, 164, 49, 174,
    177, 178, 180, 89, 163, 107, 50, 211, 31, 25, 205, 49, 216, 88, 114, 221, 75, 52, 183, 86, 142,
    113, 155, 106, 174, 250, 236, 173, 100, 247, 228, 138, 84, 50, 218, 138, 101, 72, 173, 118, 87,
    46, 57, 194, 188, 148, 231, 151, 151, 36, 186, 201, 188, 154, 156, 177, 154, 153, 107, 78, 178,
    213, 151, 70, 103, 110, 226, 76, 205, 109, 108, 244, 150, 210, 93, 187, 171, 152, 183, 157, 99,
    94, 182, 220, 216, 204, 109, 13, 199, 52, 227, 136, 156, 42, 183, 27, 179, 206, 205, 194, 195,
    76, 106, 94, 234, 87, 213, 109, 177, 170, 136, 113, 137, 148, 102, 169, 145, 101, 108, 200,
    149, 151, 94, 22, 114, 241, 184, 150, 98, 55, 54, 107, 70, 178, 121, 171, 205, 204, 244, 189,
    220, 214, 168, 187, 153, 202, 75, 43, 54, 198, 202, 230, 138, 181, 198, 136, 149, 78, 212, 86,
    200, 217, 197, 78, 57, 194, 165, 46, 139, 11, 82, 235, 101, 207, 25, 205, 141, 149, 38, 165,
    88, 154, 146, 50, 133, 81, 108, 202, 236, 184, 220, 164, 77, 233, 57, 171, 74, 15, 184, 231,
    84, 51, 199, 87, 101, 89, 28, 98, 86, 102, 161, 37, 235, 234, 191, 68, 236, 173, 224, 195, 2,
    162, 185, 237, 175, 101, 155, 157, 150, 154, 230, 168, 156, 202, 60, 249, 43, 51, 37, 20, 75,
    172, 243, 36, 238, 106, 170, 115, 157, 54, 181, 167, 28, 248, 147, 73, 69, 164, 141, 107, 44,
    26, 188, 187, 84, 109, 173, 157, 74, 50, 118, 119, 187, 101, 171, 165, 149, 204, 173, 197, 226,
    73, 138, 106, 58, 50, 201, 109, 4, 181, 82, 92, 103, 67, 19, 213, 68, 145, 177, 145, 157, 198,
    84, 201, 27, 3, 24, 39, 113, 228, 202, 229, 150, 38, 167, 57, 106, 137, 97, 163, 198, 204, 230,
    154, 105, 28, 141, 178, 98, 180, 213, 88, 101, 214, 69, 139, 178, 138, 141, 227, 73, 21, 114,
    42, 121, 174, 119, 81, 204, 235, 113, 101, 193, 43, 79, 41, 174, 119, 61, 172, 189, 166, 18,
    109, 43, 90, 51, 98, 105, 77, 109, 33, 80, 202, 102, 236, 114, 153, 101, 154, 19, 42, 116, 211,
    161, 186, 76, 230, 111, 45, 68, 199, 66, 116, 250, 142, 108, 188, 204, 76, 101, 225, 40, 229,
    149, 86, 111, 106, 202, 150, 46, 156, 120, 74, 150, 179, 77, 162, 206, 156, 235, 111, 70, 107,
    73, 193, 37, 105, 221, 94, 18, 42, 116, 149, 141, 133, 19, 176, 229, 187, 148, 213, 22, 103,
    25, 88, 117, 147, 74, 228, 214, 23, 102, 149, 91, 50, 170, 29, 108, 172, 235, 153, 78, 102, 78,
    74, 25, 85, 100, 185, 210, 177, 122, 178, 99, 154, 221, 236, 121, 166, 41, 45, 187, 68, 206,
    74, 52, 194, 170, 25, 69, 141, 76, 85, 145, 60, 167, 23, 204, 231, 34, 74, 237, 150, 230, 76,
    228, 235, 61, 109, 172, 166, 89, 90, 119, 123, 107, 26, 217, 109, 42, 77, 147, 170, 108, 97,
    235, 154, 162, 141, 73, 51, 220, 102, 44, 188, 68, 206, 3, 42, 55, 98, 106, 78, 73, 81, 181,
    90, 141, 202, 212, 152, 208, 220, 45, 201, 72, 168, 167, 109, 203, 117, 85, 69, 85, 85, 27,
    173, 84, 165, 150, 108, 246, 202, 171, 53, 78, 154, 101, 156, 169, 171, 157, 167, 145, 72, 141,
    104, 231, 18, 153, 218, 115, 70, 197, 142, 165, 53, 156, 71, 28, 153, 56, 153, 75, 145, 91, 45,
    90, 97, 227, 78, 76, 201, 19, 9, 57, 90, 155, 21, 37, 40, 238, 180, 173, 241, 83, 42, 185, 165,
    215, 106, 91, 86, 182, 115, 94, 115, 135, 124, 157, 199, 39, 26, 86, 228, 252, 204, 203, 154,
    177, 136, 165, 143, 109, 148, 179, 242, 201, 107, 58, 113, 163, 29, 45, 25, 86, 84, 179, 93,
    44, 243, 231, 149, 162, 213, 141, 86, 183, 44, 217, 115, 26, 106, 103, 58, 103, 94, 115, 42,
    181, 214,
];

#[derive(Debug, Clone)]
enum ChannelState {
    Header,
    Payload,
    PayloadB { bytes: [u8; 8] },
}

#[derive(Debug)]
struct Decoder {
    bits: BitIterator,
    state: ChannelState,
}

impl Decoder {
    pub async fn parse(&mut self) -> Result<Option<Packet>> {
        match self.state {
            ChannelState::Header => {
                let sync = self.bits.find(|n| {
                    (*n & 0xffffff) as u32 == FP_SYNC || (*n & 0xffffff) as u32 == PP_SYNC
                });

                let sync = match sync {
                    Some(index) => index,
                    None => return Ok(None),
                };
                println!("sync: {:016X}", sync);
                self.state = ChannelState::Payload;
                Ok(Some(Packet::Header {
                    rxmode: 0,
                    channel: 0,
                    slot: 0,
                    frameno: 0,
                    rssi: 0,
                    preamble: [
                        (sync >> 40 & 0xff) as u8,
                        (sync >> 32 & 0xff) as u8,
                        (sync >> 24 & 0xff) as u8,
                    ],
                    sync: (sync as u16).to_be(),
                }))
            }
            ChannelState::PayloadB { bytes } => {
                let header = bytes[7];
                let ba = (header >> 1) & 7;

                let blen = match ba {
                    4 => 10,
                    2 => 100,
                    7 => 0,
                    _ => 40,
                };
                if let Some(b) = self.bits.peek_bits(blen + 1) {
                    self.bits.nth(blen);
                    self.state = ChannelState::Header;
                    Ok(Some(Packet::A {
                        header,
                        tail: [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]],
                        crc: (bytes[0] as u16) << 8 | bytes[1] as u16,
                        b: Some(b),
                    }))
                } else {
                    // We need more data
                    Ok(None)
                }
            }
            ChannelState::Payload => {
                let data = match self.bits.nth(63) {
                    Some(data) => data,
                    None => return Ok(None),
                };

                let bytes = data.to_be_bytes();

                let crc = bytes.crc();
                if crc != 0 {
                    self.state = ChannelState::Header;
                    return Ok(None);
                }

                let header = bytes[7];

                let ba = (header >> 1) & 7;

                let blen = match ba {
                    4 => 10,
                    2 => 100,
                    7 => 0,
                    _ => 40,
                };

                if blen > 0 {
                    self.state = ChannelState::PayloadB { bytes };
                    if let Some(b) = self.bits.peek_bits(blen + 1) {
                        self.bits.nth(blen);
                        Ok(Some(Packet::A {
                            header,
                            tail: [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]],
                            crc: (bytes[0] as u16) << 8 | bytes[1] as u16,
                            b: Some(b),
                        }))
                    } else {
                        // We need more data
                        return Ok(None);
                    }
                } else {
                    self.state = ChannelState::Header;
                    Ok(Some(Packet::A {
                        header,
                        tail: [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]],
                        crc: (bytes[0] as u16) << 8 | bytes[1] as u16,
                        b: None,
                    }))
                }
            }
        }
    }
}

impl Extend<u8> for Decoder {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.bits.extend(iter);
    }
}

#[derive(Debug)]
struct Channel {
    socket: UdpSocket,

    decoder: Decoder,
}

impl Channel {
    pub async fn new(port: u16, index: usize) -> Result<Self> {
        let addr = Ipv4Addr::new(0, 0, 0, 0);
        let addr = SocketAddrV4::new(addr, port);

        let socket = UdpSocket::bind(addr).await?;

        let bits = BitIterator::new([]);
        Ok(Self {
            socket,

            decoder: Decoder {
                bits,
                state: ChannelState::Header,
            },
        })
    }

    pub async fn recv(&mut self) -> Result<()> {
        let mut buf = [0u8; 2048];
        let size = self.socket.recv(&mut buf).await?;
        if size > 0 {
            self.decoder.extend(buf[..size].iter().copied());
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    //let mut channel = Channel::new(2323).await?;

    let mut channel = Channel::new(2323, 0).await?;
    channel.recv().await?;

    while let Ok(packet) = channel.decoder.parse().await {
        match packet {
            Some(packet) => println!("{:?}", packet),
            None => {
                channel.recv().await?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {

    use crate::{BitIterator, ChannelState, Decoder, DUMMY_DATA};

    #[test]
    fn test_bit_iterator() {
        let iter = super::BitIterator::new(super::DUMMY_DATA);

        assert!(iter
            .map(|n| (n & 0xffffff) as u32)
            .any(|n| n == super::FP_SYNC || n == super::PP_SYNC));
    }

    #[tokio::test]
    async fn test_decoder() {
        let mut decoder = Decoder {
            bits: BitIterator::new(DUMMY_DATA),
            state: ChannelState::Header,
        };
        decoder.extend(DUMMY_DATA.iter().copied());
        let packet = decoder.parse().await.unwrap();
        println!("{:?}", packet);
    }
}
