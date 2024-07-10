use crate::ethernet::EthernetFrame;
use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::icmp4::icmp_input;

#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
struct IP4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: U16,
    identification: U16,
    flags_fragment_offset: U16,
    ttl: u8,
    protocol: u8,
    checksum: U16,
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
}

impl IP4Header {
    fn calc_checksum(&self) -> U16 {
        let mut sum = 0u32;
        sum += u32::from(self.version_ihl) << 8 | u32::from(self.dscp_ecn);
        sum += u32::from(self.total_length.get());
        sum += u32::from(self.identification.get());
        sum += u32::from(self.flags_fragment_offset.get());
        sum += (u32::from(self.ttl)) << 8 | u32::from(self.protocol);
        sum += u32::from(self.source_ip[0]) << 8 | u32::from(self.source_ip[1]);
        sum += u32::from(self.source_ip[2]) << 8 | u32::from(self.source_ip[3]);
        sum += u32::from(self.destination_ip[0]) << 8 | u32::from(self.destination_ip[1]);
        sum += u32::from(self.destination_ip[2]) << 8 | u32::from(self.destination_ip[3]);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        U16::new(!sum as u16)
    }
}

#[derive(Debug, FromPrimitive)]
#[repr(u8)]
enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

pub struct IP4Stack {}

impl IP4Stack {
    pub fn new() -> Self {
        Self {}
    }

    pub fn ip4_input(&self, frame: &EthernetFrame) -> Option<Vec<u8>> {
        let (ip4_header, payload) = IP4Header::ref_from_prefix(frame.payload).unwrap();
        if ip4_header.version_ihl & 0xf != 5 {
            return None;
        }
        let reply = match FromPrimitive::from_u8(ip4_header.protocol) {
            Some(Protocol::Icmp) => icmp_input(payload),
            _ => {
                warn!("Unimplemented protocol {}", ip4_header.protocol);
                None
            }
        };
        if let Some(reply) = reply {
            let mut ip4_reply = Vec::<u8>::new();
            let mut ip4_reply_header = IP4Header {
                version_ihl: 0x45,
                dscp_ecn: 0,
                total_length: U16::new(20 + reply.len() as u16),
                identification: U16::new(0),
                flags_fragment_offset: U16::new(0),
                ttl: 64,
                protocol: 1,
                checksum: U16::new(0),
                source_ip: ip4_header.destination_ip,
                destination_ip: ip4_header.source_ip,
            };
            ip4_reply_header.checksum = ip4_reply_header.calc_checksum();
            ip4_reply.extend_from_slice(ip4_reply_header.as_bytes());
            ip4_reply.extend_from_slice(&reply);
            return Some(ip4_reply);
        }
        None
    }
}
