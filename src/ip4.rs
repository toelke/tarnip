use crate::ethernet::EthernetFrame;
use crate::ethernet::EthernetHeader;
use crate::pcap_driver::PcapDriver;
use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::cell::RefCell;
use std::rc::Rc;
use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

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

#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
struct ICMPHeader {
    icmp_type: u8,
    icmp_code: u8,
    checksum: U16,
}

#[derive(Debug, FromPrimitive)]
#[repr(u8)]
enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

pub struct IP4Stack<'a> {
    driver: Rc<RefCell<&'a mut PcapDriver>>,
}

impl<'a> IP4Stack<'a> {
    pub fn new(driver: Rc<RefCell<&'a mut PcapDriver>>) -> Self {
        Self { driver }
    }

    fn icmp_input(&self, eth_header: &EthernetHeader, ip_header: &IP4Header, payload: &[u8]) {
        let (icmp_header, payload) = ICMPHeader::ref_from_prefix(&payload).unwrap();
        match icmp_header.icmp_type {
            8 => {
                let mut reply = Vec::<u8>::new();
                reply.extend_from_slice(
                    EthernetHeader {
                        destination: eth_header.source,
                        source: eth_header.destination,
                        ether_type: eth_header.ether_type,
                    }
                    .as_bytes(),
                );
                let mut ip4header = IP4Header {
                    version_ihl: 0x45,
                    dscp_ecn: 0,
                    total_length: U16::new(20 + 4 + payload.len() as u16),
                    identification: U16::new(0),
                    flags_fragment_offset: U16::new(0),
                    ttl: 64,
                    protocol: 1,
                    checksum: U16::new(0),
                    source_ip: ip_header.destination_ip,
                    destination_ip: ip_header.source_ip,
                };
                reply.extend_from_slice(ip4header.as_bytes());
                reply.extend_from_slice(
                    ICMPHeader {
                        icmp_type: 0,
                        icmp_code: 0,
                        checksum: U16::new(0),
                    }
                    .as_bytes(),
                );
                reply.extend_from_slice(payload);
                self.driver.borrow_mut().sendpacket(&reply);
            }
            _ => {}
        }
    }

    pub fn ip4_input(&self, frame: &EthernetFrame) {
        let (header, payload) = IP4Header::ref_from_prefix(&frame.payload).unwrap();
        if header.version_ihl & 0xf != 5 {
            return;
        }
        match FromPrimitive::from_u8(header.protocol) {
            Some(Protocol::ICMP) => self.icmp_input(frame.header, header, payload),
            _ => {
                warn!("Unimplemented protocol {}", header.protocol)
            }
        }
    }
}
