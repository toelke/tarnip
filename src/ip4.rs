use crate::pcap_driver::PcapDriver;
use crate::ethernet::EthernetFrame;
use crate::ethernet::EthernetHeader;
use std::cell::RefCell;
use std::rc::Rc;
use log::*;
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

#[derive(Debug)]
#[repr(C)]
enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

#[derive(Debug, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
struct ICMPPacket {
    header: EthernetHeader,
    ip5_header: IP4Header,
    icmp_header: ICMPHeader,
}

pub struct IP4Stack<'a> {
    driver: Rc<RefCell<&'a mut PcapDriver>>,
}

impl<'a> IP4Stack<'a> {
    pub fn new(driver: Rc<RefCell<&'a mut PcapDriver>>) -> Self {
        Self { driver }
    }

    fn icmp_input(&self, header: &IP4Header, payload: &[u8]) {
        let (icmp_header, payload) = ICMPHeader::ref_from_prefix(&payload).unwrap();
    }

    pub fn ip4_input(&self, frame: &EthernetFrame) {
        let (header, payload) = IP4Header::ref_from_prefix(&frame.payload).unwrap();
        if header.version_ihl & 0xf != 5 {
            return;
        }
        match header.protocol {
            1 => self.icmp_input(header, payload),
            _ => { warn!("Unimplemented protocol {}", header.protocol) }
        }
    }
}

