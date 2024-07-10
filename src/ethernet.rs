use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;

use crate::arp::arp_input;
use crate::ip4::ip4_input;
use log::*;

#[derive(Debug, FromBytes, Immutable)]
#[repr(C)]
pub struct EthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: U16,
}

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub header: &'a EthernetHeader,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    fn from_u8(data: &'a [u8]) -> Self {
        let ([header], payload) = <[EthernetHeader]>::ref_from_prefix_with_elems(data, 1).unwrap() else {
            todo!() // this cannot happen, the element-count 1 ensures it
        };
        Self { header, payload }
    }
}

pub fn ethernet_input(data: &[u8]) {
    let frame = EthernetFrame::from_u8(data);
    match frame.header.destination {
        [0xaa, 0, 0, 0, 0, 1] => {}
        [51, 51, 255, 0, 18, 52] => {}
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] => {}
        _ => {
            return;
        }
    }
    match frame.header.ether_type.get() {
        0x0800 => ip4_input(&frame),
        0x0806 => arp_input(&frame),
        _ => {
            warn!("Unknown ethertype {:04x}", frame.header.ether_type);
        }
    }
}
