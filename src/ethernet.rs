use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;

use crate::ip4::ip4_input;

#[derive(Debug, FromBytes, Immutable)]
#[repr(C)]
struct EthernetHeader {
    destination: [u8; 6],
    source: [u8; 6],
    ether_type: U16,
}

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    header: &'a EthernetHeader,
    payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    fn from_u8(data: &'a [u8]) -> Self {
        let ([header], payload) = <[EthernetHeader]>::ref_from_prefix_with_elems(data, 1).unwrap() else {
            todo!() // this cannot happen, the element-count 1 ensures it
        };
        Self { header, payload }
    }
}

pub fn ethernet_input(data: &[u8]) -> () {
    let frame = EthernetFrame::from_u8(data);
    match frame.header.ether_type.get() {
        0x0800 => ip4_input(&frame),
        _ => {
            println!("Unknown ethertype {:04x}", frame.header.ether_type);
        }
    }
}
