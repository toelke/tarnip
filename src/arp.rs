use crate::ethernet::EthernetFrame;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::KnownLayout;
use zerocopy::byteorder::network_endian::U16;
use log::*;

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ArpPayload {
    hardware_type: U16,
    protocol_type: U16,
    hardware_size: u8,
    protocol_size: u8,
    opcode: U16,
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
}

pub fn arp_input(frame: &EthernetFrame) {
    let payload = ArpPayload::ref_from_bytes(frame.payload).unwrap();
    info!("ARP {:?}", payload);
}
