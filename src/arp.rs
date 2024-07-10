use crate::ethernet::EthernetFrame;
use crate::ethernet::EthernetHeader;
use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

#[derive(Debug, FromPrimitive)]
#[repr(u16)]
enum Opcode {
    Request = 1,
    Reply = 2,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
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

fn handle_request(payload: &ArpPayload) {
    match payload.target_ip {
        [192, 168, 3, 150] => {
            let arp_reply = ArpPayload {
                hardware_type: payload.hardware_type,
                protocol_type: payload.protocol_type,
                hardware_size: payload.hardware_size,
                protocol_size: payload.protocol_size,
                opcode: U16::new(Opcode::Reply as u16),
                sender_mac: [0xaa, 0, 0, 0, 0, 1],
                sender_ip: [192, 168, 3, 150],
                target_mac: payload.sender_mac,
                target_ip: payload.sender_ip,
            };
            let ethernet_reply = EthernetFrame {
                header: &EthernetHeader {
                    destination: payload.sender_mac,
                    source: [0xaa, 0, 0, 0, 0, 1],
                    ether_type: U16::new(0x0806),
                },
                payload: arp_reply.as_bytes(),
            };
            info!("Would send reply {:?}", ethernet_reply);
        }
        _ => {}
    }
}

pub fn arp_input(frame: &EthernetFrame) {
    let (payload, _) = ArpPayload::ref_from_prefix(frame.payload)
        .map_err(|_| {
            warn!(
                "ARP payload too or too long: {} {:?}",
                frame.payload.len(),
                frame.payload
            );
        })
        .unwrap();
    match FromPrimitive::from_u16(payload.opcode.get()) {
        Some(Opcode::Request) => handle_request(payload),
        Some(Opcode::Reply) => info!("ARP Reply"),
        None => info!("ARP Unknown"),
    }
}
