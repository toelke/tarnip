use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::arp::ArpStack;
use crate::ip4::IP4Stack;
use crate::udp::UdpStack;
use crate::driver::Driver;
use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct EthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: U16,
}

#[derive(FromPrimitive, Debug)]
enum EtherType {
    IPv4 = 0x0800,
    Arp = 0x0806,
    IPv6 = 0x86dd,
}

#[derive(Debug)]
#[repr(C)]
pub struct EthernetFrame<'a> {
    pub header: &'a EthernetHeader,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    fn from_u8(data: &'a [u8]) -> Result<Self, String> {
        let Ok((header, payload)) = EthernetHeader::ref_from_prefix(data) else {
            return Err("Failed to parse EthernetHeader".to_string());
        };
        Ok(Self { header, payload })
    }
}

pub struct EthernetStack<'a> {
    driver: Rc<RefCell<&'a mut dyn Driver>>,
    arp: ArpStack,
    ip4: IP4Stack<'a>,
}

impl<'a> EthernetStack<'a> {
    pub fn new(driver: Rc<RefCell<&'a mut dyn Driver>>, udp_stack: &'a mut UdpStack) -> Self {
        Self {
            driver: driver.clone(),
            arp: ArpStack::new(),
            ip4: IP4Stack::new(udp_stack),
        }
    }

    pub fn ethernet_input(&self, data: &[u8]) {
        let Ok(frame) = EthernetFrame::from_u8(data) else {
            warn!("Failed to parse EthernetFrame");
            return;
        };
        match frame.header.destination {
            [0xaa, 0, 0, 0, 0, 1] => {}
            [51, 51, 255, 0, 18, 52] => {}
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] => {}
            _ => {
                return;
            }
        }
        let reply = match FromPrimitive::from_u16(frame.header.ether_type.get()) {
            Some(EtherType::IPv4) => self.ip4.ip4_input(&frame),
            Some(EtherType::Arp) => self.arp.arp_input(&frame),
            _ => {
                warn!("Unknown ethertype {:04x}", frame.header.ether_type);
                None
            }
        };
        if let Some(reply) = reply {
            let mut eth_reply = Vec::<u8>::new();
            eth_reply.extend_from_slice(
                EthernetHeader {
                    destination: frame.header.source,
                    source: [0xaa, 0, 0, 0, 0, 1],
                    ether_type: frame.header.ether_type,
                }
                .as_bytes(),
            );
            eth_reply.extend_from_slice(&reply);
            self.driver.borrow_mut().sendpacket(&eth_reply);
        }
    }
}
