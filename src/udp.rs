use std::collections::HashMap;
use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

pub trait Listener {
    fn on_packet(&self, data: &[u8]) -> Option<Vec<u8>>;
}

pub struct UdpStack {
    listeners: HashMap<u16, Box<dyn Listener>>,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
struct UDPHeader {
    src_port: U16,
    dst_port: U16,
    len: U16,
    checksum: U16,
}

impl UDPHeader {
    fn calc_checksum(&self, _payload: &[u8]) -> U16 {
        // needs pseudo ip header, but it's optional for ip4
        U16::new(0)
    }
}

impl UdpStack {
    pub fn new() -> Self {
        Self {
            listeners: HashMap::new(),
        }
    }

    pub fn udp_input(&self, data: &[u8]) -> Option<Vec<u8>> {
        let Ok((udp_header, payload)) = UDPHeader::ref_from_prefix(data) else {
            return None;
        };

        if let Some(listener) = self.listeners.get(&udp_header.dst_port.get()) {
            if let Some(reply_payload) = listener.on_packet(&payload[..udp_header.len.get() as usize - 8]) {
                let mut reply = Vec::<u8>::new();
                let mut udpheader = UDPHeader {
                    src_port: udp_header.dst_port,
                    dst_port: udp_header.src_port,
                    len: U16::new(8 + reply_payload.len() as u16),
                    checksum: U16::new(0),
                };
                udpheader.checksum = udpheader.calc_checksum(reply_payload.as_slice());
                reply.extend_from_slice(udpheader.as_bytes());
                reply.extend_from_slice(reply_payload.as_slice());
                return Some(reply);
            }
        }
        None
    }

    pub fn add_listener(&mut self, port: u16, listener: Box<dyn Listener>) {
        self.listeners.insert(port, listener);
    }
}
