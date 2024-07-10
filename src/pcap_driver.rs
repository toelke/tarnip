use crate::ethernet::ethernet_input;
use log::*;
use pcap::Active;
use pcap::Capture;
use pcap::Device;

fn get_device(interface: String) -> Option<Device> {
    for device in Device::list().unwrap() {
        info!("device {:?}", device);
        if device.name == interface {
            return Some(device);
        }
    }
    None
}

pub struct PcapDriver {
    cap: Capture<Active>,
}

impl PcapDriver {
    pub fn new(interface: String) -> Self {
        let device = get_device(interface).unwrap();
        let cap = Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .immediate_mode(true)
            .open()
            .unwrap();
        Self { cap }
    }

    pub fn run(&mut self) {
        while let Ok(packet) = self.cap.next_packet() {
            ethernet_input(&packet);
        }
    }
}
