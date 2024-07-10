use crate::ethernet::EthernetStack;
use log::*;
use pcap::Active;
use pcap::Capture;
use pcap::Device;
use std::cell::RefCell;
use std::rc::Rc;

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
    cap: Rc<RefCell<Capture<Active>>>,
}

impl PcapDriver {
    pub fn new(interface: String) -> Self {
        let device = get_device(interface).unwrap();
        let cap = Rc::new(RefCell::new(
            Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .immediate_mode(true)
                .open()
                .unwrap(),
        ));
        Self { cap }
    }

    pub fn run(&mut self) {
        let me = Rc::new(RefCell::new(self));
        let ethernet_stack = EthernetStack::new(me.clone());
        loop {
            let packet = {
                let me = me.borrow();
                let mut cap = me.cap.borrow_mut();
                cap.next_packet().unwrap().data[..].to_vec()
            };

            ethernet_stack.ethernet_input(&packet);
        }
    }

    pub fn sendpacket(&mut self, packet: &[u8]) {
        self.cap.borrow_mut().sendpacket(packet).unwrap();
    }
}
