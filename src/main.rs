use clap::Parser;

use crate::ethernet::EthernetStack;
use crate::udp::Listener;
use crate::udp::UdpStack;
mod arp;
mod driver;
mod ethernet;
mod icmp4;
mod ip4;
mod pcap_driver;
mod udp;
use crate::driver::Driver;
use crate::pcap_driver::PcapDriver;
use log::*;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(short, long, default_value = "eth0")]
    interface: String,
}

struct UdpEcho {}

impl Listener for UdpEcho {
    fn on_packet(&self, data: &[u8]) -> Option<Vec<u8>> {
        info!("UdpEcho::on_packet {:?}", data);
        Some(data.to_vec())
    }
}

fn main() {
    stderrlog::new().module(module_path!()).verbosity(5).init().unwrap();
    let args = Cli::parse();

    let driver: &mut dyn Driver = &mut PcapDriver::new(args.interface);
    let rcpcd = Rc::new(RefCell::new(driver));

    let udp_echo = UdpEcho {};
    let mut udp_stack = UdpStack::new();
    udp_stack.add_listener(7, Box::new(udp_echo));

    let ethernet_stack: EthernetStack = EthernetStack::new(rcpcd.clone(), &mut udp_stack);
    loop {
        let packet = rcpcd.borrow_mut().get_next_packet_blocking();
        ethernet_stack.ethernet_input(&packet);
    }
}
