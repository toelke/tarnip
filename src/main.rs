use clap::Parser;

use crate::ethernet::EthernetStack;
mod arp;
mod ethernet;
mod icmp4;
mod ip4;
mod pcap_driver;
use crate::pcap_driver::PcapDriver;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(short, long, default_value = "eth0")]
    interface: String,
}

fn main() {
    stderrlog::new().module(module_path!()).verbosity(5).init().unwrap();
    let args = Cli::parse();

    let mut pcd = PcapDriver::new(args.interface);
    let rcpcd = Rc::new(RefCell::new(&mut pcd));
    let ethernet_stack: EthernetStack = EthernetStack::new(rcpcd.clone());
    loop {
        let packet = rcpcd.borrow_mut().run();
        ethernet_stack.ethernet_input(&packet);
    }
}
