use clap::Parser;
use log::*;
use pcap::Capture;
use pcap::Device;
use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(short, long, default_value = "eth0")]
    interface: String,
}

#[derive(Debug, FromBytes, Immutable)]
#[repr(C)]
struct EthernetFrame {
    destination: [u8; 6],
    source: [u8; 6],
    ether_type: U16,
}

fn get_device(interface: String) -> Option<Device> {
    for device in Device::list().unwrap() {
        info!("device {:?}", device);
        if device.name == interface {
            return Some(device);
        }
    }
    None
}

fn main() {
    stderrlog::new().module(module_path!()).verbosity(5).init().unwrap();
    let args = Cli::parse();

    let device = get_device(args.interface).unwrap();
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next_packet() {
        let (frame, rest) = <[EthernetFrame]>::ref_from_prefix_with_elems(&packet, 1).unwrap();
        info!("received packet! {:?} {:?}", frame, rest);
    }
}
