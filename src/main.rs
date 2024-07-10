use clap::Parser;

mod arp;
mod ethernet;
mod ip4;
mod pcap_driver;
use crate::pcap_driver::PcapDriver;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(short, long, default_value = "eth0")]
    interface: String,
}

fn main() {
    stderrlog::new().module(module_path!()).verbosity(5).init().unwrap();
    let args = Cli::parse();

    let mut pcd = PcapDriver::new(args.interface);
    pcd.run();
}
