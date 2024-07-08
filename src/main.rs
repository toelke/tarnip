use log::*;
use pcap::Capture;
use pcap::Device;

fn get_device() -> Option<Device> {
    for device in Device::list().unwrap() {
        info!("device {:?}", device);
        if device.name == "eth0" {
            return Some(device);
        }
    }
    None
}

fn main() {
    stderrlog::new().module(module_path!()).verbosity(5).init().unwrap();
    let device = get_device().unwrap();
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    while let Ok(packet) = cap.next_packet() {
        info!("received packet! {:?}", packet);
    }
}
