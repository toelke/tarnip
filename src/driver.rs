pub trait Driver {
    fn sendpacket(&mut self, packet: &[u8]);
    fn get_next_packet_blocking(&mut self) -> Vec<u8>;
}
