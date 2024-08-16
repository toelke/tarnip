# tarnip

A small, toy IP stack, mainly written for learning rust.

Tested under Windows with WSL and Linux.

Run it using `cargo run --interface <interface>`. It uses `libpcap` to read and create packets. This has the downside that the computer that runs tarnip does not "see" packets by tarnip.

It opens a UDP echo socket on port 7. For now, the MAC is fixed at `AA:00:00:00:00:01` (defined in `ethernet.rs`), the IP is fixed to `192.168.3.150` (defined in `arp.rs`).

To implement own behaviour, you would implement `trait udp::Listener`.
