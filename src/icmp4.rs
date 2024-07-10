use zerocopy::byteorder::network_endian::U16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

#[derive(Debug, FromBytes, Immutable, KnownLayout, IntoBytes)]
#[repr(C)]
struct ICMPHeader {
    icmp_type: u8,
    icmp_code: u8,
    checksum: U16,
}

impl ICMPHeader {
    fn calc_checksum(&self, rest: &[u8]) -> U16 {
        let mut sum = 0u32;
        sum += u32::from(self.icmp_type) << 8 | u32::from(self.icmp_code);
        for i in (0..rest.len()).step_by(2) {
            sum += u32::from(rest[i]) << 8 | u32::from(rest[i + 1]);
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        U16::new(!sum as u16)
    }
}

pub fn icmp_input(payload: &[u8]) -> Option<Vec<u8>> {
    let (icmp_header, payload) = ICMPHeader::ref_from_prefix(payload).unwrap();
    match icmp_header.icmp_type {
        8 => {
            let mut reply = Vec::<u8>::new();
            let mut icmpheader = ICMPHeader {
                icmp_type: 0,
                icmp_code: 0,
                checksum: U16::new(0),
            };
            icmpheader.checksum = icmpheader.calc_checksum(payload);
            reply.extend_from_slice(icmpheader.as_bytes());
            reply.extend_from_slice(payload);
            Some(reply)
        }
        _ => None,
    }
}
