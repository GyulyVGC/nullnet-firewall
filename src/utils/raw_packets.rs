//! Packets are taken from wireshark sample captures available at <https://wiki.wireshark.org/SampleCaptures>
//! These data are only used for testing purposes

#[cfg(test)]
pub(crate) mod test_packets {
    #[rustfmt::skip]
    pub(crate) const TCP_PACKET: [u8; 66] = [
        // ethernet header
        0x00, 0x0c, 0x29, 0x1c, 0xe3, 0x19,
        0xec, 0xf4, 0xbb, 0xd9, 0xe3, 0x7d,
        0x08, 0x00,
        // ip header
        0x45, 0x00, 0x00, 0x34, 0x1b, 0x63,
        0x40, 0x00, 0x80, 0x06, 0xcd, 0x72,
        0xc0, 0xa8, 0xc8, 0x87,
        0xc0, 0xa8, 0xc8, 0x15,
        // tcp header
        0x1a, 0x37, 0x07, 0xd0, 0xdd, 0x6a,
        0xbb, 0x2a, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x02, 0xfa, 0xf0, 0x12, 0x15,
        0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x01, 0x03, 0x03, 0x08, 0x01, 0x01,
        0x04, 0x02
    ];

    #[rustfmt::skip]
    pub(crate) const ICMP_PACKET: [u8; 50] = [
        // ethernet header
        0x00, 0x0c, 0x29, 0x1c, 0xe3, 0x19,
        0xec, 0xf4, 0xbb, 0xd9, 0xe3, 0x7d,
        0x08, 0x00,
        // ip header
        0x45, 0x00, 0x00, 0x34, 0x1b, 0x63,
        0x40, 0x00, 0x80, 0x01, 0xcd, 0x72,
        0x02, 0x01, 0x01, 0x02,
        0x02, 0x01, 0x01, 0x01,
        // icmp header
        0x08, 0x00, 0x4d, 0x71, 0x13, 0xc2,
        0x00, 0x01, 0x14, 0x2b, 0xd2, 0x59,
        0x00, 0x00, 0x00, 0x00
    ];

    #[rustfmt::skip]
    pub(crate) const ARP_PACKET: [u8; 42] = [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01,         // dst MAC
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02,         // src MAC
        0x08, 0x06,                                 // ether type: ARP
        0x00, 0x01,                                 // HTYPE: ethernet
        0x08, 0x00,                                 // PTYPE: IPv4
        6,                                          // HLEN: 6 bytes for ethernet
        4,                                          // PLEN: 4 bytes for IPv4
        0x00, 0x02,                                 // operation: 2 is ARP reply
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01,         // sender MAC
        192, 168, 1, 251,                           // sender IP
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02,         // target MAC
        192, 168, 1, 1,                             // target IP
    ];

    #[rustfmt::skip]
    pub(crate) const UDP_IPV6_PACKET: [u8; 62] = [
        // ethernet header
        0x00, 0x00, 0x86, 0x05, 0x80, 0xda,
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea,
        0x86, 0xdd, //ipv6
        // ipv6 header
        0x60, 0x00, 0x00, 0x00, 0x01, 0xc8,
        0x11, 0xe6,
        0x3f, 0xfe, 0x05, 0x01, 0x48, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x08, 0xda,
        // udp header
        0x00, 0x35,
        0x09, 0x5c,
        0x01, 0xc8,
        0xfe, 0x6a,
    ];
}