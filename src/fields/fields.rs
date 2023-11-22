use std::net::IpAddr;

use etherparse::PacketHeaders;

use crate::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};

#[derive(Default)]
pub(crate) struct Fields {
    pub(crate) source: Option<IpAddr>,
    pub(crate) dest: Option<IpAddr>,
    pub(crate) sport: Option<u16>,
    pub(crate) dport: Option<u16>,
    pub(crate) proto: Option<u8>,
    pub(crate) icmp_type: Option<u8>,
    pub(crate) size: usize,
}

impl Fields {
    pub(crate) fn new(packet: &[u8]) -> Fields {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet) {
            let ip_header = headers.ip;
            let transport_header = headers.transport;
            Fields {
                source: get_source(&ip_header),
                dest: get_dest(&ip_header),
                sport: get_sport(&transport_header),
                dport: get_dport(&transport_header),
                proto: get_proto(&ip_header),
                icmp_type: get_icmp_type(&transport_header),
                size: packet.len(),
            }
        } else {
            Fields {
                size: packet.len(),
                ..Fields::default()
            }
        }
    }
}
