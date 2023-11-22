use std::net::IpAddr;

use etherparse::PacketHeaders;

use crate::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};

#[derive(Default, PartialEq, Debug)]
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

#[cfg(test)]
mod tests {
    use crate::utils::raw_packets::test_packets::{ARP_PACKET, ICMPV6_PACKET, TCP_PACKET};
    use crate::Fields;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_fields_new() {
        assert_eq!(
            Fields::new(&TCP_PACKET),
            Fields {
                source: Some(IpAddr::from_str("192.168.200.135").unwrap()),
                dest: Some(IpAddr::from_str("192.168.200.21").unwrap()),
                sport: Some(6711),
                dport: Some(2000),
                proto: Some(6),
                icmp_type: None,
                size: 66
            }
        );

        assert_eq!(
            Fields::new(&ICMPV6_PACKET),
            Fields {
                source: Some(IpAddr::from_str("3ffe:501:4819::42").unwrap()),
                dest: Some(IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap()),
                sport: None,
                dport: None,
                proto: Some(58),
                icmp_type: Some(135),
                size: 86
            }
        );

        assert_eq!(
            Fields::new(&ARP_PACKET),
            Fields {
                source: None,
                dest: None,
                sport: None,
                dport: None,
                proto: None,
                icmp_type: None,
                size: 42
            }
        );
    }
}
