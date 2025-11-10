use std::net::IpAddr;

use etherparse::NetHeaders;

pub(crate) fn get_source(net_header: &Option<NetHeaders>) -> Option<IpAddr> {
    if let Some(ip) = net_header {
        match ip {
            NetHeaders::Ipv4(h, _) => Some(IpAddr::from(h.source)),
            NetHeaders::Ipv6(h, _) => Some(IpAddr::from(h.source)),
            NetHeaders::Arp(_) => None,
        }
    } else {
        None
    }
}

pub(crate) fn get_dest(net_header: &Option<NetHeaders>) -> Option<IpAddr> {
    if let Some(ip) = net_header {
        match ip {
            NetHeaders::Ipv4(h, _) => Some(IpAddr::from(h.destination)),
            NetHeaders::Ipv6(h, _) => Some(IpAddr::from(h.destination)),
            NetHeaders::Arp(_) => None,
        }
    } else {
        None
    }
}

pub(crate) fn get_proto(net_header: &Option<NetHeaders>) -> Option<u8> {
    if let Some(ip) = net_header {
        match ip {
            NetHeaders::Ipv4(h, _) => Some(h.protocol.0),
            NetHeaders::Ipv6(h, _) => Some(h.next_header.0),
            NetHeaders::Arp(_) => None,
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use etherparse::PacketHeaders;

    use crate::fields::net_header::{get_dest, get_proto, get_source};
    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMP_PACKET, ICMPV6_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };

    #[test]
    fn test_get_source_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_source(&net_header),
            Some(IpAddr::from_str("192.168.200.135").unwrap())
        );
    }

    #[test]
    fn test_get_source_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_source(&net_header),
            Some(IpAddr::from_str("2.1.1.2").unwrap())
        );
    }

    #[test]
    fn test_get_source_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(get_source(&net_header), None);
    }

    #[test]
    fn test_get_source_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_source(&net_header),
            Some(IpAddr::from_str("3ffe:501:4819::42").unwrap())
        );
    }

    #[test]
    fn test_get_source_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_source(&net_header),
            Some(IpAddr::from_str("3ffe:501:4819::42").unwrap())
        );
    }

    #[test]
    fn test_get_dest_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_dest(&net_header),
            Some(IpAddr::from_str("192.168.200.21").unwrap())
        );
    }

    #[test]
    fn test_get_dest_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_dest(&net_header),
            Some(IpAddr::from_str("2.1.1.1").unwrap())
        );
    }

    #[test]
    fn test_get_dest_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(get_dest(&net_header), None);
    }

    #[test]
    fn test_get_dest_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_dest(&net_header),
            Some(IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap())
        );
    }

    #[test]
    fn test_get_dest_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(
            get_dest(&net_header),
            Some(IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap())
        );
    }

    #[test]
    fn test_get_proto_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(get_proto(&net_header), Some(6)); // tcp
    }

    #[test]
    fn test_get_proto_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(get_proto(&net_header), Some(1)); // icmp
    }

    #[test]
    fn test_get_proto_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(get_proto(&net_header), None);
    }

    #[test]
    fn test_get_proto_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(get_proto(&net_header), Some(17)); // udp
    }

    #[test]
    fn test_get_proto_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let net_header = headers.net;
        assert_eq!(get_proto(&net_header), Some(58)); // icmpv6
    }
}
