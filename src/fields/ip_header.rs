use std::net::IpAddr;

use etherparse::IpHeader;

pub(crate) fn get_source(ip_header: Option<IpHeader>) -> Option<IpAddr> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(IpAddr::from(h.source)),
            IpHeader::Version6(h, _) => Some(IpAddr::from(h.source)),
        }
    } else {
        None
    }
}

pub(crate) fn get_dest(ip_header: Option<IpHeader>) -> Option<IpAddr> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(IpAddr::from(h.destination)),
            IpHeader::Version6(h, _) => Some(IpAddr::from(h.destination)),
        }
    } else {
        None
    }
}

pub(crate) fn get_proto(ip_header: Option<IpHeader>) -> Option<u8> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(h.protocol),
            IpHeader::Version6(h, _) => Some(h.next_header),
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

    use crate::fields::ip_header::{get_dest, get_proto, get_source};
    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMPV6_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };

    #[test]
    fn test_get_source_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("192.168.200.135").unwrap())
        );
    }

    #[test]
    fn test_get_source_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("2.1.1.2").unwrap())
        );
    }

    #[test]
    fn test_get_source_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(get_source(ip_header.clone()), None);
    }

    #[test]
    fn test_get_source_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("3ffe:501:4819::42").unwrap())
        );
    }

    #[test]
    fn test_get_source_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("3ffe:501:4819::42").unwrap())
        );
    }

    #[test]
    fn test_get_dest_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_dest(ip_header.clone()),
            Some(IpAddr::from_str("192.168.200.21").unwrap())
        );
    }

    #[test]
    fn test_get_dest_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_dest(ip_header.clone()),
            Some(IpAddr::from_str("2.1.1.1").unwrap())
        );
    }

    #[test]
    fn test_get_dest_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(get_dest(ip_header.clone()), None);
    }

    #[test]
    fn test_get_dest_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_dest(ip_header.clone()),
            Some(IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap())
        );
    }

    #[test]
    fn test_get_dest_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(
            get_dest(ip_header.clone()),
            Some(IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap())
        );
    }

    #[test]
    fn test_get_proto_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(get_proto(ip_header.clone()), Some(6)); // tcp
    }

    #[test]
    fn test_get_proto_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(get_proto(ip_header.clone()), Some(1)); // icmp
    }

    #[test]
    fn test_get_proto_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(get_proto(ip_header.clone()), None);
    }

    #[test]
    fn test_get_proto_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(get_proto(ip_header.clone()), Some(17)); // udp
    }

    #[test]
    fn test_get_proto_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let ip_header = headers.ip;
        assert_eq!(get_proto(ip_header.clone()), Some(58)); // icmpv6
    }
}
