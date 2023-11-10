use etherparse::TransportHeader;

pub(crate) fn get_sport(transport_header: Option<TransportHeader>) -> Option<u16> {
    if let Some(transport) = transport_header {
        match transport {
            TransportHeader::Tcp(h) => Some(h.source_port),
            TransportHeader::Udp(h) => Some(h.source_port),
            TransportHeader::Icmpv4(_) | TransportHeader::Icmpv6(_) => None,
        }
    } else {
        None
    }
}

pub(crate) fn get_dport(transport_header: Option<TransportHeader>) -> Option<u16> {
    if let Some(transport) = transport_header {
        match transport {
            TransportHeader::Tcp(h) => Some(h.destination_port),
            TransportHeader::Udp(h) => Some(h.destination_port),
            TransportHeader::Icmpv4(_) | TransportHeader::Icmpv6(_) => None,
        }
    } else {
        None
    }
}

pub(crate) fn get_icmp_type(transport_header: Option<TransportHeader>) -> Option<u8> {
    if let Some(transport) = transport_header {
        match transport {
            TransportHeader::Icmpv4(h) => Some(*h.to_bytes().first().unwrap()),
            TransportHeader::Icmpv6(h) => Some(*h.to_bytes().first().unwrap()),
            TransportHeader::Tcp(_) | TransportHeader::Udp(_) => None,
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::transport_header::{get_dport, get_icmp_type, get_sport};
    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMPV6_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };
    use etherparse::PacketHeaders;

    #[test]
    fn test_get_sport_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_sport(transport_header.clone()), Some(6711));
    }

    #[test]
    fn test_get_sport_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_sport(transport_header.clone()), None);
    }

    #[test]
    fn test_get_sport_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_sport(transport_header.clone()), None);
    }

    #[test]
    fn test_get_sport_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_sport(transport_header.clone()), Some(53));
    }

    #[test]
    fn test_get_sport_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_sport(transport_header.clone()), None);
    }

    #[test]
    fn test_get_dport_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_dport(transport_header.clone()), Some(2000));
    }

    #[test]
    fn test_get_dport_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_dport(transport_header.clone()), None);
    }

    #[test]
    fn test_get_dport_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_dport(transport_header.clone()), None);
    }

    #[test]
    fn test_get_dport_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_dport(transport_header.clone()), Some(2396));
    }

    #[test]
    fn test_get_dport_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_dport(transport_header.clone()), None);
    }

    #[test]
    fn test_get_icmp_type_tcp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_icmp_type(transport_header.clone()), None);
    }

    #[test]
    fn test_get_icmp_type_icmp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_icmp_type(transport_header.clone()), Some(8)); // echo request
    }

    #[test]
    fn test_get_icmp_type_arp_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_icmp_type(transport_header.clone()), None);
    }

    #[test]
    fn test_get_icmp_type_udp_ipv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_icmp_type(transport_header.clone()), None);
    }

    #[test]
    fn test_get_icmp_type_icmpv6_packet() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMPV6_PACKET).unwrap();
        let transport_header = headers.transport;
        assert_eq!(get_icmp_type(transport_header.clone()), Some(135)); // neighbor solicitation
    }
}
