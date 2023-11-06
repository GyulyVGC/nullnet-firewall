use etherparse::{IpHeader, TransportHeader};
use std::net::IpAddr;

/// Extract header fields

pub fn get_source(ip_header: Option<IpHeader>) -> Option<IpAddr> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(IpAddr::from(h.source)),
            IpHeader::Version6(h, _) => Some(IpAddr::from(h.source)),
        }
    } else {
        None
    }
}

pub fn get_dest(ip_header: Option<IpHeader>) -> Option<IpAddr> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(IpAddr::from(h.destination)),
            IpHeader::Version6(h, _) => Some(IpAddr::from(h.destination)),
        }
    } else {
        None
    }
}

pub fn get_sport(transport_header: Option<TransportHeader>) -> Option<u16> {
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

pub fn get_dport(transport_header: Option<TransportHeader>) -> Option<u16> {
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

pub fn get_proto(ip_header: Option<IpHeader>) -> Option<u8> {
    if let Some(ip) = ip_header {
        match ip {
            IpHeader::Version4(h, _) => Some(h.protocol),
            IpHeader::Version6(h, _) => Some(h.next_header),
        }
    } else {
        None
    }
}

pub fn get_icmp_type(transport_header: Option<TransportHeader>) -> Option<u8> {
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
    use crate::fields::{
        get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport,
    };
    use crate::raw_packets::{ARP_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET};
    use etherparse::PacketHeaders;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_tcp_packet_fields() {
        let headers = PacketHeaders::from_ethernet_slice(&TCP_PACKET).unwrap();
        let ip_header = headers.ip;
        let transport_header = headers.transport;
        assert_eq!(get_proto(ip_header.clone()), Some(6)); // tcp
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("192.168.200.135").unwrap())
        );
        assert_eq!(
            get_dest(ip_header),
            Some(IpAddr::from_str("192.168.200.21").unwrap())
        );
        assert_eq!(get_icmp_type(transport_header.clone()), None);
        assert_eq!(get_sport(transport_header.clone()), Some(6711));
        assert_eq!(get_dport(transport_header), Some(2000));
    }

    #[test]
    fn test_icmp_packet_fields() {
        let headers = PacketHeaders::from_ethernet_slice(&ICMP_PACKET).unwrap();
        let ip_header = headers.ip;
        let transport_header = headers.transport;
        assert_eq!(get_proto(ip_header.clone()), Some(1)); // icmp
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("2.1.1.2").unwrap())
        );
        assert_eq!(
            get_dest(ip_header),
            Some(IpAddr::from_str("2.1.1.1").unwrap())
        );
        assert_eq!(get_icmp_type(transport_header.clone()), Some(8)); // echo request
        assert_eq!(get_sport(transport_header.clone()), None);
        assert_eq!(get_dport(transport_header), None);
    }

    #[test]
    fn test_arp_packet_fields() {
        let headers = PacketHeaders::from_ethernet_slice(&ARP_PACKET).unwrap();
        let ip_header = headers.ip;
        let transport_header = headers.transport;
        assert_eq!(get_proto(ip_header.clone()), None);
        assert_eq!(get_source(ip_header.clone()), None);
        assert_eq!(get_dest(ip_header), None);
        assert_eq!(get_icmp_type(transport_header.clone()), None);
        assert_eq!(get_sport(transport_header.clone()), None);
        assert_eq!(get_dport(transport_header), None);
    }

    #[test]
    fn test_udp_ipv6_packet_fields() {
        let headers = PacketHeaders::from_ethernet_slice(&UDP_IPV6_PACKET).unwrap();
        let ip_header = headers.ip;
        let transport_header = headers.transport;
        assert_eq!(get_proto(ip_header.clone()), Some(17)); // udp
        assert_eq!(
            get_source(ip_header.clone()),
            Some(IpAddr::from_str("3ffe:501:4819::42").unwrap())
        );
        assert_eq!(
            get_dest(ip_header),
            Some(IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap())
        );
        assert_eq!(get_icmp_type(transport_header.clone()), None);
        assert_eq!(get_sport(transport_header.clone()), Some(53));
        assert_eq!(get_dport(transport_header), Some(2396));
    }
}
