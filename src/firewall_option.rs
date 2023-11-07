use crate::utils::ip_collection::IpCollection;
use crate::utils::port_collection::PortCollection;
use crate::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport, FirewallError};
use etherparse::PacketHeaders;
use std::str::FromStr;

/// Options associated to a specific firewall rule
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FirewallOption {
    /// Destination IP addresses
    Dest(IpCollection),
    /// Destination ports
    Dport(PortCollection),
    /// ICMP message type
    IcmpType(u8),
    /// IP protocol number
    Proto(u8),
    /// Source IP addresses
    Source(IpCollection),
    /// Source ports
    Sport(PortCollection),
}

impl FirewallOption {
    pub(crate) const DEST: &'static str = "--dest";
    pub(crate) const DPORT: &'static str = "--dport";
    pub(crate) const ICMPTYPE: &'static str = "--icmp-type";
    pub(crate) const PROTO: &'static str = "--proto";
    pub(crate) const SOURCE: &'static str = "--source";
    pub(crate) const SPORT: &'static str = "--sport";

    pub(crate) fn new(option: &str, value: &str) -> Result<Self, FirewallError> {
        Ok(match option {
            FirewallOption::DEST => Self::Dest(IpCollection::new(FirewallOption::DEST, value)?),
            FirewallOption::DPORT => {
                Self::Dport(PortCollection::new(FirewallOption::DPORT, value)?)
            }
            FirewallOption::ICMPTYPE => Self::IcmpType(
                u8::from_str(value)
                    .map_err(|_| FirewallError::InvalidIcmpTypeValue(value.to_owned()))?,
            ),
            FirewallOption::PROTO => Self::Proto(
                u8::from_str(value)
                    .map_err(|_| FirewallError::InvalidProtocolValue(value.to_owned()))?,
            ),
            FirewallOption::SOURCE => {
                Self::Source(IpCollection::new(FirewallOption::SOURCE, value)?)
            }
            FirewallOption::SPORT => {
                Self::Sport(PortCollection::new(FirewallOption::SPORT, value)?)
            }
            x => return Err(FirewallError::UnknownOption(x.to_owned())),
        })
    }

    pub(crate) fn matches_packet(&self, packet: &[u8]) -> bool {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet) {
            let ip_header = headers.ip;
            let transport_header = headers.transport;
            match self {
                FirewallOption::Dest(ip_collection) => ip_collection.contains(get_dest(ip_header)),
                FirewallOption::Dport(port_collection) => {
                    port_collection.contains(get_dport(transport_header))
                }
                FirewallOption::IcmpType(icmp_type) => {
                    if let Some(observed_icmp) = get_icmp_type(transport_header) {
                        icmp_type.eq(&observed_icmp)
                    } else {
                        false
                    }
                }
                FirewallOption::Proto(proto) => {
                    if let Some(observed_proto) = get_proto(ip_header) {
                        proto.eq(&observed_proto)
                    } else {
                        false
                    }
                }
                FirewallOption::Source(ip_collection) => {
                    ip_collection.contains(get_source(ip_header))
                }
                FirewallOption::Sport(port_collection) => {
                    port_collection.contains(get_sport(transport_header))
                }
            }
        } else {
            false
        }
    }

    pub(crate) fn to_option_str(&self) -> &str {
        match self {
            FirewallOption::Dest(_) => FirewallOption::DEST,
            FirewallOption::Dport(_) => FirewallOption::DPORT,
            FirewallOption::Proto(_) => FirewallOption::PROTO,
            FirewallOption::Source(_) => FirewallOption::SOURCE,
            FirewallOption::Sport(_) => FirewallOption::SPORT,
            FirewallOption::IcmpType(_) => FirewallOption::ICMPTYPE,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::firewall_option::FirewallOption;
    use crate::utils::ip_collection::IpCollection;
    use crate::utils::port_collection::PortCollection;
    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };
    use crate::FirewallError;

    #[test]
    fn test_new_dest_option() {
        assert_eq!(
            FirewallOption::new(
                "--dest",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            )
            .unwrap(),
            FirewallOption::Dest(
                IpCollection::new(
                    FirewallOption::DEST,
                    "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
                )
                .unwrap()
            )
        );

        assert_eq!(
            FirewallOption::new(
                "--dest",
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap(),
            FirewallOption::Dest(IpCollection::new(
                FirewallOption::DEST,
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap())
        );
    }

    #[test]
    fn test_new_dport_option() {
        assert_eq!(
            FirewallOption::new("--dport", "1,2,10:20,3,4,999:1200").unwrap(),
            FirewallOption::Dport(
                PortCollection::new(FirewallOption::DPORT, "1,2,10:20,3,4,999:1200").unwrap()
            )
        );
    }

    #[test]
    fn test_new_icmp_type_option() {
        assert_eq!(
            FirewallOption::new("--icmp-type", "8").unwrap(),
            FirewallOption::IcmpType(8)
        );
    }

    #[test]
    fn test_new_proto_option() {
        assert_eq!(
            FirewallOption::new("--proto", "1").unwrap(),
            FirewallOption::Proto(1)
        );
    }

    #[test]
    fn test_new_sport_option() {
        assert_eq!(
            FirewallOption::new("--sport", "1,2,10:20,3,4,999:1200").unwrap(),
            FirewallOption::Sport(
                PortCollection::new(FirewallOption::SPORT, "1,2,10:20,3,4,999:1200").unwrap()
            )
        );
    }

    #[test]
    fn test_new_source_option() {
        assert_eq!(
            FirewallOption::new(
                "--source",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            )
            .unwrap(),
            FirewallOption::Source(
                IpCollection::new(
                    FirewallOption::SOURCE,
                    "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
                )
                .unwrap()
            )
        );

        assert_eq!(
            FirewallOption::new(
                "--source",
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap(),
            FirewallOption::Source(IpCollection::new(
                FirewallOption::SOURCE,
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap())
        );
    }

    #[test]
    fn test_not_existing_option() {
        assert_eq!(
            FirewallOption::new("--not-exists", "8.8.8.8"),
            Err(FirewallError::UnknownOption("--not-exists".to_owned()))
        );
    }

    #[test]
    fn test_invalid_dest_option() {
        assert_eq!(
            FirewallOption::new("--dest", "8"),
            Err(FirewallError::InvalidDestValue("8".to_owned()))
        );
    }

    #[test]
    fn test_invalid_dport_option() {
        assert_eq!(
            FirewallOption::new("--dport", "8.8.8.8"),
            Err(FirewallError::InvalidDportValue("8.8.8.8".to_owned()))
        );
    }

    #[test]
    fn test_invalid_source_option() {
        assert_eq!(
            FirewallOption::new("--source", "8"),
            Err(FirewallError::InvalidSourceValue("8".to_owned()))
        );
    }

    #[test]
    fn test_invalid_sport_option() {
        assert_eq!(
            FirewallOption::new("--sport", "8.8.8.8"),
            Err(FirewallError::InvalidSportValue("8.8.8.8".to_owned()))
        );
    }

    #[test]
    fn test_invalid_proto_option() {
        assert_eq!(
            FirewallOption::new("--proto", "256"),
            Err(FirewallError::InvalidProtocolValue("256".to_owned()))
        );
    }

    #[test]
    fn test_invalid_icmp_type_option() {
        assert_eq!(
            FirewallOption::new("--icmp-type", "256"),
            Err(FirewallError::InvalidIcmpTypeValue("256".to_owned()))
        );
    }

    #[test]
    fn test_dest_matches_packets() {
        let dest_opt = FirewallOption::new("--dest", "192.168.200.21,8.8.8.8,2.1.1.2").unwrap();
        let range_dest_opt =
            FirewallOption::new("--dest", "192.168.200.0-192.168.200.255,8.8.8.8").unwrap();
        let range_dest_opt_miss =
            FirewallOption::new("--dest", "192.168.200.0-192.168.200.20,8.8.8.8").unwrap();

        // tcp packet
        assert!(dest_opt.matches_packet(&TCP_PACKET));
        assert!(range_dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!dest_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dest_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!dest_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dest_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_dport_matches_packets() {
        let dport_opt = FirewallOption::new("--dport", "2000").unwrap();
        let range_dport_opt = FirewallOption::new("--dport", "6700:6750").unwrap();

        // tcp packet
        assert!(dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dport_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!dport_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dport_opt.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!dport_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dport_opt.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_icmp_type_matches_packets() {
        let icmp_type_opt = FirewallOption::new("--icmp-type", "8").unwrap();
        let wrong_icmp_type_opt = FirewallOption::new("--icmp-type", "7").unwrap();

        // tcp packet
        assert!(!icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(icmp_type_opt.matches_packet(&ICMP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!icmp_type_opt.matches_packet(&ARP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_proto_matches_packets() {
        let tcp_proto_opt = FirewallOption::new("--proto", "6").unwrap();
        let icmp_proto_opt = FirewallOption::new("--proto", "1").unwrap();

        // tcp packet
        assert!(tcp_proto_opt.matches_packet(&TCP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!tcp_proto_opt.matches_packet(&ICMP_PACKET));
        assert!(icmp_proto_opt.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!tcp_proto_opt.matches_packet(&ARP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_source_matches_packets() {
        let source_opt =
            FirewallOption::new("--source", "192.168.200.0-192.168.200.255,2.1.1.2").unwrap();

        // tcp packet
        assert!(source_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(source_opt.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!source_opt.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_sport_matches_packets() {
        let sport_opt_wrong = FirewallOption::new("--sport", "2000").unwrap();
        let sport_opt_miss = FirewallOption::new("--sport", "6712").unwrap();
        let range_sport_opt = FirewallOption::new("--sport", "6711:6750").unwrap();
        let range_sport_opt_miss = FirewallOption::new("--sport", "6712:6750").unwrap();

        // tcp packet
        assert!(!sport_opt_wrong.matches_packet(&TCP_PACKET));
        assert!(!sport_opt_miss.matches_packet(&TCP_PACKET));
        assert!(range_sport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_sport_opt_miss.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!sport_opt_wrong.matches_packet(&ICMP_PACKET));
        assert!(!sport_opt_miss.matches_packet(&ICMP_PACKET));
        assert!(!range_sport_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_sport_opt_miss.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!sport_opt_wrong.matches_packet(&ARP_PACKET));
        assert!(!sport_opt_miss.matches_packet(&ARP_PACKET));
        assert!(!range_sport_opt.matches_packet(&ARP_PACKET));
        assert!(!range_sport_opt_miss.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_dest_matches_ipv6() {
        let dest_ok = FirewallOption::new("--dest", "3ffe:507:0:1:200:86ff:fe05:8da").unwrap();
        let dest_ko = FirewallOption::new("--dest", "3ffe:501:4819::42").unwrap();
        let range_dest_ok = FirewallOption::new(
            "--dest",
            "3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:900",
        )
        .unwrap();
        let range_dest_ko = FirewallOption::new(
            "--dest",
            "3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:8bf",
        )
        .unwrap();

        // ipv6 packet
        assert!(dest_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!dest_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_dest_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_dest_ko.matches_packet(&UDP_IPV6_PACKET));
    }

    #[test]
    fn test_dport_matches_ipv6() {
        let dport_ok = FirewallOption::new("--dport", "2396").unwrap();
        let dport_ko = FirewallOption::new("--dport", "3296").unwrap();
        let range_dport_ok = FirewallOption::new("--dport", "2000:2500").unwrap();
        let range_dport_ko = FirewallOption::new("--dport", "53:63").unwrap();

        // ipv6 packet
        assert!(dport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!dport_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_dport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_dport_ko.matches_packet(&UDP_IPV6_PACKET));
    }

    #[test]
    fn test_icmp_type_matches_ipv6() {
        let icmp_type = FirewallOption::new("--icmp-type", "8").unwrap();

        // ipv6 packet
        assert!(!icmp_type.matches_packet(&UDP_IPV6_PACKET));
    }

    #[test]
    fn test_proto_matches_ipv6() {
        let proto_ok = FirewallOption::new("--proto", "17").unwrap();
        let proto_ko = FirewallOption::new("--proto", "18").unwrap();

        // ipv6 packet
        assert!(proto_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!proto_ko.matches_packet(&UDP_IPV6_PACKET));
    }

    #[test]
    fn test_source_matches_ipv6() {
        let source_ko = FirewallOption::new("--source", "3ffe:507:0:1:200:86ff:fe05:8da").unwrap();
        let source_ok = FirewallOption::new("--source", "3ffe:501:4819::42").unwrap();
        let range_source_ok =
            FirewallOption::new("--source", "3ffe:501:4819::35-3ffe:501:4819::45").unwrap();
        let range_source_ok_2 = FirewallOption::new(
            "--source",
            "3ffe:501:4819::31-3ffe:501:4819::41,3ffe:501:4819::42",
        )
        .unwrap();
        let range_source_ko =
            FirewallOption::new("--source", "3ffe:501:4819::31-3ffe:501:4819::41").unwrap();

        // ipv6 packet
        assert!(!source_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(source_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_source_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_source_ok_2.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_source_ko.matches_packet(&UDP_IPV6_PACKET));
    }

    #[test]
    fn test_sport_matches_ipv6() {
        let sport_ok = FirewallOption::new("--sport", "53").unwrap();
        let sport_ko = FirewallOption::new("--sport", "55").unwrap();
        let range_sport_ok = FirewallOption::new("--sport", "53:63").unwrap();
        let range_sport_ko = FirewallOption::new("--sport", "2000:2500").unwrap();

        // ipv6 packet
        assert!(sport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!sport_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_sport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_sport_ko.matches_packet(&UDP_IPV6_PACKET));
    }
}
