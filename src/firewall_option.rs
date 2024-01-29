use std::str::FromStr;

use crate::log_level::LogLevel;
use crate::utils::ip_collection::IpCollection;
use crate::utils::port_collection::PortCollection;
use crate::{Fields, FirewallError};

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
    /// Log level
    LogLevel(LogLevel),
}

impl FirewallOption {
    pub(crate) const DEST: &'static str = "--dest";
    pub(crate) const DPORT: &'static str = "--dport";
    pub(crate) const ICMPTYPE: &'static str = "--icmp-type";
    pub(crate) const PROTO: &'static str = "--proto";
    pub(crate) const SOURCE: &'static str = "--source";
    pub(crate) const SPORT: &'static str = "--sport";
    pub(crate) const LOGLEVEL: &'static str = "--log-level";

    pub(crate) fn new(l: usize, option: &str, value: &str) -> Result<Self, FirewallError> {
        Ok(match option {
            FirewallOption::DEST => Self::Dest(IpCollection::new(l, FirewallOption::DEST, value)?),
            FirewallOption::DPORT => {
                Self::Dport(PortCollection::new(l, FirewallOption::DPORT, value)?)
            }
            FirewallOption::ICMPTYPE => Self::IcmpType(
                u8::from_str(value)
                    .map_err(|_| FirewallError::InvalidIcmpTypeValue(l, value.to_owned()))?,
            ),
            FirewallOption::PROTO => Self::Proto(
                u8::from_str(value)
                    .map_err(|_| FirewallError::InvalidProtocolValue(l, value.to_owned()))?,
            ),
            FirewallOption::SOURCE => {
                Self::Source(IpCollection::new(l, FirewallOption::SOURCE, value)?)
            }
            FirewallOption::SPORT => {
                Self::Sport(PortCollection::new(l, FirewallOption::SPORT, value)?)
            }
            FirewallOption::LOGLEVEL => Self::LogLevel(LogLevel::from_str_with_line(l, value)?),
            x => return Err(FirewallError::UnknownOption(l, x.to_owned())),
        })
    }

    pub(crate) fn matches_packet(&self, fields: &Fields) -> bool {
        match self {
            FirewallOption::Dest(ip_collection) => ip_collection.contains(fields.dest),
            FirewallOption::Dport(port_collection) => port_collection.contains(fields.dport),
            FirewallOption::IcmpType(icmp_type) => {
                if let Some(observed_icmp) = fields.icmp_type {
                    icmp_type.eq(&observed_icmp)
                } else {
                    false
                }
            }
            FirewallOption::Proto(proto) => {
                if let Some(observed_proto) = fields.proto {
                    proto.eq(&observed_proto)
                } else {
                    false
                }
            }
            FirewallOption::Source(ip_collection) => ip_collection.contains(fields.source),
            FirewallOption::Sport(port_collection) => port_collection.contains(fields.sport),
            FirewallOption::LogLevel(_) => true,
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
            FirewallOption::LogLevel(_) => FirewallOption::LOGLEVEL,
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
    use crate::{DataLink, Fields, FirewallError, LogLevel};

    #[test]
    fn test_new_dest_option() {
        assert_eq!(
            FirewallOption::new(
                1,
                "--dest",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            )
            .unwrap(),
            FirewallOption::Dest(
                IpCollection::new(
                    1,
                    FirewallOption::DEST,
                    "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
                )
                .unwrap()
            )
        );

        assert_eq!(
            FirewallOption::new(
                2,
                "--dest",
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap(),
            FirewallOption::Dest(IpCollection::new(
                2,
                FirewallOption::DEST,
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap())
        );
    }

    #[test]
    fn test_new_dport_option() {
        assert_eq!(
            FirewallOption::new(3, "--dport", "1,2,10:20,3,4,999:1200").unwrap(),
            FirewallOption::Dport(
                PortCollection::new(3, FirewallOption::DPORT, "1,2,10:20,3,4,999:1200").unwrap()
            )
        );
    }

    #[test]
    fn test_new_icmp_type_option() {
        assert_eq!(
            FirewallOption::new(4, "--icmp-type", "8").unwrap(),
            FirewallOption::IcmpType(8)
        );
    }

    #[test]
    fn test_new_proto_option() {
        assert_eq!(
            FirewallOption::new(5, "--proto", "1").unwrap(),
            FirewallOption::Proto(1)
        );
    }

    #[test]
    fn test_new_sport_option() {
        assert_eq!(
            FirewallOption::new(6, "--sport", "1,2,10:20,3,4,999:1200").unwrap(),
            FirewallOption::Sport(
                PortCollection::new(6, FirewallOption::SPORT, "1,2,10:20,3,4,999:1200").unwrap()
            )
        );
    }

    #[test]
    fn test_new_source_option() {
        assert_eq!(
            FirewallOption::new(
                5,
                "--source",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            )
            .unwrap(),
            FirewallOption::Source(
                IpCollection::new(
                    5,
                    FirewallOption::SOURCE,
                    "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
                )
                .unwrap()
            )
        );

        assert_eq!(
            FirewallOption::new(
                10,
                "--source",
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap(),
            FirewallOption::Source(IpCollection::new(
                10,
                FirewallOption::SOURCE,
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac"
            ).unwrap())
        );
    }

    #[test]
    fn test_new_log_level_option() {
        assert_eq!(
            FirewallOption::new(3, "--log-level", "off").unwrap(),
            FirewallOption::LogLevel(LogLevel::Off)
        );

        assert_eq!(
            FirewallOption::new(3, "--log-level", "all").unwrap(),
            FirewallOption::LogLevel(LogLevel::All)
        );

        assert_eq!(
            FirewallOption::new(3, "--log-level", "console").unwrap(),
            FirewallOption::LogLevel(LogLevel::Console)
        );

        assert_eq!(
            FirewallOption::new(3, "--log-level", "db").unwrap(),
            FirewallOption::LogLevel(LogLevel::Db)
        );
    }

    #[test]
    fn test_not_existing_option() {
        let err = FirewallOption::new(11, "--not-exists", "8.8.8.8").unwrap_err();
        assert_eq!(
            err,
            FirewallError::UnknownOption(11, "--not-exists".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "Firewall error at line 11 - the specified option '--not-exists' doesn't exist"
        );

        assert_eq!(
            FirewallOption::new(14, "--log", "ciao").unwrap_err(),
            FirewallError::UnknownOption(14, "--log".to_owned())
        );
    }

    #[test]
    fn test_invalid_dest_option() {
        let err = FirewallOption::new(9, "--dest", "8").unwrap_err();
        assert_eq!(err, FirewallError::InvalidDestValue(9, "8".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 9 - incorrect value for option '--dest 8'"
        );
    }

    #[test]
    fn test_invalid_dport_option() {
        let err = FirewallOption::new(7, "--dport", "8.8.8.8").unwrap_err();
        assert_eq!(
            err,
            FirewallError::InvalidDportValue(7, "8.8.8.8".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "Firewall error at line 7 - incorrect value for option '--dport 8.8.8.8'"
        );
    }

    #[test]
    fn test_invalid_source_option() {
        let err = FirewallOption::new(55, "--source", "8").unwrap_err();
        assert_eq!(err, FirewallError::InvalidSourceValue(55, "8".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 55 - incorrect value for option '--source 8'"
        );
    }

    #[test]
    fn test_invalid_sport_option() {
        let err = FirewallOption::new(23, "--sport", "8.8.8.8").unwrap_err();
        assert_eq!(
            err,
            FirewallError::InvalidSportValue(23, "8.8.8.8".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "Firewall error at line 23 - incorrect value for option '--sport 8.8.8.8'"
        );
    }

    #[test]
    fn test_invalid_proto_option() {
        let err = FirewallOption::new(1, "--proto", "256").unwrap_err();
        assert_eq!(
            err,
            FirewallError::InvalidProtocolValue(1, "256".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "Firewall error at line 1 - incorrect value for option '--proto 256'"
        );
    }

    #[test]
    fn test_invalid_icmp_type_option() {
        let err = FirewallOption::new(2, "--icmp-type", "-1").unwrap_err();
        assert_eq!(err, FirewallError::InvalidIcmpTypeValue(2, "-1".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 2 - incorrect value for option '--icmp-type -1'"
        );
    }

    #[test]
    fn test_invalid_log_level_option() {
        let err = FirewallOption::new(17, "--log-level", "3").unwrap_err();
        assert_eq!(err, FirewallError::InvalidLogLevelValue(17, "3".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 17 - incorrect value for option '--log-level 3'"
        );
    }

    #[test]
    fn test_dest_matches_packets() {
        let dest_opt = FirewallOption::new(1, "--dest", "192.168.200.21,8.8.8.8,2.1.1.2").unwrap();
        let range_dest_opt =
            FirewallOption::new(1, "--dest", "192.168.200.0-192.168.200.255,8.8.8.8").unwrap();
        let range_dest_opt_miss =
            FirewallOption::new(5, "--dest", "192.168.200.0-192.168.200.20,8.8.8.8").unwrap();

        // tcp packet
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        assert!(dest_opt.matches_packet(&tcp_packet_fields));
        assert!(range_dest_opt.matches_packet(&tcp_packet_fields));
        assert!(!range_dest_opt_miss.matches_packet(&tcp_packet_fields));

        // icmp packet
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        assert!(!dest_opt.matches_packet(&icmp_packet_fields));
        assert!(!range_dest_opt.matches_packet(&icmp_packet_fields));
        assert!(!range_dest_opt_miss.matches_packet(&icmp_packet_fields));

        // arp packet
        let arp_packet_fields = Fields::new(&ARP_PACKET, DataLink::Ethernet);
        assert!(!dest_opt.matches_packet(&arp_packet_fields));
        assert!(!range_dest_opt.matches_packet(&arp_packet_fields));
        assert!(!range_dest_opt_miss.matches_packet(&arp_packet_fields));
    }

    #[test]
    fn test_dport_matches_packets() {
        let dport_opt = FirewallOption::new(2, "--dport", "2000").unwrap();
        let range_dport_opt = FirewallOption::new(22, "--dport", "6700:6750").unwrap();

        // tcp packet
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        assert!(dport_opt.matches_packet(&tcp_packet_fields));
        assert!(!range_dport_opt.matches_packet(&tcp_packet_fields));

        // icmp packet
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        assert!(!dport_opt.matches_packet(&icmp_packet_fields));
        assert!(!range_dport_opt.matches_packet(&icmp_packet_fields));

        // arp packet
        let arp_packet_fields = Fields::new(&ARP_PACKET, DataLink::Ethernet);
        assert!(!dport_opt.matches_packet(&arp_packet_fields));
        assert!(!range_dport_opt.matches_packet(&arp_packet_fields));
    }

    #[test]
    fn test_icmp_type_matches_packets() {
        let icmp_type_opt = FirewallOption::new(3, "--icmp-type", "8").unwrap();
        let wrong_icmp_type_opt = FirewallOption::new(4, "--icmp-type", "7").unwrap();

        // tcp packet
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        assert!(!icmp_type_opt.matches_packet(&tcp_packet_fields));
        assert!(!wrong_icmp_type_opt.matches_packet(&tcp_packet_fields));

        // icmp packet
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        assert!(icmp_type_opt.matches_packet(&icmp_packet_fields));
        assert!(!wrong_icmp_type_opt.matches_packet(&icmp_packet_fields));

        // arp packet
        let arp_packet_fields = Fields::new(&ARP_PACKET, DataLink::Ethernet);
        assert!(!icmp_type_opt.matches_packet(&arp_packet_fields));
        assert!(!wrong_icmp_type_opt.matches_packet(&arp_packet_fields));
    }

    #[test]
    fn test_proto_matches_packets() {
        let tcp_proto_opt = FirewallOption::new(5, "--proto", "6").unwrap();
        let icmp_proto_opt = FirewallOption::new(7, "--proto", "1").unwrap();

        // tcp packet
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        assert!(tcp_proto_opt.matches_packet(&tcp_packet_fields));
        assert!(!icmp_proto_opt.matches_packet(&tcp_packet_fields));

        // icmp packet
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        assert!(!tcp_proto_opt.matches_packet(&icmp_packet_fields));
        assert!(icmp_proto_opt.matches_packet(&icmp_packet_fields));

        // arp packet
        let arp_packet_fields = Fields::new(&ARP_PACKET, DataLink::Ethernet);
        assert!(!tcp_proto_opt.matches_packet(&arp_packet_fields));
        assert!(!icmp_proto_opt.matches_packet(&arp_packet_fields));
    }

    #[test]
    fn test_source_matches_packets() {
        let source_opt =
            FirewallOption::new(88, "--source", "192.168.200.0-192.168.200.255,2.1.1.2").unwrap();

        // tcp packet
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        assert!(source_opt.matches_packet(&tcp_packet_fields));

        // icmp packet
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        assert!(source_opt.matches_packet(&icmp_packet_fields));

        // arp packet
        let arp_packet_fields = Fields::new(&ARP_PACKET, DataLink::Ethernet);
        assert!(!source_opt.matches_packet(&arp_packet_fields));
    }

    #[test]
    fn test_sport_matches_packets() {
        let sport_opt_wrong = FirewallOption::new(6, "--sport", "2000").unwrap();
        let sport_opt_miss = FirewallOption::new(7, "--sport", "6712").unwrap();
        let range_sport_opt = FirewallOption::new(8, "--sport", "6711:6750").unwrap();
        let range_sport_opt_miss = FirewallOption::new(6, "--sport", "6712:6750").unwrap();

        // tcp packet
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        assert!(!sport_opt_wrong.matches_packet(&tcp_packet_fields));
        assert!(!sport_opt_miss.matches_packet(&tcp_packet_fields));
        assert!(range_sport_opt.matches_packet(&tcp_packet_fields));
        assert!(!range_sport_opt_miss.matches_packet(&tcp_packet_fields));

        // icmp packet
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        assert!(!sport_opt_wrong.matches_packet(&icmp_packet_fields));
        assert!(!sport_opt_miss.matches_packet(&icmp_packet_fields));
        assert!(!range_sport_opt.matches_packet(&icmp_packet_fields));
        assert!(!range_sport_opt_miss.matches_packet(&icmp_packet_fields));

        // arp packet
        let arp_packet_fields = Fields::new(&ARP_PACKET, DataLink::Ethernet);
        assert!(!sport_opt_wrong.matches_packet(&arp_packet_fields));
        assert!(!sport_opt_miss.matches_packet(&arp_packet_fields));
        assert!(!range_sport_opt.matches_packet(&arp_packet_fields));
        assert!(!range_sport_opt_miss.matches_packet(&arp_packet_fields));
    }

    #[test]
    fn test_log_level_matches_packets() {
        let off = FirewallOption::new(6, "--log-level", "off").unwrap();
        let all = FirewallOption::new(7, "--log-level", "all").unwrap();
        let console = FirewallOption::new(8, "--log-level", "console").unwrap();
        let db = FirewallOption::new(6, "--log-level", "db").unwrap();

        // tcp packet
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        assert!(off.matches_packet(&tcp_packet_fields));
        assert!(all.matches_packet(&tcp_packet_fields));
        assert!(console.matches_packet(&tcp_packet_fields));
        assert!(db.matches_packet(&tcp_packet_fields));

        // icmp packet
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        assert!(off.matches_packet(&icmp_packet_fields));
        assert!(all.matches_packet(&icmp_packet_fields));
        assert!(console.matches_packet(&icmp_packet_fields));
        assert!(db.matches_packet(&icmp_packet_fields));

        // arp packet
        let arp_packet_fields = Fields::new(&ARP_PACKET, DataLink::Ethernet);
        assert!(off.matches_packet(&arp_packet_fields));
        assert!(all.matches_packet(&arp_packet_fields));
        assert!(console.matches_packet(&arp_packet_fields));
        assert!(db.matches_packet(&arp_packet_fields));
    }

    #[test]
    fn test_dest_matches_ipv6() {
        let dest_ok = FirewallOption::new(2, "--dest", "3ffe:507:0:1:200:86ff:fe05:8da").unwrap();
        let dest_ko = FirewallOption::new(2, "--dest", "3ffe:501:4819::42").unwrap();
        let range_dest_ok = FirewallOption::new(
            1,
            "--dest",
            "3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:900",
        )
        .unwrap();
        let range_dest_ko = FirewallOption::new(
            3,
            "--dest",
            "3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:8bf",
        )
        .unwrap();

        // ipv6 packet
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        assert!(dest_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(!dest_ko.matches_packet(&udp_ipv6_packet_fields));
        assert!(range_dest_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(!range_dest_ko.matches_packet(&udp_ipv6_packet_fields));
    }

    #[test]
    fn test_dport_matches_ipv6() {
        let dport_ok = FirewallOption::new(3, "--dport", "2396").unwrap();
        let dport_ko = FirewallOption::new(4, "--dport", "3296").unwrap();
        let range_dport_ok = FirewallOption::new(44, "--dport", "2000:2500").unwrap();
        let range_dport_ko = FirewallOption::new(4, "--dport", "53:63").unwrap();

        // ipv6 packet
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        assert!(dport_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(!dport_ko.matches_packet(&udp_ipv6_packet_fields));
        assert!(range_dport_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(!range_dport_ko.matches_packet(&udp_ipv6_packet_fields));
    }

    #[test]
    fn test_icmp_type_matches_ipv6() {
        let icmp_type = FirewallOption::new(1, "--icmp-type", "8").unwrap();

        // ipv6 packet
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        assert!(!icmp_type.matches_packet(&udp_ipv6_packet_fields));
    }

    #[test]
    fn test_proto_matches_ipv6() {
        let proto_ok = FirewallOption::new(1, "--proto", "17").unwrap();
        let proto_ko = FirewallOption::new(2, "--proto", "18").unwrap();

        // ipv6 packet
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        assert!(proto_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(!proto_ko.matches_packet(&udp_ipv6_packet_fields));
    }

    #[test]
    fn test_source_matches_ipv6() {
        let source_ko =
            FirewallOption::new(65, "--source", "3ffe:507:0:1:200:86ff:fe05:8da").unwrap();
        let source_ok = FirewallOption::new(6, "--source", "3ffe:501:4819::42").unwrap();
        let range_source_ok =
            FirewallOption::new(2, "--source", "3ffe:501:4819::35-3ffe:501:4819::45").unwrap();
        let range_source_ok_2 = FirewallOption::new(
            21,
            "--source",
            "3ffe:501:4819::31-3ffe:501:4819::41,3ffe:501:4819::42",
        )
        .unwrap();
        let range_source_ko =
            FirewallOption::new(1, "--source", "3ffe:501:4819::31-3ffe:501:4819::41").unwrap();

        // ipv6 packet
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        assert!(!source_ko.matches_packet(&udp_ipv6_packet_fields));
        assert!(source_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(range_source_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(range_source_ok_2.matches_packet(&udp_ipv6_packet_fields));
        assert!(!range_source_ko.matches_packet(&udp_ipv6_packet_fields));
    }

    #[test]
    fn test_sport_matches_ipv6() {
        let sport_ok = FirewallOption::new(1, "--sport", "53").unwrap();
        let sport_ko = FirewallOption::new(1, "--sport", "55").unwrap();
        let range_sport_ok = FirewallOption::new(3, "--sport", "53:63").unwrap();
        let range_sport_ko = FirewallOption::new(3, "--sport", "2000:2500").unwrap();

        // ipv6 packet
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        assert!(sport_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(!sport_ko.matches_packet(&udp_ipv6_packet_fields));
        assert!(range_sport_ok.matches_packet(&udp_ipv6_packet_fields));
        assert!(!range_sport_ko.matches_packet(&udp_ipv6_packet_fields));
    }

    #[test]
    fn test_invalid_packets_do_not_match_options() {
        let sport = FirewallOption::new(7, "--sport", "53").unwrap();
        let source = FirewallOption::new(5, "--source", "55.55.55.55").unwrap();
        let dest = FirewallOption::new(3, "--dest", "0.0.0.0-255.255.255.255").unwrap();
        let dport = FirewallOption::new(9, "--dport", "0:65535").unwrap();
        let proto = FirewallOption::new(11, "--proto", "1").unwrap();
        let icmp_type = FirewallOption::new(13, "--icmp-type", "8").unwrap();

        // invalid packet #1
        let packet_1 = [];
        let fields_1 = Fields::new(&packet_1, DataLink::Ethernet);
        assert!(!sport.matches_packet(&fields_1));
        assert!(!source.matches_packet(&fields_1));
        assert!(!dest.matches_packet(&fields_1));
        assert!(!dport.matches_packet(&fields_1));
        assert!(!proto.matches_packet(&fields_1));
        assert!(!icmp_type.matches_packet(&fields_1));

        // invalid packet #2
        let packet_2 = [b'n', b'o', b't', b'v', b'a', b'l', b'i', b'd'];
        let fields_2 = Fields::new(&packet_2, DataLink::Ethernet);
        assert!(!sport.matches_packet(&fields_2));
        assert!(!source.matches_packet(&fields_2));
        assert!(!dest.matches_packet(&fields_2));
        assert!(!dport.matches_packet(&fields_2));
        assert!(!proto.matches_packet(&fields_2));
        assert!(!icmp_type.matches_packet(&fields_2));
    }
}
