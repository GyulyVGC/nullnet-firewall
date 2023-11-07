mod fields;
mod firewall_action;
mod firewall_direction;
mod firewall_error;
mod firewall_option;
mod firewall_rule;
mod ip_collection;
mod port_collection;
mod raw_packets;

use crate::fields::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};
use crate::firewall_action::FirewallAction;
use crate::firewall_direction::FirewallDirection;
use crate::firewall_error::FirewallError;
use crate::firewall_rule::FirewallRule;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// The firewall of our driver
#[derive(Debug, Eq, PartialEq, Default)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
    enabled: bool,
    policy_in: FirewallAction,
    policy_out: FirewallAction,
}

impl Firewall {
    pub fn new(file_path: &str) -> Result<Self, FirewallError> {
        let mut rules = Vec::new();
        let file = File::open(file_path).unwrap();
        for firewall_rule_str in BufReader::new(file).lines().flatten() {
            rules.push(FirewallRule::new(&firewall_rule_str)?);
        }

        Ok(Self {
            rules,
            enabled: true,
            policy_in: FirewallAction::default(),
            policy_out: FirewallAction::default(),
        })
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn set_policy_in(&mut self, policy: FirewallAction) {
        self.policy_in = policy;
    }

    pub fn set_policy_out(&mut self, policy: FirewallAction) {
        self.policy_out = policy;
    }

    #[must_use]
    pub fn determine_action_for_packet(
        &self,
        packet: &[u8],
        direction: &FirewallDirection,
    ) -> FirewallAction {
        if !self.enabled {
            return FirewallAction::Accept;
        }

        let mut action = match direction {
            FirewallDirection::In => self.policy_in,
            FirewallDirection::Out => self.policy_out,
        };

        let mut current_specificity = 0;
        for rule in &self.rules {
            if rule.matches_packet(packet, direction) && rule.specificity() >= current_specificity {
                current_specificity = rule.specificity();
                action = rule.action;
            }
        }
        action
    }
}

// for the moment it can be derived
// impl Default for Firewall {
//     fn default() -> Self {
//         Self {
//             rules: vec![],
//             enabled: false,
//             policy_in: FirewallAction::default(),
//             policy_out: FirewallAction::default(),
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use crate::firewall_option::FirewallOption;
    use crate::ip_collection::IpCollection;
    use crate::port_collection::PortCollection;
    use crate::raw_packets::test_packets::{ARP_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET};
    use crate::Firewall;
    use crate::{FirewallAction, FirewallDirection, FirewallError, FirewallRule};
    use std::net::IpAddr;
    use std::ops::RangeInclusive;
    use std::str::FromStr;

    const TEST_FILE_1: &str = "./samples/firewall_for_tests_1.txt";
    const TEST_FILE_2: &str = "./samples/firewall_for_tests_2.txt";
    const TEST_FILE_3: &str = "./samples/firewall_for_tests_3.txt";

    #[test]
    fn test_new_port_collections() {
        assert_eq!(
            PortCollection::new("1,2,3,4,999", FirewallError::InvalidSportValue).unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4, 999],
                ranges: vec![]
            }
        );

        assert_eq!(
            PortCollection::new("1,2,3,4,900:999", FirewallError::InvalidSportValue).unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![900..=999]
            }
        );

        assert_eq!(
            PortCollection::new("1:999", FirewallError::InvalidSportValue).unwrap(),
            PortCollection {
                ports: vec![],
                ranges: vec![1..=999]
            }
        );

        assert_eq!(
            PortCollection::new("1,2,10:20,3,4,999:1200", FirewallError::InvalidSportValue)
                .unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![10..=20, 999..=1200]
            }
        );

        assert_eq!(
            PortCollection::new("1,2,10:20,3,4,:1200", FirewallError::InvalidSportValue),
            Err(FirewallError::InvalidSportValue)
        );

        assert_eq!(
            PortCollection::new("1,2,10:20,3,4,999-1200", FirewallError::InvalidSportValue),
            Err(FirewallError::InvalidSportValue)
        );

        assert_eq!(
            PortCollection::new("1,2,10:20,3,4,999-1200,", FirewallError::InvalidDportValue),
            Err(FirewallError::InvalidDportValue)
        );
    }

    #[test]
    fn test_new_ip_collections() {
        assert_eq!(
            IpCollection::new("1.1.1.1,2.2.2.2", FirewallError::InvalidSourceValue).unwrap(),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap()
                ],
                ranges: vec![]
            }
        );

        assert_eq!(
            IpCollection::new(
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9",
                FirewallError::InvalidSourceValue
            )
            .unwrap(),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap(),
                    IpAddr::from_str("9.9.9.9").unwrap()
                ],
                ranges: vec![
                    RangeInclusive::new(
                        IpAddr::from_str("3.3.3.3").unwrap(),
                        IpAddr::from_str("5.5.5.5").unwrap()
                    ),
                    RangeInclusive::new(
                        IpAddr::from_str("10.0.0.1").unwrap(),
                        IpAddr::from_str("10.0.0.255").unwrap()
                    )
                ]
            }
        );

        assert_eq!(
            IpCollection::new(
                "aaaa::ffff,bbbb::1-cccc::2",
                FirewallError::InvalidSourceValue
            )
            .unwrap(),
            IpCollection {
                ips: vec![IpAddr::from_str("aaaa::ffff").unwrap(),],
                ranges: vec![RangeInclusive::new(
                    IpAddr::from_str("bbbb::1").unwrap(),
                    IpAddr::from_str("cccc::2").unwrap()
                )]
            }
        );

        assert_eq!(
            IpCollection::new(
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9",
                FirewallError::InvalidSourceValue
            ),
            Err(FirewallError::InvalidSourceValue)
        );

        assert_eq!(
            IpCollection::new(
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1:10.0.0.255,9.9.9.9",
                FirewallError::InvalidDestValue
            ),
            Err(FirewallError::InvalidDestValue)
        );
    }

    #[test]
    fn test_port_collection_contains() {
        let collection =
            PortCollection::new("1,2,25:30", FirewallError::InvalidDportValue).unwrap();
        assert!(collection.contains(Some(1)));
        assert!(collection.contains(Some(2)));
        assert!(collection.contains(Some(25)));
        assert!(collection.contains(Some(27)));
        assert!(collection.contains(Some(30)));
        assert!(!collection.contains(None));
        assert!(!collection.contains(Some(24)));
        assert!(!collection.contains(Some(31)));
        assert!(!collection.contains(Some(8080)));
    }

    #[test]
    fn test_ip_collection_contains() {
        let collection = IpCollection::new(
            "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9",
            FirewallError::InvalidDestValue,
        )
        .unwrap();
        assert!(collection.contains(Some(IpAddr::from_str("2.2.2.2").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("4.0.0.0").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("9.9.9.9").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("10.0.0.1").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("10.0.0.128").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("10.0.0.255").unwrap())));
        assert!(!collection.contains(None));
        assert!(!collection.contains(Some(IpAddr::from_str("10.0.0.0").unwrap())));
        assert!(!collection.contains(Some(IpAddr::from_str("2.2.2.1").unwrap())));
    }

    #[test]
    fn test_ip_collection_contains_ipv6() {
        let collection =
            IpCollection::new("2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac", FirewallError::InvalidDestValue).unwrap();
        assert!(collection.contains(Some(
            IpAddr::from_str("2001:db8:1234:0000:0000:0000:0000:0000").unwrap()
        )));
        assert!(collection.contains(Some(
            IpAddr::from_str("2001:db8:1234:ffff:ffff:ffff:ffff:ffff").unwrap()
        )));
        assert!(collection.contains(Some(
            IpAddr::from_str("2001:db8:1234:ffff:ffff:ffff:ffff:eeee").unwrap()
        )));
        assert!(collection.contains(Some(
            IpAddr::from_str("2001:db8:1234:aaaa:ffff:ffff:ffff:eeee").unwrap()
        )));
        assert!(collection.contains(Some(IpAddr::from_str("daa::aad").unwrap())));
        assert!(collection.contains(Some(IpAddr::from_str("caa::aac").unwrap())));
        assert!(!collection.contains(Some(
            IpAddr::from_str("2000:db8:1234:0000:0000:0000:0000:0000").unwrap()
        )));
        assert!(!collection.contains(Some(
            IpAddr::from_str("2001:db8:1235:ffff:ffff:ffff:ffff:ffff").unwrap()
        )));
        assert!(!collection.contains(Some(
            IpAddr::from_str("2001:eb8:1234:ffff:ffff:ffff:ffff:eeee").unwrap()
        )));
        assert!(!collection.contains(Some(IpAddr::from_str("da::aad").unwrap())));
        assert!(!collection.contains(Some(IpAddr::from_str("caa::aab").unwrap())));
    }

    #[test]
    fn test_new_firewall_options() {
        assert_eq!(
            FirewallOption::new(
                "--dest",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            )
            .unwrap(),
            FirewallOption::Dest(
                IpCollection::new(
                    "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9",
                    FirewallError::InvalidDestValue
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
                "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac", FirewallError::InvalidDestValue
            ).unwrap())
        );

        assert_eq!(
            FirewallOption::new("--dport", "1,2,10:20,3,4,999:1200").unwrap(),
            FirewallOption::Dport(
                PortCollection::new("1,2,10:20,3,4,999:1200", FirewallError::InvalidDportValue)
                    .unwrap()
            )
        );

        assert_eq!(
            FirewallOption::new("--icmp-type", "8").unwrap(),
            FirewallOption::IcmpType(8)
        );

        assert_eq!(
            FirewallOption::new("--proto", "1").unwrap(),
            FirewallOption::Proto(1)
        );

        assert_eq!(
            FirewallOption::new(
                "--source",
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9"
            )
            .unwrap(),
            FirewallOption::Source(
                IpCollection::new(
                    "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9",
                    FirewallError::InvalidSourceValue
                )
                .unwrap()
            )
        );

        assert_eq!(
            FirewallOption::new("--sport", "1,2,10:20,3,4,999:1200").unwrap(),
            FirewallOption::Sport(
                PortCollection::new("1,2,10:20,3,4,999:1200", FirewallError::InvalidSportValue)
                    .unwrap()
            )
        );

        assert_eq!(
            FirewallOption::new("--not-exists", "8.8.8.8"),
            Err(FirewallError::UnknownOption)
        );
    }

    #[test]
    fn test_new_firewall_rules() {
        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3")
                .unwrap(),
            FirewallRule {
                direction: FirewallDirection::Out,
                action: FirewallAction::Accept,
                options: vec![
                    FirewallOption::Source(
                        IpCollection::new("8.8.8.8,7.7.7.7", FirewallError::InvalidSourceValue)
                            .unwrap()
                    ),
                    FirewallOption::Dport(
                        PortCollection::new("900:1000,1,2,3", FirewallError::InvalidDportValue)
                            .unwrap()
                    )
                ]
            }
        );

        assert_eq!(
            FirewallRule::new("OUT REJECT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 1").unwrap(),
            FirewallRule {
                direction: FirewallDirection::Out,
                action: FirewallAction::Reject,
                options: vec![
                    FirewallOption::Source(IpCollection::new("8.8.8.8,7.7.7.7", FirewallError::InvalidSourceValue).unwrap()),
                    FirewallOption::Dport(PortCollection::new("900:1000,1,2,3", FirewallError::InvalidDportValue).unwrap()),
                    FirewallOption::IcmpType(8),
                    FirewallOption::Proto(1)
                ]
            }
        );

        assert_eq!(
            FirewallRule::new(
                "IN DENY --dest 8.8.8.8,7.7.7.7 --sport 900:1000,1,2,3 --icmp-type 1 --proto 58"
            )
            .unwrap(),
            FirewallRule {
                direction: FirewallDirection::In,
                action: FirewallAction::Deny,
                options: vec![
                    FirewallOption::Dest(
                        IpCollection::new("8.8.8.8,7.7.7.7", FirewallError::InvalidDestValue)
                            .unwrap()
                    ),
                    FirewallOption::Sport(
                        PortCollection::new("900:1000,1,2,3", FirewallError::InvalidSportValue)
                            .unwrap()
                    ),
                    FirewallOption::IcmpType(1),
                    FirewallOption::Proto(58)
                ]
            }
        );

        assert_eq!(
            FirewallRule::new("ACCEPT OUT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidDirection)
        );

        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport"),
            Err(FirewallError::EmptyOption)
        );

        assert_eq!(
            FirewallRule::new(
                "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
            ),
            Err(FirewallError::DuplicatedOption)
        );

        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3.3.3.3"),
            Err(FirewallError::InvalidDportValue)
        );

        assert_eq!(
            FirewallRule::new(
                "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8"
            ),
            Err(FirewallError::NotApplicableIcmpType)
        );

        assert_eq!(FirewallRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 57"
        ), Err(FirewallError::NotApplicableIcmpType));

        assert_eq!(
            FirewallRule::new("UP ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidDirection)
        );

        assert_eq!(
            FirewallRule::new("OUT PUTAWAY --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidAction)
        );
    }

    #[test]
    fn test_options_match_packets() {
        let dest_opt = FirewallOption::new("--dest", "192.168.200.21,8.8.8.8,2.1.1.2").unwrap();
        let range_dest_opt =
            FirewallOption::new("--dest", "192.168.200.0-192.168.200.255,8.8.8.8").unwrap();
        let range_dest_opt_miss =
            FirewallOption::new("--dest", "192.168.200.0-192.168.200.20,8.8.8.8").unwrap();
        let source_opt =
            FirewallOption::new("--source", "192.168.200.0-192.168.200.255,2.1.1.2").unwrap();
        let dport_opt = FirewallOption::new("--dport", "2000").unwrap();
        let range_dport_opt = FirewallOption::new("--dport", "6700:6750").unwrap();
        let sport_opt_wrong = FirewallOption::new("--sport", "2000").unwrap();
        let sport_opt_miss = FirewallOption::new("--sport", "6712").unwrap();
        let range_sport_opt = FirewallOption::new("--sport", "6711:6750").unwrap();
        let range_sport_opt_miss = FirewallOption::new("--sport", "6712:6750").unwrap();
        let icmp_type_opt = FirewallOption::new("--icmp-type", "8").unwrap();
        let wrong_icmp_type_opt = FirewallOption::new("--icmp-type", "7").unwrap();
        let tcp_proto_opt = FirewallOption::new("--proto", "6").unwrap();
        let icmp_proto_opt = FirewallOption::new("--proto", "1").unwrap();

        // tcp packet
        assert!(dest_opt.matches_packet(&TCP_PACKET));
        assert!(range_dest_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&TCP_PACKET));
        assert!(source_opt.matches_packet(&TCP_PACKET));
        assert!(dport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_dport_opt.matches_packet(&TCP_PACKET));
        assert!(!sport_opt_wrong.matches_packet(&TCP_PACKET));
        assert!(!sport_opt_miss.matches_packet(&TCP_PACKET));
        assert!(range_sport_opt.matches_packet(&TCP_PACKET));
        assert!(!range_sport_opt_miss.matches_packet(&TCP_PACKET));
        assert!(!icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&TCP_PACKET));
        assert!(tcp_proto_opt.matches_packet(&TCP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&TCP_PACKET));

        // icmp packet
        assert!(!dest_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dest_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&ICMP_PACKET));
        assert!(source_opt.matches_packet(&ICMP_PACKET));
        assert!(!dport_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_dport_opt.matches_packet(&ICMP_PACKET));
        assert!(!range_sport_opt.matches_packet(&ICMP_PACKET));
        assert!(icmp_type_opt.matches_packet(&ICMP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&ICMP_PACKET));
        assert!(!tcp_proto_opt.matches_packet(&ICMP_PACKET));
        assert!(icmp_proto_opt.matches_packet(&ICMP_PACKET));

        // arp packet
        assert!(!dest_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dest_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dest_opt_miss.matches_packet(&ARP_PACKET));
        assert!(!source_opt.matches_packet(&ARP_PACKET));
        assert!(!dport_opt.matches_packet(&ARP_PACKET));
        assert!(!range_dport_opt.matches_packet(&ARP_PACKET));
        assert!(!range_sport_opt.matches_packet(&ARP_PACKET));
        assert!(!icmp_type_opt.matches_packet(&ARP_PACKET));
        assert!(!wrong_icmp_type_opt.matches_packet(&ARP_PACKET));
        assert!(!tcp_proto_opt.matches_packet(&ARP_PACKET));
        assert!(!icmp_proto_opt.matches_packet(&ARP_PACKET));
    }

    #[test]
    fn test_options_match_ipv6() {
        let dest_ok = FirewallOption::new("--dest", "3ffe:507:0:1:200:86ff:fe05:8da").unwrap();
        let dest_ko = FirewallOption::new("--dest", "3ffe:501:4819::42").unwrap();
        let source_ko = FirewallOption::new("--source", "3ffe:507:0:1:200:86ff:fe05:8da").unwrap();
        let source_ok = FirewallOption::new("--source", "3ffe:501:4819::42").unwrap();
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
        let range_source_ok =
            FirewallOption::new("--source", "3ffe:501:4819::35-3ffe:501:4819::45").unwrap();
        let range_source_ok_2 = FirewallOption::new(
            "--source",
            "3ffe:501:4819::31-3ffe:501:4819::41,3ffe:501:4819::42",
        )
        .unwrap();
        let range_source_ko =
            FirewallOption::new("--source", "3ffe:501:4819::31-3ffe:501:4819::41").unwrap();
        let dport_ok = FirewallOption::new("--dport", "2396").unwrap();
        let dport_ko = FirewallOption::new("--dport", "3296").unwrap();
        let range_dport_ok = FirewallOption::new("--dport", "2000:2500").unwrap();
        let range_dport_ko = FirewallOption::new("--dport", "53:63").unwrap();
        let sport_ok = FirewallOption::new("--sport", "53").unwrap();
        let sport_ko = FirewallOption::new("--sport", "55").unwrap();
        let range_sport_ok = FirewallOption::new("--sport", "53:63").unwrap();
        let range_sport_ko = FirewallOption::new("--sport", "2000:2500").unwrap();
        let icmp_type = FirewallOption::new("--icmp-type", "8").unwrap();
        let proto_ok = FirewallOption::new("--proto", "17").unwrap();
        let proto_ko = FirewallOption::new("--proto", "18").unwrap();

        // ipv6 packet
        assert!(dest_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!dest_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(!source_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(source_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_dest_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_dest_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_source_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_source_ok_2.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_source_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(dport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!dport_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_dport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_dport_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(sport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!sport_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(range_sport_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!range_sport_ko.matches_packet(&UDP_IPV6_PACKET));
        assert!(!icmp_type.matches_packet(&UDP_IPV6_PACKET));
        assert!(proto_ok.matches_packet(&UDP_IPV6_PACKET));
        assert!(!proto_ko.matches_packet(&UDP_IPV6_PACKET));
    }

    #[test]
    fn test_rules_match_packets() {
        let rule_1 = FirewallRule::new("OUT DENY").unwrap();
        assert!(rule_1.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_1.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(rule_1.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_1.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_2 = FirewallRule::new("IN DENY").unwrap();
        assert!(!rule_2.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(rule_2.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_2.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(rule_2.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_3_ok_out =
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001").unwrap();
        assert!(rule_3_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_3_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_3_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_3_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_4_ok_in =
            FirewallRule::new("IN REJECT --source 192.168.200.135 --dport 1999:2001").unwrap();
        assert!(!rule_4_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(rule_4_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_4_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_4_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_5_ok_out =
            FirewallRule::new("OUT ACCEPT --source 192.168.200.135 --dport 1999:2001 --sport 6711")
                .unwrap();
        assert!(rule_5_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_5_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_5_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_5_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_6_ko =
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6710")
                .unwrap();
        assert!(!rule_6_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_6_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_6_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_6_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_7_ok_out = FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.21").unwrap();
        assert!(rule_7_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_7_ok_out.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_7_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_7_ok_out.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_8_ko = FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.20").unwrap();
        assert!(!rule_8_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_8_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_8_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_8_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_9_ok_in = FirewallRule::new("IN ACCEPT --proto 6").unwrap();
        assert!(!rule_9_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(rule_9_ok_in.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_9_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_9_ok_in.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_10_ko = FirewallRule::new("IN ACCEPT --proto 58").unwrap();
        assert!(!rule_10_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_10_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_10_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_10_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_11_ko = FirewallRule::new("IN ACCEPT --proto 1 --icmp-type 8").unwrap();
        assert!(!rule_11_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_11_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_11_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(rule_11_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_12_ko = FirewallRule::new("OUT DENY --proto 1 --icmp-type 7").unwrap();
        assert!(!rule_12_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_12_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(!rule_12_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_12_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
        let rule_13_ko = FirewallRule::new("OUT DENY --proto 1 --icmp-type 8").unwrap();
        assert!(!rule_13_ko.matches_packet(&TCP_PACKET, &FirewallDirection::Out));
        assert!(!rule_13_ko.matches_packet(&TCP_PACKET, &FirewallDirection::In));
        assert!(rule_13_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::Out));
        assert!(!rule_13_ko.matches_packet(&ICMP_PACKET, &FirewallDirection::In));
    }

    #[test]
    fn test_rules_match_ipv6() {
        let rule_1 = FirewallRule::new("OUT DENY").unwrap();
        assert!(rule_1.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(!rule_1.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
        let rule_2 = FirewallRule::new("IN DENY").unwrap();
        assert!(!rule_2.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(rule_2.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
        let rule_3_ok_out =
            FirewallRule::new("OUT REJECT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17")
                .unwrap();
        assert!(rule_3_ok_out.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(!rule_3_ok_out.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
        let rule_4_ok_in =
            FirewallRule::new("IN REJECT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17")
                .unwrap();
        assert!(!rule_4_ok_in.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(rule_4_ok_in.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
        let rule_5_ok_out = FirewallRule::new(
            "OUT ACCEPT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17 --sport 545:560,43,53",
        )
        .unwrap();
        assert!(rule_5_ok_out.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(!rule_5_ok_out.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
        let rule_6_ko = FirewallRule::new(
            "OUT ACCEPT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17 --sport 545:560,43,52",
        )
        .unwrap();
        assert!(!rule_6_ko.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(!rule_6_ko.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
        let rule_9_ok_in =
            FirewallRule::new("IN ACCEPT --source 3ffe:501:4819::42,3ffe:501:4819::49").unwrap();
        assert!(!rule_9_ok_in.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(rule_9_ok_in.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
        let rule_10_ko =
            FirewallRule::new("IN ACCEPT --source 3ffe:501:4819::47,3ffe:501:4819::49").unwrap();
        assert!(!rule_10_ko.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out));
        assert!(!rule_10_ko.matches_packet(&UDP_IPV6_PACKET, &FirewallDirection::In));
    }

    /// File is placed in examples/firewall_for_tests_1.txt and its content is the following:
    /// OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080
    /// OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080 --dport 1,2,2000
    /// OUT DENY --source 192.168.200.135-192.168.200.140 --sport 6700:6800,8080 --dport 1,2,2000
    /// OUT REJECT --source 192.168.200.135 --sport 6750:6800,8080 --dest 192.168.200.21 --dport 1,2,2000
    /// IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1
    /// IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8
    /// IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 9
    /// IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 58 --icmp-type 8
    /// OUT REJECT
    /// IN ACCEPT
    #[test]
    fn test_new_firewall_from_file() {
        let rules = vec![
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080").unwrap(),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new("OUT DENY --source 192.168.200.135-192.168.200.140 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6750:6800,8080 --dest 192.168.200.21 --dport 1,2,2000").unwrap(),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1").unwrap(),
            FirewallRule::new("IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8").unwrap(),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 9").unwrap(),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 58 --icmp-type 8").unwrap(),
            FirewallRule::new("OUT REJECT").unwrap(),
            FirewallRule::new("IN ACCEPT").unwrap(),
        ];
        let mut firewall = Firewall {
            rules,
            enabled: true,
            policy_in: FirewallAction::default(),
            policy_out: FirewallAction::default(),
        };

        assert_eq!(Firewall::new(TEST_FILE_1).unwrap(), firewall);

        firewall.disable();
        firewall.set_policy_in(FirewallAction::Deny);
        firewall.set_policy_out(FirewallAction::Reject);
        assert!(!firewall.enabled);
        assert_eq!(firewall.policy_in, FirewallAction::Deny);
        assert_eq!(firewall.policy_out, FirewallAction::Reject);
    }

    #[test]
    fn test_determine_action_for_packet_1() {
        let firewall = Firewall::new(TEST_FILE_1).unwrap();

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::Out),
            FirewallAction::Deny
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::In),
            FirewallAction::Reject
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::Out),
            FirewallAction::Reject
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::Out),
            FirewallAction::Reject
        );
    }

    #[test]
    fn test_determine_action_for_packet_2() {
        let mut firewall = Firewall::new(TEST_FILE_2).unwrap();
        firewall.set_policy_in(FirewallAction::Deny);
        firewall.set_policy_out(FirewallAction::Accept);

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::In),
            FirewallAction::Deny
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::Out),
            FirewallAction::Deny
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::In),
            FirewallAction::Reject
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::Out),
            FirewallAction::Accept
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::In),
            FirewallAction::Deny
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::Out),
            FirewallAction::Accept
        );
    }

    #[test]
    fn test_determine_action_for_packet_3() {
        let firewall = Firewall::new(TEST_FILE_3).unwrap();

        // ipv6 packet
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::In),
            FirewallAction::Reject
        );
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out),
            FirewallAction::Deny
        );
    }

    #[test]
    fn test_determine_action_for_packet_with_firewall_disabled() {
        let mut firewall = Firewall::new(TEST_FILE_1).unwrap();
        firewall.set_policy_in(FirewallAction::Reject); // doesn't matter
        firewall.set_policy_out(FirewallAction::Reject); // doesn't matter
        firewall.disable(); // always accept

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::Out),
            FirewallAction::Accept
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::Out),
            FirewallAction::Accept
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::In),
            FirewallAction::Accept
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::Out),
            FirewallAction::Accept
        );
    }
}
