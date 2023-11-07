mod fields;
mod firewall_action;
mod firewall_direction;
mod firewall_error;
mod firewall_option;
mod firewall_rule;
mod utils;

use crate::fields::ip_header::{get_dest, get_proto, get_source};
use crate::fields::transport_header::{get_dport, get_icmp_type, get_sport};
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
    use crate::utils::ip_collection::IpCollection;
    use crate::utils::port_collection::PortCollection;
    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };
    use crate::Firewall;
    use crate::{FirewallAction, FirewallDirection, FirewallError, FirewallRule};

    const TEST_FILE_1: &str = "./samples/firewall_for_tests_1.txt";
    const TEST_FILE_2: &str = "./samples/firewall_for_tests_2.txt";
    const TEST_FILE_3: &str = "./samples/firewall_for_tests_3.txt";

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
                        IpCollection::new(FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()
                    ),
                    FirewallOption::Dport(
                        PortCollection::new(FirewallOption::DPORT, "900:1000,1,2,3").unwrap()
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
                    FirewallOption::Source(IpCollection::new(FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()),
                    FirewallOption::Dport(PortCollection::new(FirewallOption::DPORT, "900:1000,1,2,3").unwrap()),
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
                        IpCollection::new(FirewallOption::DEST, "8.8.8.8,7.7.7.7").unwrap()
                    ),
                    FirewallOption::Sport(
                        PortCollection::new(FirewallOption::SPORT, "900:1000,1,2,3").unwrap()
                    ),
                    FirewallOption::IcmpType(1),
                    FirewallOption::Proto(58)
                ]
            }
        );

        assert_eq!(
            FirewallRule::new("ACCEPT OUT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidDirection("ACCEPT".to_owned()))
        );

        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport"),
            Err(FirewallError::EmptyOption("--dport".to_owned()))
        );

        assert_eq!(
            FirewallRule::new(
                "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
            ),
            Err(FirewallError::DuplicatedOption("--dport".to_owned()))
        );

        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3.3.3.3"),
            Err(FirewallError::InvalidDportValue(
                "900:1000,1,2,3.3.3.3".to_owned()
            ))
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
            Err(FirewallError::InvalidDirection("UP".to_owned()))
        );

        assert_eq!(
            FirewallRule::new("OUT PUTAWAY --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidAction("PUTAWAY".to_owned()))
        );
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
