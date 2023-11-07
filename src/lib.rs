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
    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };
    use crate::Firewall;
    use crate::{FirewallAction, FirewallDirection, FirewallRule};

    const TEST_FILE_1: &str = "./samples/firewall_for_tests_1.txt";
    const TEST_FILE_2: &str = "./samples/firewall_for_tests_2.txt";
    const TEST_FILE_3: &str = "./samples/firewall_for_tests_3.txt";

    #[test]
    fn test_new_firewall_from_file_1() {
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
    fn test_firewall_determine_action_for_packets_file_1() {
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
    fn test_firewall_determine_action_for_packets_file_2() {
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
    fn test_firewall_determine_action_for_packets_file_3() {
        let mut firewall = Firewall::new(TEST_FILE_3).unwrap();

        // ipv6 packet
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::In),
            FirewallAction::Reject
        );
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out),
            FirewallAction::Deny
        );

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::In),
            FirewallAction::default()
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::Out),
            FirewallAction::default()
        );

        // change default policies
        firewall.set_policy_in(FirewallAction::Deny);
        firewall.set_policy_out(FirewallAction::Accept);

        // ipv6 packet
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::In),
            FirewallAction::Reject
        );
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::Out),
            FirewallAction::Deny
        );

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::In),
            FirewallAction::Deny
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::Out),
            FirewallAction::Accept
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_while_disabled() {
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
