//! # Title
//! ### Subtitle

mod fields;
mod firewall_action;
mod firewall_direction;
mod firewall_error;
mod firewall_option;
mod firewall_rule;
mod utils;

use crate::fields::ip_header::{get_dest, get_proto, get_source};
use crate::fields::transport_header::{get_dport, get_icmp_type, get_sport};
pub use crate::firewall_action::FirewallAction;
pub use crate::firewall_direction::FirewallDirection;
pub use crate::firewall_error::FirewallError;
use crate::firewall_rule::FirewallRule;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Object embedding a collection of firewall rules and policies to determine
/// the action to be taken for a given network packet.
///
/// A new `Firewall` can be created from a textual file listing a set of rule.
#[derive(Debug, Eq, PartialEq, Default)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
    enabled: bool,
    policy_in: FirewallAction,
    policy_out: FirewallAction,
}

impl Firewall {
    /// Instantiates a new [`Firewall`] from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path of a file defining the firewall rules.
    ///
    /// # Errors
    ///
    /// Will return a [`FirewallError`] if the rules defined in the file are not properly formatted.
    ///
    /// # Panics
    ///
    /// Will panic if the supplied `file_path` does not exist or the user does not have
    /// permission to read it.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::Firewall;
    ///
    /// let firewall = Firewall::new("./samples/firewall.txt").unwrap();
    /// ```
    ///
    /// Sample file content:
    ///
    /// ``` txt
    /// OUT REJECT --source 8.8.8.8 --sport 6700:6800,8080
    /// OUT DENY --source 192.168.200.0-192.168.200.255 --sport 6700:6800,8080 --dport 1,2,2000
    /// IN ACCEPT --source 2.1.1.2,2.1.1.3 --dest 2.1.1.1 --proto 1
    /// IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8
    /// OUT REJECT
    /// IN ACCEPT
    /// ```
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

    /// Returns the action to be taken for a supplied network packet,
    /// according to rules defined for the [`Firewall`].
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw network packet data including headers and payload.
    ///
    /// * `direction` - The network packet direction (incoming or outgoing).
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::{Firewall, FirewallDirection, FirewallAction};
    ///
    /// let firewall = Firewall::new("/my/firewall/rules/file.txt").unwrap();
    ///
    /// // determine action for packet
    /// let action = firewall.determine_action_for_packet(&pkt_data, &FirewallDirection::IN);
    ///
    /// // act accordingly
    /// match action {
    ///     FirewallAction::ACCEPT => {/* ... */}
    ///     FirewallAction::DENY => {/* ... */}
    ///     FirewallAction::REJECT => {/* ... */}
    /// }
    /// ```
    #[must_use]
    pub fn determine_action_for_packet(
        &self,
        packet: &[u8],
        direction: &FirewallDirection,
    ) -> FirewallAction {
        if !self.enabled {
            return FirewallAction::ACCEPT;
        }

        let mut action = match direction {
            FirewallDirection::IN => self.policy_in,
            FirewallDirection::OUT => self.policy_out,
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

    /// Disables an existing [`Firewall`].
    ///
    /// This will make all the network packets be accepted
    /// regardless of the rules defined for the firewall.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::Firewall;
    ///
    /// let mut firewall = Firewall::new("./samples/firewall.txt").unwrap();
    ///
    /// // disable the firewall
    /// firewall.disable();
    /// ```
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enables an existing [`Firewall`].
    ///
    /// When a new firewall is created, it's enabled by default.
    ///
    /// When the firewall is enabled, the actions to take for network packets are determined
    /// according to the specified rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::Firewall;
    ///
    /// // a new firewall is enabled by default
    /// let mut firewall = Firewall::new("./samples/firewall.txt").unwrap();
    ///
    /// // disable the firewall
    /// firewall.disable();
    ///
    /// /* ... */
    ///
    /// // enable the firewall again
    /// firewall.enable();
    /// ```
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Sets the input policy for an existing [`Firewall`].
    ///
    /// # Arguments
    ///
    /// * `policy` - The policy to use for incoming packets that don't match any of the specified rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::{Firewall, FirewallAction};
    ///
    /// let mut firewall = Firewall::new("./samples/firewall.txt").unwrap();
    ///
    /// // set the firewall input policy
    /// firewall.set_policy_in(FirewallAction::DENY);
    /// ```
    pub fn set_policy_in(&mut self, policy: FirewallAction) {
        self.policy_in = policy;
    }

    /// Sets the output policy for an existing [`Firewall`].
    ///
    /// # Arguments
    ///
    /// * `policy` - The policy to use for outgoing packets that don't match any of the specified rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::{Firewall, FirewallAction};
    ///
    /// let mut firewall = Firewall::new("./samples/firewall.txt").unwrap();
    ///
    /// // set the firewall output policy
    /// firewall.set_policy_out(FirewallAction::ACCEPT);
    /// ```
    pub fn set_policy_out(&mut self, policy: FirewallAction) {
        self.policy_out = policy;
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
        firewall.set_policy_in(FirewallAction::DENY);
        firewall.set_policy_out(FirewallAction::REJECT);
        assert!(!firewall.enabled);
        assert_eq!(firewall.policy_in, FirewallAction::DENY);
        assert_eq!(firewall.policy_out, FirewallAction::REJECT);
    }

    #[test]
    fn test_firewall_determine_action_for_packets_file_1() {
        let mut firewall = Firewall::new(TEST_FILE_1).unwrap();
        firewall.set_policy_in(FirewallAction::DENY);
        firewall.set_policy_out(FirewallAction::ACCEPT);

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::OUT),
            FirewallAction::DENY
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::IN),
            FirewallAction::REJECT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::OUT),
            FirewallAction::REJECT
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::OUT),
            FirewallAction::REJECT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_file_2() {
        let mut firewall = Firewall::new(TEST_FILE_2).unwrap();
        firewall.set_policy_in(FirewallAction::DENY);
        firewall.set_policy_out(FirewallAction::ACCEPT);

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::OUT),
            FirewallAction::DENY
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::IN),
            FirewallAction::REJECT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_file_3() {
        let mut firewall = Firewall::new(TEST_FILE_3).unwrap();

        // ipv6 packet
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::IN),
            FirewallAction::REJECT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::OUT),
            FirewallAction::DENY
        );

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::IN),
            FirewallAction::default()
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::OUT),
            FirewallAction::default()
        );

        // change default policies
        firewall.set_policy_in(FirewallAction::DENY);
        firewall.set_policy_out(FirewallAction::ACCEPT);

        // ipv6 packet
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::IN),
            FirewallAction::REJECT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&UDP_IPV6_PACKET, &FirewallDirection::OUT),
            FirewallAction::DENY
        );

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_while_disabled() {
        let mut firewall = Firewall::new(TEST_FILE_1).unwrap();
        firewall.set_policy_in(FirewallAction::REJECT); // doesn't matter
        firewall.set_policy_out(FirewallAction::REJECT); // doesn't matter
        firewall.disable(); // always accept

        // tcp packet
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&TCP_PACKET, &FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // icmp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ICMP_PACKET, &FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // arp packet
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.determine_action_for_packet(&ARP_PACKET, &FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );
    }
}
