//! **Rust-based firewall for network drivers.**
//!
//! # Purpose
//!
//! This library is used to match network packets against a set of constraints (here called *firewall rules*)
//! with the aim of deciding whether to permit or deny incoming/outgoing traffic.
//!
//! Given a set of firewall rules and a network packet, the library will *inform* the user
//! about *how* to handle the packet.
//!
//! The library assumes that users are able to manipulate the stream of network packets in a way such
//! it's possible to take proper actions to allow or deny the forwarding of single packets
//! between the operating system and the network card; consequently, this framework is mainly intended
//! to be used at the level of *network drivers*.
//!
//! # Firewall definition
//!
//! A new [`Firewall`] object is defined via the [`Firewall::new`] method, which accepts as parameter
//! the path of a file defining a collection of firewall rules.
//!
//! Each of the **rules** defined in the file is placed on a new line and has the following structure:
//! ``` txt
//! DIRECTION ACTION [OPTIONS]
//! ```
//!
//! * `DIRECTION` can be either `IN` or `OUT` and represents the traffic directionality
//! (see [`FirewallDirection`]).
//!
//! * `ACTION` can be either `ACCEPT`, `DENY`, or `REJECT` and represents the action
//! associated with the rule (see [`FirewallAction`]).
//!
//! * For each rule, a list of **options** can be specified to match the desired traffic:
//!   * `--dest`: destination IP addresses; the value is expressed in the form of a comma-separated
//!     list of IP addresses, in which each entry can also represent an address range (using the `-` character).
//!   * `--dport`: destination transport ports; the value is expressed in the form of a comma-separated
//!     list of port numbers, in which each entry can also represent a port range (using the `:` character).
//!   * `--icmp-type`: ICMP message type; the value is expressed as a number representing
//!     a specific message type (see [here](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types) for more info).
//!   * `--proto`: Internet Protocol number; the value is expressed as a number representing
//!     a specific protocol number (see [here](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1) for more info).
//!   * `--source`: source IP addresses; the value is expressed in the form of a comma-separated
//!     list of IP addresses, in which each entry can also represent an address range (using the `-` character).
//!   * `--sport`: source transport ports; the value is expressed in the form of a comma-separated
//!     list of port numbers, in which each entry can also represent a port range (using the `:` character).
//!
//! A **sample** firewall configuration file is reported in the following:
//!
//! ``` txt
//! OUT REJECT --source 8.8.8.8 --sport 6700:6800,8080
//! OUT DENY --source 192.168.200.0-192.168.200.255 --sport 6700:6800,8080 --dport 1,2,2000
//! IN ACCEPT --source 2.1.1.2,2.1.1.3 --dest 2.1.1.1 --proto 1
//! IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8
//! OUT REJECT
//! IN ACCEPT
//! ```
//!
//! In case of invalid firewall configurations, a [`FirewallError`] will be returned.
//!
//! # Usage
//!
//! Once a [`Firewall`] has been defined, it can be used to determine which action to take for each
//! of the netwrok packets in transit.
//!
//! This is done by invoking [`Firewall::resolve_packet`], which will answer with the
//! action to take for the supplied packet.
//!
//! ```
//! use nullnet_firewall::{Firewall, FirewallDirection, FirewallAction};
//!
//! // build the firewall from the rules in a file
//! let firewall = Firewall::new("./samples/firewall.txt").unwrap();
//!
//! // here we suppose to have a packet to match against the firewall
//! let packet = [/* ... */];
//!
//! // determine action for packet, supposing incoming direction for packet
//! let action = firewall.resolve_packet(&packet, FirewallDirection::IN);
//!
//! // act accordingly
//! match action {
//!     FirewallAction::ACCEPT => {/* ... */}
//!     FirewallAction::DENY => {/* ... */}
//!     FirewallAction::REJECT => {/* ... */}
//! }
//! ```
//!
//! An existing firewall can be temporarily [disabled](Firewall::disable),
//! and the default [input policy](Firewall::set_policy_in) and
//! [output policy](Firewall::set_policy_out) can
//! be overridden for packets that doesn't match any of the firewall rules.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use crate::fields::fields::Fields;
use crate::fields::ip_header::{get_dest, get_proto, get_source};
use crate::fields::transport_header::{get_dport, get_icmp_type, get_sport};
pub use crate::firewall_action::FirewallAction;
pub use crate::firewall_direction::FirewallDirection;
pub use crate::firewall_error::FirewallError;
use crate::firewall_rule::FirewallRule;
use crate::logs::log_entry::LogEntry;
use crate::logs::logger::log;

mod fields;
mod firewall_action;
mod firewall_direction;
mod firewall_error;
mod firewall_option;
mod firewall_rule;
mod logs;
mod utils;

/// Object embedding a collection of firewall rules and policies to determine
/// the action to be taken for a given network packet.
///
/// A new `Firewall` can be created from a textual file listing a set of rule.
pub struct Firewall {
    rules: Vec<FirewallRule>,
    enabled: bool,
    policy_in: FirewallAction,
    policy_out: FirewallAction,
    tx: Sender<LogEntry>,
}

impl Firewall {
    const COMMENT: char = '#';

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
        let (tx, rx): (Sender<LogEntry>, Receiver<LogEntry>) = mpsc::channel();
        thread::Builder::new()
            .name("logger".to_string())
            .spawn(move || {
                log(&rx);
            })
            .unwrap();

        let mut firewall = Firewall {
            rules: Vec::new(),
            enabled: true,
            policy_in: FirewallAction::default(),
            policy_out: FirewallAction::default(),
            tx,
        };

        firewall.update_rules(file_path)?;

        Ok(firewall)
    }

    /// Returns the action to be taken for a supplied network packet,
    /// according to rules defined for the [`Firewall`].
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw network packet bytes, including headers and payload.
    ///
    /// * `direction` - The network packet direction (incoming or outgoing).
    ///
    /// # Panics
    ///
    /// Will panic if the logger routine of the firewall aborts for some reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::{Firewall, FirewallDirection, FirewallAction};
    ///
    /// let firewall = Firewall::new("./samples/firewall.txt").unwrap();
    ///
    /// // here we suppose to have a packet to match against the firewall
    /// let packet = [/* ... */];
    ///
    /// // determine action for packet, supposing incoming direction for packet
    /// let action = firewall.resolve_packet(&packet, FirewallDirection::IN);
    ///
    /// // act accordingly
    /// match action {
    ///     FirewallAction::ACCEPT => {/* ... */}
    ///     FirewallAction::DENY => {/* ... */}
    ///     FirewallAction::REJECT => {/* ... */}
    /// }
    /// ```
    #[must_use]
    pub fn resolve_packet(&self, packet: &[u8], direction: FirewallDirection) -> FirewallAction {
        if !self.enabled {
            return FirewallAction::ACCEPT;
        }

        let mut action_opt = None;

        // structure the packet as a set of relevant fields
        let fields = Fields::new(packet);

        // determine action for packet
        for rule in &self.rules {
            if rule.matches_packet(&fields, &direction) {
                if rule.quick {
                    action_opt = Some(rule.action);
                    break;
                } else if action_opt.is_none() {
                    action_opt = Some(rule.action);
                }
            }
        }

        let action = action_opt.unwrap_or(match direction {
            FirewallDirection::IN => self.policy_in,
            FirewallDirection::OUT => self.policy_out,
        });

        // send the log entry to the logger thread
        let log_entry = LogEntry::new(&fields, direction, action);
        self.tx
            .send(log_entry)
            .expect("the firewall logger routine aborted");

        action
    }

    pub fn update_rules(&mut self, file_path: &str) -> Result<(), FirewallError> {
        let mut rules = Vec::new();
        let file = File::open(file_path).unwrap();
        for firewall_rule_str in BufReader::new(file)
            .lines()
            .flatten()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.starts_with(Self::COMMENT) && !l.is_empty())
        {
            rules.push(FirewallRule::new(&firewall_rule_str)?);
        }
        self.rules = rules;
        Ok(())
    }

    /// Disables an existing [`Firewall`].
    ///
    /// This will make all the network packets be accepted
    /// regardless of the rules defined for the firewall.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::{Firewall, FirewallAction, FirewallDirection};
    ///
    /// let mut firewall = Firewall::new("./samples/firewall.txt").unwrap();
    ///
    /// // here we suppose to have a packet to match against the firewall
    /// let packet = [/* ... */];
    ///
    /// // disable the firewall
    /// firewall.disable();
    ///
    /// // a disabled firewall will accept everything
    /// assert_eq!(
    ///     firewall.resolve_packet(&packet, FirewallDirection::IN),
    ///     FirewallAction::ACCEPT
    /// );
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
    /// firewall.policy_in(FirewallAction::DENY);
    /// ```
    pub fn policy_in(&mut self, policy: FirewallAction) {
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
    /// firewall.policy_out(FirewallAction::ACCEPT);
    /// ```
    pub fn policy_out(&mut self, policy: FirewallAction) {
        self.policy_out = policy;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};

    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };
    use crate::{Firewall, LogEntry};
    use crate::{FirewallAction, FirewallDirection, FirewallRule};

    const TEST_FILE_1: &str = "./samples/firewall_for_tests_1.txt";
    const TEST_FILE_2: &str = "./samples/firewall_for_tests_2.txt";
    const TEST_FILE_3: &str = "./samples/firewall_for_tests_3.txt";

    #[test]
    fn test_new_firewall_from_file_1() {
        let rules = vec![
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080").unwrap(),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new("+ OUT DENY --source 192.168.200.135-192.168.200.140 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6750:6800,8080 --dest 192.168.200.21 --dport 1,2,2000").unwrap(),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8").unwrap(),
            FirewallRule::new("+ IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8").unwrap(),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 9").unwrap(),
            FirewallRule::new("IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 58 --icmp-type 8").unwrap(),
            FirewallRule::new("OUT REJECT").unwrap(),
            FirewallRule::new("IN ACCEPT").unwrap(),
        ];

        let mut firewall_from_file = Firewall::new(TEST_FILE_1).unwrap();

        assert_eq!(firewall_from_file.rules, rules);
        assert!(firewall_from_file.enabled);
        assert_eq!(firewall_from_file.policy_out, FirewallAction::default());
        assert_eq!(firewall_from_file.policy_in, FirewallAction::default());

        firewall_from_file.disable();
        firewall_from_file.policy_in(FirewallAction::DENY);
        firewall_from_file.policy_out(FirewallAction::REJECT);
        assert!(!firewall_from_file.enabled);
        assert_eq!(firewall_from_file.policy_in, FirewallAction::DENY);
        assert_eq!(firewall_from_file.policy_out, FirewallAction::REJECT);

        firewall_from_file.enable();
        assert!(firewall_from_file.enabled);
    }

    #[test]
    fn test_firewall_determine_action_for_packets_file_1() {
        let mut firewall = Firewall::new(TEST_FILE_1).unwrap();
        firewall.policy_in(FirewallAction::DENY);
        firewall.policy_out(FirewallAction::ACCEPT);

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::DENY
        );

        // icmp packet
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET, FirewallDirection::IN),
            FirewallAction::REJECT
        );
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET, FirewallDirection::OUT),
            FirewallAction::REJECT
        );

        // arp packet
        assert_eq!(
            firewall.resolve_packet(&ARP_PACKET, FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.resolve_packet(&ARP_PACKET, FirewallDirection::OUT),
            FirewallAction::REJECT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_file_2() {
        let mut firewall = Firewall::new(TEST_FILE_2).unwrap();
        firewall.policy_in(FirewallAction::DENY);
        firewall.policy_out(FirewallAction::ACCEPT);

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::DENY
        );

        // icmp packet
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET, FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // arp packet
        assert_eq!(
            firewall.resolve_packet(&ARP_PACKET, FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&ARP_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_file_3() {
        let mut firewall = Firewall::new(TEST_FILE_3).unwrap();

        // ipv6 packet
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET, FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::IN),
            FirewallAction::default()
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::default()
        );

        // change default policies
        firewall.policy_in(FirewallAction::DENY);
        firewall.policy_out(FirewallAction::REJECT);

        // ipv6 packet
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET, FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::REJECT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_while_disabled() {
        let mut firewall = Firewall::new(TEST_FILE_1).unwrap();
        firewall.policy_in(FirewallAction::REJECT); // doesn't matter
        firewall.policy_out(FirewallAction::REJECT); // doesn't matter
        firewall.disable(); // always accept

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // icmp packet
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET, FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // arp packet
        assert_eq!(
            firewall.resolve_packet(&ARP_PACKET, FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.resolve_packet(&ARP_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );
    }

    #[test]
    fn test_firewall_rules_precedence() {
        let (tx, _rx): (Sender<LogEntry>, Receiver<LogEntry>) = mpsc::channel();
        let mut firewall = Firewall {
            rules: vec![],
            enabled: true,
            policy_in: Default::default(),
            policy_out: Default::default(),
            tx,
        };

        let rules_1 = vec![
            // no quick, first match wins
            FirewallRule::new("OUT DENY --source 192.168.200.135 --sport 6700:6800,8080").unwrap(),
            FirewallRule::new("OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
        ];
        firewall = Firewall {
            rules: rules_1,
            ..firewall
        };
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::IN),
            FirewallAction::default()
        );

        let rules_2 = vec![
            // quick match wins
            FirewallRule::new("+ OUT DENY --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
            FirewallRule::new("OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
        ];
        firewall = Firewall {
            rules: rules_2,
            ..firewall
        };
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::DENY
        );

        let rules_3 = vec![
            // quick match wins even if after other matches
            FirewallRule::new("OUT DENY --source 192.168.200.135 --sport 6700:6800,8080").unwrap(),
            FirewallRule::new("OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
            FirewallRule::new("+ OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
        ];
        firewall = Firewall {
            rules: rules_3,
            ..firewall
        };
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::REJECT
        );

        let rules_4 = vec![
            // first quick match wins
            FirewallRule::new("OUT DENY --source 192.168.200.135 --sport 6700:6800,8080").unwrap(),
            FirewallRule::new("+ OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
            FirewallRule::new("+ OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
        ];
        firewall = Firewall {
            rules: rules_4,
            ..firewall
        };
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        let rules_5 = vec![
            // only quick rules, first wins
            FirewallRule::new("+ OUT DENY --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
            FirewallRule::new("+ OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
            FirewallRule::new("+ OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080")
                .unwrap(),
        ];
        firewall = Firewall {
            rules: rules_5,
            ..firewall
        };
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET, FirewallDirection::OUT),
            FirewallAction::DENY
        );
    }
}
