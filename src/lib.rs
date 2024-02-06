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
//! between the network card and the operating system; consequently, this framework is mainly intended
//! to be used at the level of *network drivers*.
//!
//! Each of the packets passed to the firewall will be logged both in standard output
//! and in a `SQLite` database with path `./log.sqlite`.
//!
//! # Firewall definition
//!
//! A new [`Firewall`] object is instantiated via the [`Firewall::new`] method.
//!
//! The newly created firewall can be configured via [`Firewall::set_rules`], which accepts as parameter
//! the path of a file defining a collection of firewall rules.
//!
//! Each of the **rules** defined in the file is placed on a new line and has the following structure:
//! ``` txt
//! [+] DIRECTION ACTION [OPTIONS]
//! ```
//!
//! * Each rule can optionally be introduced by a `+` character; this will make the rule
//! have higher priority (quick rule).
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
//!   * `--log-level`: [logging strategy](`LogLevel`) to use for traffic matching the rule; possible values are `off`, `console`, `db`, `all`.
//!   * `--proto`: Internet Protocol number; the value is expressed as a number representing
//!     a specific protocol number (see [here](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1) for more info).
//!   * `--source`: source IP addresses; the value is expressed in the form of a comma-separated
//!     list of IP addresses, in which each entry can also represent an address range (using the `-` character).
//!   * `--sport`: source transport ports; the value is expressed in the form of a comma-separated
//!     list of port numbers, in which each entry can also represent a port range (using the `:` character).
//!
//! A **sample** firewall configuration file is reported in the following:
//!
//! ``` text
//! # Firewall rules (this is a comment line)
//!
//! IN REJECT --source 8.8.8.8 --log-level all
//! # Rules marked with '+' have higher priority
//! + IN ACCEPT --source 8.8.8.0-8.8.8.10 --sport 8
//! OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3
//! OUT DENY
//! ```
//!
//! In case of invalid firewall configurations, a [`FirewallError`] will be raised.
//!
//! # Usage
//!
//! Once a [`Firewall`] has been defined, it can be used to determine which action to take for each
//! of the network packets in transit.
//!
//! This is done by invoking [`Firewall::resolve_packet`], which will answer with the
//! action to take for the supplied packet.
//!
//! ```
//! use nullnet_firewall::{Firewall, FirewallDirection, FirewallAction};
//!
//! // build the firewall from the rules in a file
//! let mut firewall = Firewall::new();
//! firewall.set_rules("./samples/firewall.txt").unwrap();
//!
//! // here we suppose to have an incoming packet to match against the firewall
//! let packet = [/* ... */];
//!
//! // determine action for the packet
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
//! its rules can be [updated](Firewall::set_rules),
//! and the default [input policy](Firewall::policy_in) and
//! [output policy](Firewall::policy_out) can
//! be overridden for packets that don't match any of the firewall rules.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

pub use crate::data_link::DataLink;
use crate::fields::fields::Fields;
use crate::fields::net_header::{get_dest, get_proto, get_source};
use crate::fields::transport_header::{get_dport, get_icmp_type, get_sport};
pub use crate::firewall_action::FirewallAction;
pub use crate::firewall_direction::FirewallDirection;
pub use crate::firewall_error::FirewallError;
use crate::firewall_rule::FirewallRule;
pub use crate::log_level::LogLevel;
use crate::logs::log_entry::LogEntry;
use crate::logs::logger::log;

mod data_link;
mod fields;
mod firewall_action;
mod firewall_direction;
mod firewall_error;
mod firewall_option;
mod firewall_rule;
mod log_level;
mod logs;
mod utils;

/// Object embedding a collection of firewall rules and policies to determine
/// the action to be taken for a given network packet.
///
/// A new `Firewall` can be created from a textual file listing a set of rules.
pub struct Firewall {
    rules: Vec<FirewallRule>,
    enabled: bool,
    policy_in: FirewallAction,
    policy_out: FirewallAction,
    tx: Sender<LogEntry>,
    data_link: DataLink,
    log_level: LogLevel,
}

impl Firewall {
    const COMMENT: char = '#';

    /// Instantiates a new [`Firewall`] object.
    ///
    /// The newly instantiated firewall has no rules defined by default;
    /// use [`Firewall::set_rules`] to load the rules definition from a file.
    ///
    /// # Panics
    ///
    /// Will panic if the logger routine of the firewall can't be spawned some reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::Firewall;
    ///
    /// let firewall = Firewall::new();
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    /// let mut firewall = Firewall::new();
    /// firewall.set_rules("./samples/firewall.txt").unwrap();
    ///
    /// // here we suppose to have an incoming packet to match against the firewall
    /// let packet = [/* ... */];
    ///
    /// // determine action for packet
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

        let (mut action_opt, mut log_level_opt) = (None, None);

        // structure the packet as a set of relevant fields
        let fields = Fields::new(packet, self.data_link);

        // determine action for packet
        for rule in &self.rules {
            if rule.matches_packet(&fields, &direction) {
                if rule.quick {
                    (action_opt, log_level_opt) = rule.get_match_info();
                    break;
                } else if action_opt.is_none() {
                    (action_opt, log_level_opt) = rule.get_match_info();
                }
            }
        }

        let action = action_opt.unwrap_or(match direction {
            FirewallDirection::IN => self.policy_in,
            FirewallDirection::OUT => self.policy_out,
        });
        let log_level = log_level_opt.unwrap_or(self.log_level);

        if log_level != LogLevel::Off {
            // send the log entry to the logger thread
            self.tx
                .send(LogEntry::new(&fields, direction, action, log_level))
                .expect("the firewall logger routine aborted");
        }

        action
    }

    /// Sets the rules of a [`Firewall`].
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
    /// let mut firewall = Firewall::new();
    ///
    /// firewall.set_rules("./samples/firewall_for_tests_1.txt").unwrap();
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
    pub fn set_rules(&mut self, file_path: &str) -> Result<(), FirewallError> {
        let mut rules = Vec::new();
        let file = File::open(file_path).unwrap();

        for (l, firewall_rule_str_result) in BufReader::new(file).lines().enumerate() {
            let Ok(firewall_rule_str_raw) = firewall_rule_str_result else {
                continue;
            };
            let firewall_rule_str = firewall_rule_str_raw.trim();
            if !firewall_rule_str.starts_with(Self::COMMENT) && !firewall_rule_str.is_empty() {
                rules.push(FirewallRule::new(l + 1, firewall_rule_str)?);
            }
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
    /// let mut firewall = Firewall::new();
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
    /// let mut firewall = Firewall::new();
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
    /// let mut firewall = Firewall::new();
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
    /// let mut firewall = Firewall::new();
    ///
    /// // set the firewall output policy
    /// firewall.policy_out(FirewallAction::ACCEPT);
    /// ```
    pub fn policy_out(&mut self, policy: FirewallAction) {
        self.policy_out = policy;
    }

    /// Sets the [`DataLink`] type for an existing [`Firewall`].
    ///
    /// As default, a firewall will try to parse packets considering them Ethernet frames; if different kinds of packets
    /// want to be inspected, it's necessary to set the corresponding data link type via this method.
    ///
    /// # Arguments
    ///
    /// * `data_link` - The data link type that'll be used to parse packets.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::{DataLink, Firewall};
    ///
    /// let mut firewall = Firewall::new();
    ///
    /// // let the firewall know that submitted packets start with an IP header
    /// firewall.data_link(DataLink::RawIP);
    /// ```
    pub fn data_link(&mut self, data_link: DataLink) {
        self.data_link = data_link;
    }

    /// Changes the default logging strategy of the firewall.
    ///
    /// By default packets are printed in stdout and are logged into a DB; this method allows to change this behaviour.
    ///
    /// # Arguments
    ///
    /// * `log_level` - Default logging strategy to use for the firewall.
    ///
    /// # Examples
    ///
    /// ```
    /// use nullnet_firewall::{Firewall, LogLevel};
    ///
    /// let mut firewall = Firewall::new();
    ///
    /// // disable logging
    /// firewall.log_level(LogLevel::Off);
    /// ```
    pub fn log_level(&mut self, log_level: LogLevel) {
        self.log_level = log_level;
    }
}

impl Default for Firewall {
    fn default() -> Self {
        let (tx, rx): (Sender<LogEntry>, Receiver<LogEntry>) = mpsc::channel();
        thread::Builder::new()
            .name("logger".to_string())
            .spawn(move || {
                log(&rx);
            })
            .unwrap();

        Firewall {
            rules: Vec::new(),
            enabled: true,
            policy_in: FirewallAction::default(),
            policy_out: FirewallAction::default(),
            tx,
            data_link: DataLink::default(),
            log_level: LogLevel::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};

    use crate::log_level::LogLevel;
    use crate::utils::raw_packets::test_packets::{
        ARP_PACKET, ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET,
    };
    use crate::{DataLink, Firewall, LogEntry};
    use crate::{FirewallAction, FirewallDirection, FirewallRule};

    const TEST_FILE_1: &str = "./samples/firewall_for_tests_1.txt";
    const TEST_FILE_2: &str = "./samples/firewall_for_tests_2.txt";
    const TEST_FILE_3: &str = "./samples/firewall_for_tests_3.txt";

    fn get_error_file_path(name: &str) -> String {
        format!("./samples/firewall_for_tests_error_{name}.txt")
    }

    #[test]
    fn test_new_firewall_from_file_1() {
        let rules = vec![
            FirewallRule::new(1,"OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080").unwrap(),
            FirewallRule::new(2,"OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new(3, "+ OUT DENY --source 192.168.200.135-192.168.200.140 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new(4,"OUT REJECT --source 192.168.200.135 --sport 6750:6800,8080 --dest 192.168.200.21 --dport 1,2,2000").unwrap(),
            FirewallRule::new(5,"IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8").unwrap(),
            FirewallRule::new(6,"+ IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8").unwrap(),
            FirewallRule::new(7,"IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 9").unwrap(),
            FirewallRule::new(8,"IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 58 --icmp-type 8").unwrap(),
            FirewallRule::new(9,"OUT REJECT").unwrap(),
            FirewallRule::new(10,"IN ACCEPT --log-level console").unwrap(),
        ];

        let mut firewall_from_file = Firewall::new();
        firewall_from_file.set_rules(TEST_FILE_1).unwrap();

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
        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_1).unwrap();
        firewall.policy_in(FirewallAction::DENY);
        firewall.policy_out(FirewallAction::ACCEPT);

        assert_eq!(firewall.data_link, DataLink::Ethernet);

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
    fn test_firewall_determine_action_for_packets_file_1_with_data_link_raw_ip() {
        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_1).unwrap();
        firewall.data_link(DataLink::RawIP);
        firewall.policy_in(FirewallAction::DENY);
        firewall.policy_out(FirewallAction::ACCEPT);

        assert_eq!(firewall.data_link, DataLink::RawIP);

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET[14..], FirewallDirection::IN),
            FirewallAction::ACCEPT
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET[14..], FirewallDirection::OUT),
            FirewallAction::DENY
        );

        // icmp packet
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET[14..], FirewallDirection::IN),
            FirewallAction::REJECT
        );
        assert_eq!(
            firewall.resolve_packet(&ICMP_PACKET[14..], FirewallDirection::OUT),
            FirewallAction::REJECT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_file_2() {
        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_2).unwrap();
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
        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_3).unwrap();

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
    fn test_firewall_determine_action_for_packets_file_3_with_data_link_raw_ip() {
        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_3).unwrap();
        firewall.data_link(DataLink::RawIP);

        // ipv6 packet
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET[14..], FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET[14..], FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET[14..], FirewallDirection::IN),
            FirewallAction::default()
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET[14..], FirewallDirection::OUT),
            FirewallAction::default()
        );

        // change default policies
        firewall.policy_in(FirewallAction::DENY);
        firewall.policy_out(FirewallAction::REJECT);

        // ipv6 packet
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET[14..], FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&UDP_IPV6_PACKET[14..], FirewallDirection::OUT),
            FirewallAction::ACCEPT
        );

        // tcp packet
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET[14..], FirewallDirection::IN),
            FirewallAction::DENY
        );
        assert_eq!(
            firewall.resolve_packet(&TCP_PACKET[14..], FirewallDirection::OUT),
            FirewallAction::REJECT
        );
    }

    #[test]
    fn test_firewall_determine_action_for_packets_while_disabled() {
        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_1).unwrap();
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
            data_link: Default::default(),
            log_level: LogLevel::All,
        };

        let rules_1 = vec![
            // no quick, first match wins
            FirewallRule::new(
                1,
                "OUT DENY --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                2,
                "OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                3,
                "OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080",
            )
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
            FirewallRule::new(
                1,
                "+ OUT DENY --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                2,
                "OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                3,
                "OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080",
            )
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
            FirewallRule::new(
                1,
                "OUT DENY --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                2,
                "OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                3,
                "+ OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080",
            )
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
            FirewallRule::new(
                1,
                "OUT DENY --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                2,
                "+ OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                3,
                "+ OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080",
            )
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
            FirewallRule::new(
                1,
                "+ OUT DENY --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                2,
                "+ OUT ACCEPT --source 192.168.200.135 --sport 6700:6800,8080",
            )
            .unwrap(),
            FirewallRule::new(
                3,
                "+ OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080",
            )
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

    #[test]
    fn test_update_firewall_rules() {
        let rules_before_update = vec![
            FirewallRule::new(1,"OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080").unwrap(),
            FirewallRule::new(2,"OUT REJECT --source 192.168.200.135 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new(3,"+ OUT DENY --source 192.168.200.135-192.168.200.140 --sport 6700:6800,8080 --dport 1,2,2000").unwrap(),
            FirewallRule::new(4,"OUT REJECT --source 192.168.200.135 --sport 6750:6800,8080 --dest 192.168.200.21 --dport 1,2,2000").unwrap(),
            FirewallRule::new(5,"IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8").unwrap(),
            FirewallRule::new(6,"+ IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8").unwrap(),
            FirewallRule::new(7,"IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 9").unwrap(),
            FirewallRule::new(8,"IN ACCEPT --source 2.1.1.2 --dest 2.1.1.1 --proto 58 --icmp-type 8").unwrap(),
            FirewallRule::new(9,"OUT REJECT").unwrap(),
            FirewallRule::new(10,"IN ACCEPT --log-level console").unwrap(),
        ];

        let rules_after_update = vec![
            FirewallRule::new(1, "OUT REJECT --dest 3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:08dd --sport 545:560,43,53").unwrap(),
            FirewallRule::new(2,"+ OUT ACCEPT --dest 3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:08dd --sport 545:560,43,53").unwrap(),
            FirewallRule::new(3,"OUT DENY --dest 3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:08dd --proto 17 --sport 545:560,43,53 --dport 2396").unwrap(),
            FirewallRule::new(4,"OUT REJECT --dest 3ffe:507:0:1:200:86ff:fe05:800-3ffe:507:0:1:200:86ff:fe05:08dd --proto 17 --sport 545:560,43,53 --dport 2395").unwrap(),
            FirewallRule::new(5,"IN DENY --log-level db --sport 40:49,53").unwrap(),
            FirewallRule::new(6,"IN REJECT --sport 40:49,53 --source 3ffe:501:4819::41,3ffe:501:4819::42").unwrap(),
        ];

        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_1).unwrap();
        assert_eq!(firewall.rules, rules_before_update);
        assert!(firewall.enabled);
        assert_eq!(firewall.policy_in, FirewallAction::ACCEPT);
        assert_eq!(firewall.policy_out, FirewallAction::ACCEPT);

        // update the rules
        firewall.set_rules(TEST_FILE_3).unwrap();

        assert_eq!(firewall.rules, rules_after_update);
        assert!(firewall.enabled);
        assert_eq!(firewall.policy_in, FirewallAction::ACCEPT);
        assert_eq!(firewall.policy_out, FirewallAction::ACCEPT);
    }

    #[test]
    fn test_set_log_level() {
        let mut firewall = Firewall::new();
        firewall.set_rules(TEST_FILE_1).unwrap();
        assert_eq!(firewall.log_level, LogLevel::All);
        firewall.log_level(LogLevel::Db);
        assert_eq!(firewall.log_level, LogLevel::Db);
        firewall.log_level(LogLevel::Console);
        assert_eq!(firewall.log_level, LogLevel::Console);
        firewall.log_level(LogLevel::Off);
        assert_eq!(firewall.log_level, LogLevel::Off);
        firewall.log_level(LogLevel::All);
        assert_eq!(firewall.log_level, LogLevel::All);
    }

    #[test]
    fn test_file_error_invalid_dport_value() {
        let path = &get_error_file_path("invalid_dport_value");
        let expected = String::from(
            "Firewall error at line 12 - incorrect value for option '--dport 8.8.8.8'",
        );

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_sport_value() {
        let path = &get_error_file_path("invalid_sport_value");
        let expected =
            String::from("Firewall error at line 1 - incorrect value for option '--sport 70000'");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_dest_value() {
        let path = &get_error_file_path("invalid_dest_value");
        let expected =
            String::from("Firewall error at line 18 - incorrect value for option '--dest 8080'");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_source_value() {
        let path = &get_error_file_path("invalid_source_value");
        let expected = String::from(
            "Firewall error at line 9 - incorrect value for option '--source 8.8.8.8.7'",
        );

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_icmp_type_value() {
        let path = &get_error_file_path("invalid_icmp_type_value");
        let expected = String::from(
            "Firewall error at line 7 - incorrect value for option '--icmp-type ciao'",
        );

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_protocol_value() {
        let path = &get_error_file_path("invalid_protocol_value");
        let expected =
            String::from("Firewall error at line 101 - incorrect value for option '--proto -58'");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_direction() {
        let path = &get_error_file_path("invalid_direction");
        let expected = String::from("Firewall error at line 4 - incorrect direction 'this'");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_action() {
        let path = &get_error_file_path("invalid_action");
        let expected =
            String::from("Firewall error at line 1 - incorrect action 'DROPTHISPACKETOMG'");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_unknown_option() {
        let path = &get_error_file_path("unknown_option");
        let expected =
            String::from("Firewall error at line 3 - the specified option '-dest' doesn't exist");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_not_enough_arguments() {
        let path = &get_error_file_path("not_enough_arguments");
        let expected =
            String::from("Firewall error at line 8 - not enough arguments supplied for rule");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_empty_option() {
        let path = &get_error_file_path("empty_option");
        let expected =
            String::from("Firewall error at line 20 - the supplied option '--sport' is empty");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_duplicated_option() {
        let path = &get_error_file_path("duplicated_option");
        let expected = String::from(
            "Firewall error at line 9 - duplicated option '--dport' for the same rule",
        );

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_not_applicable_icmp_type() {
        let path = &get_error_file_path("not_applicable_icmp_type");
        let expected = String::from("Firewall error at line 6 - option '--icmp-type' is valid only if '--proto 1' or '--proto 58' is also specified");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }

    #[test]
    fn test_file_error_invalid_log_level() {
        let path = &get_error_file_path("invalid_log_level");
        let expected =
            String::from("Firewall error at line 4 - incorrect value for option '--log-level DB'");

        assert_eq!(
            Firewall::new().set_rules(path).unwrap_err().to_string(),
            expected
        );
    }
}
