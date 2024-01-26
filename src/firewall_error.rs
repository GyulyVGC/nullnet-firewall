use std::fmt::{Display, Formatter};

use crate::firewall_option::FirewallOption;

/// Error that may arise as a consequence of an invalid firewall specification.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FirewallError {
    /// The value supplied for the option `--dport` is invalid.
    InvalidDportValue(usize, String),
    /// The value supplied for the option `--sport` is invalid.
    InvalidSportValue(usize, String),
    /// The value supplied for the option `--dest` is invalid.
    InvalidDestValue(usize, String),
    /// The value supplied for the option `--source` is invalid.
    InvalidSourceValue(usize, String),
    /// The value supplied for the option `--icmp-type` is invalid.
    InvalidIcmpTypeValue(usize, String),
    /// The value supplied for the option `--proto` is invalid.
    InvalidProtocolValue(usize, String),
    /// An invalid direction has been specified for a firewall rule.
    InvalidDirection(usize, String),
    /// An invalid action has been specified for a firewall rule.
    InvalidAction(usize, String),
    /// An invalid log level has been specified for a firewall rule.
    InvalidLogLevel(usize, String),
    /// An unknown option has been specified for a firewall rule.
    UnknownOption(usize, String),
    /// An empty option has been specified for a firewall rule.
    EmptyOption(usize, String),
    /// The same option has been specified multiple times for the same firewall rule.
    DuplicatedOption(usize, String),
    /// Not enough arguments have been specified for a firewall rule.
    NotEnoughArguments(usize),
    /// The option `--icmp-type` is valid only if `--proto 1` or `--proto 58` is also specified.
    NotApplicableIcmpType(usize),
}

impl Display for FirewallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (l, err_info) = match self {
            FirewallError::InvalidDportValue(l, val) => (
                l,
                format!(
                    "incorrect value for option '{} {val}'",
                    FirewallOption::DPORT
                ),
            ),
            FirewallError::InvalidSportValue(l, val) => (
                l,
                format!(
                    "incorrect value for option '{} {val}'",
                    FirewallOption::SPORT
                ),
            ),
            FirewallError::InvalidDestValue(l, val) => (
                l,
                format!(
                    "incorrect value for option '{} {val}'",
                    FirewallOption::DEST
                ),
            ),
            FirewallError::InvalidSourceValue(l, val) => (
                l,
                format!(
                    "incorrect value for option '{} {val}'",
                    FirewallOption::SOURCE
                ),
            ),
            FirewallError::InvalidIcmpTypeValue(l, val) => (
                l,
                format!(
                    "incorrect value for option '{} {val}'",
                    FirewallOption::ICMPTYPE
                ),
            ),
            FirewallError::InvalidProtocolValue(l, val) => (
                l,
                format!(
                    "incorrect value for option '{} {val}'",
                    FirewallOption::PROTO
                ),
            ),
            FirewallError::InvalidDirection(l, direction) => {
                (l, format!("incorrect direction '{direction}'"))
            }
            FirewallError::InvalidAction(l, action) => (l, format!("incorrect action '{action}'")),
            FirewallError::UnknownOption(l, opt) => {
                (l, format!("the specified option '{opt}' doesn't exist"))
            }
            FirewallError::NotEnoughArguments(l) => {
                (l, "not enough arguments supplied for rule".to_string())
            }
            FirewallError::EmptyOption(l, opt) => {
                (l, format!("the supplied option '{opt}' is empty"))
            }
            FirewallError::DuplicatedOption(l, opt) => {
                (l, format!("duplicated option '{opt}' for the same rule"))
            }
            FirewallError::NotApplicableIcmpType(l) => (
                l,
                format!(
                    "option '{}' is valid only if '{} 1' or '{} 58' is also specified",
                    FirewallOption::ICMPTYPE,
                    FirewallOption::PROTO,
                    FirewallOption::PROTO
                ),
            ),
            FirewallError::InvalidLogLevel(l, log_level) => {
                (l, format!("incorrect log level '{log_level}'"))
            }
        };

        write!(f, "Firewall error at line {l} - {err_info}")
    }
}
