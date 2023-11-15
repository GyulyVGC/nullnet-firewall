use std::fmt::{Display, Formatter};

use crate::firewall_option::FirewallOption;

/// Error that may arise as a consequence of an invalid firewall specification.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FirewallError {
    /// The value supplied for the option `--dport` is invalid.
    InvalidDportValue(String),
    /// The value supplied for the option `--sport` is invalid.
    InvalidSportValue(String),
    /// The value supplied for the option `--dest` is invalid.
    InvalidDestValue(String),
    /// The value supplied for the option `--source` is invalid.
    InvalidSourceValue(String),
    /// The value supplied for the option `--icmp-type` is invalid.
    InvalidIcmpTypeValue(String),
    /// The value supplied for the option `--proto` is invalid.
    InvalidProtocolValue(String),
    /// An invalid direction has been specified for a firewall rule.
    InvalidDirection(String),
    /// An invalid action has been specified for a firewall rule.
    InvalidAction(String),
    /// An unknown option has been specified for a firewall rule.
    UnknownOption(String),
    /// An empty option has been specified for a firewall rule.
    EmptyOption(String),
    /// The same option has been specified multiple times for the same firewall rule.
    DuplicatedOption(String),
    /// Not enough arguments have been specified for a firewall rule.
    NotEnoughArguments,
    /// The option `--icmp-type` is valid only if `--proto 1` or `--proto 58` is also specified.
    NotApplicableIcmpType,
    /// Logger error
    LoggerAborted,
}

impl Display for FirewallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_info = match self {
            FirewallError::InvalidDportValue(val) => format!(
                "incorrect value for option '{} {val}'",
                FirewallOption::DPORT
            ),
            FirewallError::InvalidSportValue(val) => format!(
                "incorrect value for option '{} {val}'",
                FirewallOption::SPORT
            ),
            FirewallError::InvalidDestValue(val) => format!(
                "incorrect value for option '{} {val}'",
                FirewallOption::DEST
            ),
            FirewallError::InvalidSourceValue(val) => format!(
                "incorrect value for option '{} {val}'",
                FirewallOption::SOURCE
            ),
            FirewallError::InvalidIcmpTypeValue(val) => format!(
                "incorrect value for option '{} {val}'",
                FirewallOption::ICMPTYPE
            ),
            FirewallError::InvalidProtocolValue(val) => format!(
                "incorrect value for option '{} {val}'",
                FirewallOption::PROTO
            ),
            FirewallError::InvalidDirection(direction) => {
                format!("incorrect direction '{direction}'")
            }
            FirewallError::InvalidAction(action) => format!("incorrect action '{action}'"),
            FirewallError::UnknownOption(opt) => {
                format!("the specified option '{opt}' doesn't exist")
            }
            FirewallError::NotEnoughArguments => {
                "not enough arguments supplied for rule".to_string()
            }
            FirewallError::EmptyOption(opt) => format!("the supplied option '{opt}' is empty"),
            FirewallError::DuplicatedOption(opt) => {
                format!("duplicated option '{opt}' for the same rule")
            }
            FirewallError::NotApplicableIcmpType => {
                format!(
                    "option '{}' is valid only if '{} 1' or '{} 58' is also specified",
                    FirewallOption::ICMPTYPE,
                    FirewallOption::PROTO,
                    FirewallOption::PROTO
                )
            }
            FirewallError::LoggerAborted => "a problem occurred in the logger routine".to_string(),
        };

        write!(f, "Firewall error - {err_info}")
    }
}
