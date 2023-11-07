use crate::firewall_option::FirewallOption;
use std::fmt::{Display, Formatter};

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FirewallError {
    InvalidDportValue(String),
    InvalidSportValue(String),
    InvalidDestValue(String),
    InvalidSourceValue(String),
    InvalidIcmpTypeValue(String),
    InvalidProtocolValue(String),
    InvalidDirection(String),
    InvalidAction(String),
    UnknownOption(String),
    EmptyOption(String),
    DuplicatedOption(String),
    NotEnoughArguments,
    NotApplicableIcmpType,
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
                    "option '{}' is only valid if '{} 1' or '{} 58' is also specified",
                    FirewallOption::ICMPTYPE,
                    FirewallOption::PROTO,
                    FirewallOption::PROTO
                )
            }
        };

        write!(f, "Firewall error - {err_info}")
    }
}
