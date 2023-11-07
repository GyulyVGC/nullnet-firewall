use std::fmt::{Display, Formatter};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum FirewallError {
    InvalidDportValue,
    InvalidSportValue,
    InvalidDestValue,
    InvalidSourceValue,
    InvalidIcmpTypeValue,
    InvalidProtocolValue,
    InvalidDirection,
    InvalidAction,
    UnknownOption,
    NotEnoughArguments,
    EmptyOption,
    DuplicatedOption,
    NotApplicableIcmpType,
}

impl Display for FirewallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_info = match self {
            FirewallError::InvalidDportValue => "incorrect value for option --dport",
            FirewallError::InvalidSportValue => "incorrect value for option --sport",
            FirewallError::InvalidDestValue => "incorrect value for option --dest",
            FirewallError::InvalidSourceValue => "incorrect value for option --source",
            FirewallError::InvalidIcmpTypeValue => "incorrect value for option --icmp-type",
            FirewallError::InvalidProtocolValue => "incorrect value for option --protocol",
            FirewallError::InvalidDirection => "incorrect direction",
            FirewallError::InvalidAction => "incorrect action",
            FirewallError::UnknownOption => "the specified option doesn't exists",
            FirewallError::NotEnoughArguments => "not enough arguments supplied for rule",
            FirewallError::EmptyOption => "each option must have a value",
            FirewallError::DuplicatedOption => "duplicated option for the same rule",
            FirewallError::NotApplicableIcmpType => {
                "option --icmp-type is only valid for protocol numbers 1 or 58"
            }
        };

        write!(f, "Firewall error - {err_info}")
    }
}
