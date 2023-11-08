use crate::FirewallError;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Direction of a firewall rule.
///
/// Each firewall rule is associated to a given direction.
#[derive(Debug, Eq, PartialEq)]
pub enum FirewallDirection {
    /// Refers to incoming network traffic.
    IN,
    /// Refers to outgoing network traffic.
    OUT,
}

impl Display for FirewallDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            FirewallDirection::IN => "IN",
            FirewallDirection::OUT => "OUT",
        };

        write!(f, "{str}")
    }
}

impl FromStr for FirewallDirection {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "IN" => Ok(Self::IN),
            "OUT" => Ok(Self::OUT),
            x => Err(FirewallError::InvalidDirection(x.to_owned())),
        }
    }
}
