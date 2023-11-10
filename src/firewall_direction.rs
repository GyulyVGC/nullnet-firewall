use std::str::FromStr;

use crate::FirewallError;

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
