use std::str::FromStr;

use crate::FirewallError;

/// Action dictated by a firewall rule.
///
/// Each firewall rule is associated to a given action.
#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub enum FirewallAction {
    /// Allows traffic that matches the rule to pass.
    #[default]
    ACCEPT,
    /// Silently blocks traffic that matches the rule.
    DENY,
    /// Blocks traffic that matches the rule.
    ///
    /// An *ICMP Destination Unreachable* message should be sent back to the traffic source.
    REJECT,
}

impl FromStr for FirewallAction {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ACCEPT" => Ok(Self::ACCEPT),
            "DENY" => Ok(Self::DENY),
            "REJECT" => Ok(Self::REJECT),
            x => Err(FirewallError::InvalidAction(x.to_owned())),
        }
    }
}
