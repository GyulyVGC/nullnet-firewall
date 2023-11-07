use crate::FirewallError;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub enum FirewallAction {
    #[default]
    Accept,
    Deny,
    Reject,
}

impl Display for FirewallAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            FirewallAction::Accept => "ACCEPT",
            FirewallAction::Deny => "DENY",
            FirewallAction::Reject => "REJECT",
        };

        write!(f, "{str}")
    }
}

impl FromStr for FirewallAction {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ACCEPT" => Ok(Self::Accept),
            "DENY" => Ok(Self::Deny),
            "REJECT" => Ok(Self::Reject),
            _ => Err(FirewallError::InvalidAction),
        }
    }
}
