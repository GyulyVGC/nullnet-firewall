use std::fmt::{Display, Formatter};
use std::str::FromStr;
use crate::FirewallError;

#[derive(Debug, Eq, PartialEq)]
pub enum FirewallDirection {
    In,
    Out,
}

impl Display for FirewallDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            FirewallDirection::In => "IN",
            FirewallDirection::Out => "OUT",
        };

        write!(f, "{str}")
    }
}

impl FromStr for FirewallDirection {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "IN" => Ok(Self::In),
            "OUT" => Ok(Self::Out),
            _ => Err(FirewallError::InvalidDirection),
        }
    }
}