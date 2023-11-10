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

#[cfg(test)]
mod tests {
    use crate::{FirewallDirection, FirewallError};
    use std::str::FromStr;

    #[test]
    fn test_firewall_directions_from_str() {
        assert_eq!(FirewallDirection::from_str("IN"), Ok(FirewallDirection::IN));
        assert_eq!(
            FirewallDirection::from_str("OUT"),
            Ok(FirewallDirection::OUT)
        );

        let err = FirewallDirection::from_str("UNDER").unwrap_err();
        assert_eq!(err, FirewallError::InvalidDirection("UNDER".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error - incorrect direction 'UNDER'"
        );
    }
}
