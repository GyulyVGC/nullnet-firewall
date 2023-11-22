use std::fmt::{Display, Formatter};
use std::str::FromStr;

use rusqlite::types::ToSqlOutput;
use rusqlite::ToSql;

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

impl Display for FirewallAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ToSql for FirewallAction {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rusqlite::types::ToSqlOutput;
    use rusqlite::types::Value::Text;
    use rusqlite::ToSql;

    use crate::{FirewallAction, FirewallError};

    #[test]
    fn test_firewall_actions_from_str() {
        assert_eq!(
            FirewallAction::from_str("ACCEPT"),
            Ok(FirewallAction::ACCEPT)
        );
        assert_eq!(FirewallAction::from_str("DENY"), Ok(FirewallAction::DENY));
        assert_eq!(
            FirewallAction::from_str("REJECT"),
            Ok(FirewallAction::REJECT)
        );

        let err = FirewallAction::from_str("DROP").unwrap_err();
        assert_eq!(err, FirewallError::InvalidAction("DROP".to_owned()));
        assert_eq!(err.to_string(), "Firewall error - incorrect action 'DROP'");
    }

    #[test]
    fn test_firewall_actions_to_sql() {
        assert_eq!(
            FirewallAction::to_sql(&FirewallAction::ACCEPT),
            Ok(ToSqlOutput::Owned(Text("ACCEPT".to_string())))
        );

        assert_eq!(
            FirewallAction::to_sql(&FirewallAction::DENY),
            Ok(ToSqlOutput::Owned(Text("DENY".to_string())))
        );

        assert_eq!(
            FirewallAction::to_sql(&FirewallAction::REJECT),
            Ok(ToSqlOutput::Owned(Text("REJECT".to_string())))
        );
    }
}
