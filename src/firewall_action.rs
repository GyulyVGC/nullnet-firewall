use std::fmt::{Display, Formatter};

use rusqlite::ToSql;
use rusqlite::types::ToSqlOutput;

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

impl FirewallAction {
    pub(crate) fn from_str_with_line(l: usize, s: &str) -> Result<Self, FirewallError> {
        match s {
            "ACCEPT" => Ok(Self::ACCEPT),
            "DENY" => Ok(Self::DENY),
            "REJECT" => Ok(Self::REJECT),
            x => Err(FirewallError::InvalidAction(l, x.to_owned())),
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
    use rusqlite::ToSql;
    use rusqlite::types::ToSqlOutput;
    use rusqlite::types::Value::Text;

    use crate::{FirewallAction, FirewallError};

    #[test]
    fn test_firewall_actions_from_str() {
        assert_eq!(
            FirewallAction::from_str_with_line(1, "ACCEPT"),
            Ok(FirewallAction::ACCEPT)
        );
        assert_eq!(
            FirewallAction::from_str_with_line(1, "DENY"),
            Ok(FirewallAction::DENY)
        );
        assert_eq!(
            FirewallAction::from_str_with_line(1, "REJECT"),
            Ok(FirewallAction::REJECT)
        );

        let err = FirewallAction::from_str_with_line(28, "DROP").unwrap_err();
        assert_eq!(err, FirewallError::InvalidAction(28, "DROP".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 28 - incorrect action 'DROP'"
        );
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
