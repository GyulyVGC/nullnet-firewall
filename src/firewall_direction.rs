use std::fmt::{Display, Formatter};

use rusqlite::types::ToSqlOutput;
use rusqlite::ToSql;

use crate::FirewallError;

/// Direction of a firewall rule.
///
/// Each firewall rule is associated to a given direction.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FirewallDirection {
    /// Refers to incoming network traffic.
    IN,
    /// Refers to outgoing network traffic.
    OUT,
}

impl FirewallDirection {
    pub(crate) fn from_str_with_line(l: usize, s: &str) -> Result<Self, FirewallError> {
        match s {
            "IN" => Ok(Self::IN),
            "OUT" => Ok(Self::OUT),
            x => Err(FirewallError::InvalidDirection(l, x.to_owned())),
        }
    }
}

impl Display for FirewallDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ToSql for FirewallDirection {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::types::ToSqlOutput;
    use rusqlite::types::Value::Text;
    use rusqlite::ToSql;

    use crate::{FirewallDirection, FirewallError};

    #[test]
    fn test_firewall_directions_from_str() {
        assert_eq!(
            FirewallDirection::from_str_with_line(1, "IN"),
            Ok(FirewallDirection::IN)
        );
        assert_eq!(
            FirewallDirection::from_str_with_line(1, "OUT"),
            Ok(FirewallDirection::OUT)
        );

        let err = FirewallDirection::from_str_with_line(3, "UNDER").unwrap_err();
        assert_eq!(err, FirewallError::InvalidDirection(3, "UNDER".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 3 - incorrect direction 'UNDER'"
        );
    }

    #[test]
    fn test_firewall_direction_to_sql() {
        assert_eq!(
            FirewallDirection::to_sql(&FirewallDirection::IN),
            Ok(ToSqlOutput::Owned(Text("IN".to_string())))
        );

        assert_eq!(
            FirewallDirection::to_sql(&FirewallDirection::OUT),
            Ok(ToSqlOutput::Owned(Text("OUT".to_string())))
        );
    }
}
