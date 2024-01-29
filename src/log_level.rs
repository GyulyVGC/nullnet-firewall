use crate::FirewallError;

/// Logging strategy to use.
///
/// It can be set either for specific firewall rules via the `--log-level` option
/// or globally for the firewall.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Default)]
pub enum LogLevel {
    /// Traffic won't be logged at all.
    Off,
    /// Traffic will be logged into a database.
    Db,
    /// Traffic will be logged in standard output.
    Console,
    /// Traffic will be logged both in a database and in standard output.
    #[default]
    All,
}

impl LogLevel {
    pub(crate) fn from_str_with_line(l: usize, s: &str) -> Result<Self, FirewallError> {
        match s {
            "off" => Ok(Self::Off),
            "db" => Ok(Self::Db),
            "console" => Ok(Self::Console),
            "all" => Ok(Self::All),
            x => Err(FirewallError::InvalidLogLevelValue(l, x.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{FirewallError, LogLevel};

    #[test]
    fn test_log_levels_from_str() {
        assert_eq!(LogLevel::from_str_with_line(1, "off"), Ok(LogLevel::Off));
        assert_eq!(
            LogLevel::from_str_with_line(2, "console"),
            Ok(LogLevel::Console)
        );
        assert_eq!(LogLevel::from_str_with_line(3, "db"), Ok(LogLevel::Db));
        assert_eq!(LogLevel::from_str_with_line(28, "all"), Ok(LogLevel::All));

        let err = LogLevel::from_str_with_line(28, "none").unwrap_err();
        assert_eq!(
            err,
            FirewallError::InvalidLogLevelValue(28, "none".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "Firewall error at line 28 - incorrect value for option '--log-level none'"
        );
    }
}
