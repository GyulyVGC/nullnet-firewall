use crate::FirewallError;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LogLevel {
    Off,
    Db,
    Console,
    All,
}

impl LogLevel {
    pub(crate) fn from_str_with_line(l: usize, s: &str) -> Result<Self, FirewallError> {
        match s {
            "off" => Ok(Self::Off),
            "db" => Ok(Self::Db),
            "console" => Ok(Self::Console),
            "all" => Ok(Self::All),
            x => Err(FirewallError::InvalidLogLevel(l, x.to_owned())),
        }
    }
}
