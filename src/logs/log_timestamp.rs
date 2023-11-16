use chrono::{DateTime, Local};
use rusqlite::types::ToSqlOutput;
use rusqlite::ToSql;
use std::fmt::{Display, Formatter};

pub(crate) struct LogTimestamp {
    timestamp: DateTime<Local>,
}

impl LogTimestamp {
    pub(crate) fn from_date_time(date_time: DateTime<Local>) -> LogTimestamp {
        LogTimestamp {
            timestamp: date_time,
        }
    }
}

impl ToSql for LogTimestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.timestamp.to_string().into())
    }
}

impl Display for LogTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.timestamp)
    }
}
