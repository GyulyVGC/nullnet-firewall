use std::fmt::{Display, Formatter};

use chrono::{DateTime, Local};
use rusqlite::types::ToSqlOutput;
use rusqlite::ToSql;

#[derive(PartialEq, Debug)]
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
        Ok(self.to_string().into())
    }
}

impl Display for LogTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::types::ToSqlOutput;
    use rusqlite::types::Value::Text;
    use rusqlite::ToSql;

    use crate::logs::log_timestamp::LogTimestamp;

    #[test]
    fn test_log_timestamp_from_date_time() {
        let time = chrono::offset::Local::now();
        assert_eq!(
            LogTimestamp::from_date_time(time),
            LogTimestamp { timestamp: time }
        );
    }

    #[test]
    fn test_log_timestamp_to_sql() {
        let time = chrono::offset::Local::now();
        assert_eq!(
            LogTimestamp::to_sql(&LogTimestamp { timestamp: time }),
            Ok(ToSqlOutput::Owned(Text(time.to_string())))
        );
    }
}
