use std::fmt::{Display, Formatter};
use std::str::FromStr;

use chrono::{DateTime, Local, SecondsFormat};
use rusqlite::ToSql;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};

#[derive(PartialEq, Debug, Clone)]
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

impl FromSql for LogTimestamp {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        FromSqlResult::Ok(LogTimestamp {
            timestamp: DateTime::from_str(value.as_str()?)
                .map_err(|_| FromSqlError::InvalidType)?,
        })
    }
}

impl Display for LogTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.timestamp.to_rfc3339_opts(SecondsFormat::Secs, false)
        )
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::ToSql;
    use rusqlite::types::ToSqlOutput;
    use rusqlite::types::Value::Text;

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
        let log_timestamp = LogTimestamp { timestamp: time };
        assert_eq!(
            LogTimestamp::to_sql(&log_timestamp),
            Ok(ToSqlOutput::Owned(Text(log_timestamp.to_string())))
        );
    }
}
