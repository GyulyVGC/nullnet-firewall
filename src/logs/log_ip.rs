use crate::logs::log_entry::format_ip_address;
use rusqlite::types::ToSqlOutput;
use rusqlite::ToSql;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

pub(crate) struct LogIp {
    ip: IpAddr,
}

impl LogIp {
    pub(crate) fn from_ip_addr(ip_addr: Option<IpAddr>) -> Option<LogIp> {
        ip_addr.map(|ip| LogIp { ip })
    }
}

impl ToSql for LogIp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let formatted = format_ip_address(self.ip);
        Ok(formatted.into())
    }
}

impl Display for LogIp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format_ip_address(self.ip))
    }
}
