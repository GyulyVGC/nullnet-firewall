use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

use rusqlite::ToSql;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};

#[derive(PartialEq, Debug, Clone)]
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
        Ok(self.to_string().into())
    }
}

impl FromSql for LogIp {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        FromSqlResult::Ok(LogIp {
            ip: IpAddr::from_str(value.as_str()?).map_err(|_| FromSqlError::InvalidType)?,
        })
    }
}

impl Display for LogIp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use rusqlite::ToSql;
    use rusqlite::types::ToSqlOutput;
    use rusqlite::types::Value::Text;

    use crate::logs::log_ip::LogIp;

    #[test]
    fn test_log_ip_from_ip_addr() {
        assert_eq!(LogIp::from_ip_addr(None), None);

        assert_eq!(
            LogIp::from_ip_addr(Some(IpAddr::from_str("1.2.3.4").unwrap())),
            Some(LogIp {
                ip: IpAddr::from_str("1.2.3.4").unwrap()
            })
        );
    }

    #[test]
    fn test_log_ip_to_sql() {
        assert_eq!(
            LogIp::to_sql(&LogIp {
                ip: IpAddr::from_str("8.8.8.8").unwrap()
            }),
            Ok(ToSqlOutput::Owned(Text("8.8.8.8".to_string())))
        );
    }

    #[test]
    fn test_format_ipv4_address() {
        let result = IpAddr::from_str("192.168.1.1").unwrap().to_string();
        assert_eq!(result, "192.168.1.1".to_string());
    }

    #[test]
    fn test_format_ipv6_address() {
        let result = IpAddr::from_str("2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF")
            .unwrap()
            .to_string();
        assert_eq!(result, "2001:db8:3333:4444:cccc:dddd:eeee:ffff".to_string());
    }

    #[test]
    fn ipv6_simple_test() {
        let result = IpAddr::from([
            255, 10, 10, 255, 255, 10, 10, 255, 255, 10, 10, 255, 255, 10, 10, 255,
        ])
        .to_string();
        assert_eq!(result, "ff0a:aff:ff0a:aff:ff0a:aff:ff0a:aff".to_string());
    }

    #[test]
    fn ipv6_zeros_in_the_middle() {
        let result =
            IpAddr::from([255, 10, 10, 255, 0, 0, 0, 0, 28, 4, 4, 28, 255, 1, 0, 0]).to_string();
        assert_eq!(result, "ff0a:aff::1c04:41c:ff01:0".to_string());
    }

    #[test]
    fn ipv6_leading_zeros() {
        let result =
            IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 28, 4, 4, 28, 255, 1, 0, 10]).to_string();
        assert_eq!(result, "::1c04:41c:ff01:a".to_string());
    }

    #[test]
    fn ipv6_tail_one_after_zeros() {
        let result =
            IpAddr::from([28, 4, 4, 28, 255, 1, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1]).to_string();
        assert_eq!(result, "1c04:41c:ff01:a::1".to_string());
    }

    #[test]
    fn ipv6_tail_zeros() {
        let result =
            IpAddr::from([28, 4, 4, 28, 255, 1, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0]).to_string();
        assert_eq!(result, "1c04:41c:ff01:a::".to_string());
    }

    #[test]
    fn ipv6_multiple_zero_sequences_first_longer() {
        let result = IpAddr::from([32, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1]).to_string();
        assert_eq!(result, "2000::101:0:0:1".to_string());
    }

    #[test]
    fn ipv6_multiple_zero_sequences_first_longer_head() {
        let result = IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1]).to_string();
        assert_eq!(result, "::101:0:0:1".to_string());
    }

    #[test]
    fn ipv6_multiple_zero_sequences_second_longer() {
        let result = IpAddr::from([1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 118]).to_string();
        assert_eq!(result, "100:0:0:1::376".to_string());
    }

    #[test]
    fn ipv6_multiple_zero_sequences_second_longer_tail() {
        let result = IpAddr::from([32, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0]).to_string();
        assert_eq!(result, "2000:0:0:1:101::".to_string());
    }

    #[test]
    fn ipv6_multiple_zero_sequences_equal_length() {
        let result = IpAddr::from([118, 3, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1]).to_string();
        assert_eq!(result, "7603::1:101:0:0:1".to_string());
    }

    #[test]
    fn ipv6_all_zeros() {
        let result = IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string();
        assert_eq!(result, "::".to_string());
    }

    #[test]
    fn ipv6_x_all_zeros() {
        let result = IpAddr::from([161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string();
        assert_eq!(result, "a100::".to_string());
    }

    #[test]
    fn ipv6_all_zeros_x() {
        let result = IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 176]).to_string();
        assert_eq!(result, "::b0".to_string());
    }

    #[test]
    fn ipv6_many_zeros_but_no_compression() {
        let result = IpAddr::from([0, 16, 16, 0, 0, 1, 7, 0, 0, 2, 216, 0, 1, 0, 0, 1]).to_string();
        assert_eq!(result, "10:1000:1:700:2:d800:100:1".to_string());
    }
}
