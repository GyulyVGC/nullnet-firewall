use crate::logs::log_ip::LogIp;
use crate::logs::log_timestamp::LogTimestamp;
use crate::utils::proto::Proto;
use crate::{Fields, FirewallAction, FirewallDirection};
use std::fmt::{Display, Formatter};

pub(crate) struct LogEntry {
    pub(crate) timestamp: LogTimestamp,
    pub(crate) direction: FirewallDirection,
    pub(crate) action: FirewallAction,
    pub(crate) source: Option<LogIp>,
    pub(crate) dest: Option<LogIp>,
    pub(crate) sport: Option<u16>,
    pub(crate) dport: Option<u16>,
    pub(crate) proto: Option<u8>,
    pub(crate) icmp_type: Option<u8>,
    pub(crate) size: usize,
}

impl LogEntry {
    pub(crate) fn new(
        fields: &Fields,
        direction: FirewallDirection,
        action: FirewallAction,
    ) -> LogEntry {
        LogEntry {
            timestamp: LogTimestamp::from_date_time(chrono::offset::Local::now()),
            direction,
            action,
            source: LogIp::from_ip_addr(fields.source),
            dest: LogIp::from_ip_addr(fields.dest),
            sport: fields.sport,
            dport: fields.dport,
            proto: fields.proto,
            icmp_type: fields.icmp_type,
            size: fields.size,
        }
    }
}

impl Display for LogEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {}",
            self.timestamp,
            self.direction,
            self.action,
            Proto::from_number(self.proto),
            format_addr(&self.source),
            format_addr(&self.dest),
            format_port(self.sport),
            format_port(self.dport),
            format_icmp_type(self.icmp_type),
            self.size,
        )
    }
}

fn format_addr(addr: &Option<LogIp>) -> String {
    if let Some(ip) = addr {
        ip.to_string()
    } else {
        "-".to_string()
    }
}

fn format_port(port: Option<u16>) -> String {
    if let Some(p) = port {
        p.to_string()
    } else {
        "-".to_string()
    }
}

fn format_icmp_type(icmp_type: Option<u8>) -> String {
    if let Some(i) = icmp_type {
        i.to_string()
    } else {
        "-".to_string()
    }
}
