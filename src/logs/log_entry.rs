use std::fmt::{Display, Formatter};

use crate::logs::log_ip::LogIp;
use crate::logs::log_timestamp::LogTimestamp;
use crate::utils::log_level::LogLevel;
use crate::utils::proto::Proto;
use crate::{Fields, FirewallAction, FirewallDirection};

#[derive(Debug, PartialEq, Clone)]
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
    pub(crate) log_level: LogLevel,
}

impl LogEntry {
    pub(crate) fn new(
        fields: &Fields,
        direction: FirewallDirection,
        action: FirewallAction,
        log_level: LogLevel,
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
            log_level,
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::logs::log_ip::LogIp;
    use crate::utils::raw_packets::test_packets::{ARP_PACKET, ICMPV6_PACKET, TCP_PACKET};
    use crate::{DataLink, Fields, FirewallAction, FirewallDirection, LogEntry};

    #[test]
    fn test_log_entry_new() {
        // tcp packet
        let log_entry_tcp = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
        );
        assert_eq!(log_entry_tcp.direction, FirewallDirection::IN);
        assert_eq!(log_entry_tcp.action, FirewallAction::DENY);
        assert_eq!(
            log_entry_tcp.source,
            Some(LogIp::from_ip_addr(Some(IpAddr::from_str("192.168.200.135").unwrap())).unwrap())
        );
        assert_eq!(
            log_entry_tcp.dest,
            Some(LogIp::from_ip_addr(Some(IpAddr::from_str("192.168.200.21").unwrap())).unwrap())
        );
        assert_eq!(log_entry_tcp.sport, Some(6711));
        assert_eq!(log_entry_tcp.dport, Some(2000));
        assert_eq!(log_entry_tcp.proto, Some(6));
        assert_eq!(log_entry_tcp.icmp_type, None);
        assert_eq!(log_entry_tcp.size, 66);

        // icmpv6 packet
        let log_entry_tcp = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
        );
        assert_eq!(log_entry_tcp.direction, FirewallDirection::OUT);
        assert_eq!(log_entry_tcp.action, FirewallAction::REJECT);
        assert_eq!(
            log_entry_tcp.source,
            Some(
                LogIp::from_ip_addr(Some(IpAddr::from_str("3ffe:501:4819::42").unwrap())).unwrap()
            )
        );
        assert_eq!(
            log_entry_tcp.dest,
            Some(
                LogIp::from_ip_addr(Some(
                    IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap()
                ))
                .unwrap()
            )
        );
        assert_eq!(log_entry_tcp.sport, None);
        assert_eq!(log_entry_tcp.dport, None);
        assert_eq!(log_entry_tcp.proto, Some(58));
        assert_eq!(log_entry_tcp.icmp_type, Some(135));
        assert_eq!(log_entry_tcp.size, 86);

        // arp packet
        let log_entry_tcp = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
        );
        assert_eq!(log_entry_tcp.direction, FirewallDirection::OUT);
        assert_eq!(log_entry_tcp.action, FirewallAction::ACCEPT);
        assert_eq!(log_entry_tcp.source, None);
        assert_eq!(log_entry_tcp.dest, None);
        assert_eq!(log_entry_tcp.sport, None);
        assert_eq!(log_entry_tcp.dport, None);
        assert_eq!(log_entry_tcp.proto, None);
        assert_eq!(log_entry_tcp.icmp_type, None);
        assert_eq!(log_entry_tcp.size, 42);
    }

    #[test]
    fn test_log_entry_display() {
        let timestamp_len = chrono::offset::Local::now().to_string().len();

        // tcp packet
        let log_entry_tcp = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
        );
        assert_eq!(
            format!("{log_entry_tcp}")[timestamp_len + 1..].to_string(),
            "IN DENY TCP 192.168.200.135 192.168.200.21 6711 2000 - 66".to_string()
        );

        // icmpv6 packet
        let log_entry_tcp = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::ACCEPT,
        );
        assert_eq!(
            format!("{log_entry_tcp}")[timestamp_len + 1..].to_string(),
            "IN ACCEPT IPv6-ICMP 3ffe:501:4819::42 3ffe:507:0:1:200:86ff:fe05:8da - - 135 86"
                .to_string()
        );

        // arp packet
        let log_entry_tcp = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
        );
        assert_eq!(
            format!("{log_entry_tcp}")[timestamp_len + 1..].to_string(),
            "OUT REJECT - - - - - - 42".to_string()
        );
    }
}
