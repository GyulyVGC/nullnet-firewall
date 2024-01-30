use std::fmt::{Display, Formatter};

use crate::log_level::LogLevel;
use crate::logs::log_ip::LogIp;
use crate::logs::log_timestamp::LogTimestamp;
use crate::utils::proto::Proto;
use crate::{Fields, FirewallAction, FirewallDirection};

#[derive(Debug, Clone)]
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

impl PartialEq for LogEntry {
    fn eq(&self, other: &Self) -> bool {
        let LogEntry {
            timestamp,
            direction,
            action,
            source,
            dest,
            sport,
            dport,
            proto,
            icmp_type,
            size,
            log_level: _,
        } = self;

        timestamp.to_string() == other.timestamp.to_string()
            && direction == &other.direction
            && action == &other.action
            && source == &other.source
            && dest == &other.dest
            && sport == &other.sport
            && dport == &other.dport
            && proto == &other.proto
            && icmp_type == &other.icmp_type
            && size == &other.size
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

    use crate::log_level::LogLevel;
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
            LogLevel::All,
        );
        assert_eq!(log_entry_tcp.direction, FirewallDirection::IN);
        assert_eq!(log_entry_tcp.action, FirewallAction::DENY);
        assert_eq!(log_entry_tcp.log_level, LogLevel::All);
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
        let log_entry_icmpv6 = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
            LogLevel::Db,
        );
        assert_eq!(log_entry_icmpv6.direction, FirewallDirection::OUT);
        assert_eq!(log_entry_icmpv6.action, FirewallAction::REJECT);
        assert_eq!(log_entry_icmpv6.log_level, LogLevel::Db);
        assert_eq!(
            log_entry_icmpv6.source,
            Some(
                LogIp::from_ip_addr(Some(IpAddr::from_str("3ffe:501:4819::42").unwrap())).unwrap()
            )
        );
        assert_eq!(
            log_entry_icmpv6.dest,
            Some(
                LogIp::from_ip_addr(Some(
                    IpAddr::from_str("3ffe:507:0:1:200:86ff:fe05:8da").unwrap()
                ))
                .unwrap()
            )
        );
        assert_eq!(log_entry_icmpv6.sport, None);
        assert_eq!(log_entry_icmpv6.dport, None);
        assert_eq!(log_entry_icmpv6.proto, Some(58));
        assert_eq!(log_entry_icmpv6.icmp_type, Some(135));
        assert_eq!(log_entry_icmpv6.size, 86);

        // arp packet
        let log_entry_arp = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
            LogLevel::Off,
        );
        assert_eq!(log_entry_arp.direction, FirewallDirection::OUT);
        assert_eq!(log_entry_arp.action, FirewallAction::ACCEPT);
        assert_eq!(log_entry_arp.log_level, LogLevel::Off);
        assert_eq!(log_entry_arp.source, None);
        assert_eq!(log_entry_arp.dest, None);
        assert_eq!(log_entry_arp.sport, None);
        assert_eq!(log_entry_arp.dport, None);
        assert_eq!(log_entry_arp.proto, None);
        assert_eq!(log_entry_arp.icmp_type, None);
        assert_eq!(log_entry_arp.size, 42);
    }

    #[test]
    fn test_log_entry_display() {
        let timestamp_len = 25;

        // tcp packet
        let log_entry_tcp = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
            LogLevel::Console,
        );
        assert_eq!(log_entry_tcp.log_level, LogLevel::Console);
        assert_eq!(
            format!("{log_entry_tcp}")[timestamp_len + 1..].to_string(),
            "IN DENY TCP 192.168.200.135 192.168.200.21 6711 2000 - 66".to_string()
        );

        // icmpv6 packet
        let log_entry_icmpv6 = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::ACCEPT,
            LogLevel::All,
        );
        assert_eq!(
            format!("{log_entry_icmpv6}")[timestamp_len + 1..].to_string(),
            "IN ACCEPT IPv6-ICMP 3ffe:501:4819::42 3ffe:507:0:1:200:86ff:fe05:8da - - 135 86"
                .to_string()
        );

        // arp packet
        let log_entry_arp = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
            LogLevel::All,
        );
        assert_eq!(
            format!("{log_entry_arp}")[timestamp_len + 1..].to_string(),
            "OUT REJECT - - - - - - 42".to_string()
        );
    }
}
