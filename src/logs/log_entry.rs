use crate::logs::log_ip::LogIp;
use crate::logs::log_timestamp::LogTimestamp;
use crate::utils::proto::Proto;
use crate::{Fields, FirewallAction, FirewallDirection};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

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
        let source = if let Some(s) = &self.source {
            s.to_string()
        } else {
            "-".to_string()
        };
        let dest = if let Some(d) = &self.dest {
            d.to_string()
        } else {
            "-".to_string()
        };
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {}",
            self.timestamp,
            self.direction,
            self.action,
            Proto::from_number(self.proto),
            source,
            dest,
            format_port(self.sport),
            format_port(self.dport),
            format_icmp_type(self.icmp_type),
            self.size,
        )
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

pub(crate) fn format_ip_address(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(ip) => format_ipv4_address(ip.octets()),
        IpAddr::V6(ip) => format_ipv6_address(ip.octets()),
    }
}

fn format_ipv4_address(address: [u8; 4]) -> String {
    format!("{address:?}")
        .replace('[', "")
        .replace(']', "")
        .replace(',', ".")
        .replace(' ', "")
}

/// Function to convert a long decimal ipv6 address to a
/// shorter compressed ipv6 address
///
/// # Arguments
///
/// * `ipv6_long` - Contains the 16 integer composing the not compressed decimal ipv6 address
fn format_ipv6_address(ipv6_long: [u8; 16]) -> String {
    //from hex to dec, paying attention to the correct number of digits
    let mut ipv6_hex = String::new();
    for i in 0..=15 {
        //even: first byte of the group
        if i % 2 == 0 {
            if *ipv6_long.get(i).unwrap() == 0 {
                continue;
            }
            ipv6_hex.push_str(&format!("{:x}", ipv6_long.get(i).unwrap()));
        }
        //odd: second byte of the group
        else if *ipv6_long.get(i - 1).unwrap() == 0 {
            ipv6_hex.push_str(&format!("{:x}:", ipv6_long.get(i).unwrap()));
        } else {
            ipv6_hex.push_str(&format!("{:02x}:", ipv6_long.get(i).unwrap()));
        }
    }
    ipv6_hex.pop();

    // search for the longest zero sequence in the ipv6 address
    let mut to_compress: Vec<&str> = ipv6_hex.split(':').collect();
    let mut longest_zero_sequence = 0; // max number of consecutive zeros
    let mut longest_zero_sequence_start = 0; // first index of the longest sequence of zeros
    let mut current_zero_sequence = 0;
    let mut current_zero_sequence_start = 0;
    let mut i = 0;
    for s in to_compress.clone() {
        if s.eq("0") {
            if current_zero_sequence == 0 {
                current_zero_sequence_start = i;
            }
            current_zero_sequence += 1;
        } else if current_zero_sequence != 0 {
            if current_zero_sequence > longest_zero_sequence {
                longest_zero_sequence = current_zero_sequence;
                longest_zero_sequence_start = current_zero_sequence_start;
            }
            current_zero_sequence = 0;
        }
        i += 1;
    }
    if current_zero_sequence != 0 {
        // to catch consecutive zeros at the end
        if current_zero_sequence > longest_zero_sequence {
            longest_zero_sequence = current_zero_sequence;
            longest_zero_sequence_start = current_zero_sequence_start;
        }
    }
    if longest_zero_sequence < 2 {
        // no compression needed
        return ipv6_hex;
    }

    //from longest sequence of consecutive zeros to '::'
    let mut ipv6_hex_compressed = String::new();
    for _ in 0..longest_zero_sequence {
        to_compress.remove(longest_zero_sequence_start);
    }
    i = 0;
    if longest_zero_sequence_start == 0 {
        ipv6_hex_compressed.push_str("::");
    }
    for s in to_compress {
        ipv6_hex_compressed.push_str(s);
        ipv6_hex_compressed.push(':');
        i += 1;
        if i == longest_zero_sequence_start {
            ipv6_hex_compressed.push(':');
        }
    }
    if ipv6_hex_compressed.ends_with("::") {
        return ipv6_hex_compressed;
    }
    ipv6_hex_compressed.pop();

    ipv6_hex_compressed
}
