use crate::utils::proto::Proto;
use crate::{FirewallAction, FirewallDirection};
use chrono::{DateTime, Utc};
use std::net::IpAddr;

pub(crate) struct LogPacket {
    timestamp: DateTime<Utc>,
    direction: FirewallDirection,
    action: FirewallAction,
    proto: Proto,
    source: IpAddr,
    dest: IpAddr,
    sport: u16,
    dport: u16,
    size: u16,
}
