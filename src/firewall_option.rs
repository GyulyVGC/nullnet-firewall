use crate::utils::ip_collection::IpCollection;
use crate::utils::port_collection::PortCollection;
use crate::{get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport, FirewallError};
use etherparse::PacketHeaders;
use std::str::FromStr;

/// Options associated to a specific firewall rule
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FirewallOption {
    /// Destination IP addresses
    Dest(IpCollection),
    /// Destination ports
    Dport(PortCollection),
    /// ICMP message type
    IcmpType(u8),
    /// IP protocol number
    Proto(u8),
    /// Source IP addresses
    Source(IpCollection),
    /// Source ports
    Sport(PortCollection),
}

impl FirewallOption {
    pub(crate) const DEST: &'static str = "--dest";
    pub(crate) const DPORT: &'static str = "--dport";
    pub(crate) const ICMPTYPE: &'static str = "--icmp-type";
    pub(crate) const PROTO: &'static str = "--proto";
    pub(crate) const SOURCE: &'static str = "--source";
    pub(crate) const SPORT: &'static str = "--sport";

    pub(crate) fn new(option: &str, value: &str) -> Result<Self, FirewallError> {
        Ok(match option {
            FirewallOption::DEST => Self::Dest(IpCollection::new(FirewallOption::DEST, value)?),
            FirewallOption::DPORT => {
                Self::Dport(PortCollection::new(FirewallOption::DPORT, value)?)
            }
            FirewallOption::ICMPTYPE => Self::IcmpType(
                u8::from_str(value).map_err(|_| FirewallError::InvalidIcmpTypeValue)?,
            ),
            FirewallOption::PROTO => {
                Self::Proto(u8::from_str(value).map_err(|_| FirewallError::InvalidProtocolValue)?)
            }
            FirewallOption::SOURCE => {
                Self::Source(IpCollection::new(FirewallOption::SOURCE, value)?)
            }
            FirewallOption::SPORT => {
                Self::Sport(PortCollection::new(FirewallOption::SPORT, value)?)
            }
            _ => return Err(FirewallError::UnknownOption),
        })
    }

    pub(crate) fn matches_packet(&self, packet: &[u8]) -> bool {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(packet) {
            let ip_header = headers.ip;
            let transport_header = headers.transport;
            match self {
                FirewallOption::Dest(ip_collection) => ip_collection.contains(get_dest(ip_header)),
                FirewallOption::Dport(port_collection) => {
                    port_collection.contains(get_dport(transport_header))
                }
                FirewallOption::IcmpType(icmp_type) => {
                    if let Some(observed_icmp) = get_icmp_type(transport_header) {
                        icmp_type.eq(&observed_icmp)
                    } else {
                        false
                    }
                }
                FirewallOption::Proto(proto) => {
                    if let Some(observed_proto) = get_proto(ip_header) {
                        proto.eq(&observed_proto)
                    } else {
                        false
                    }
                }
                FirewallOption::Source(ip_collection) => {
                    ip_collection.contains(get_source(ip_header))
                }
                FirewallOption::Sport(port_collection) => {
                    port_collection.contains(get_sport(transport_header))
                }
            }
        } else {
            false
        }
    }

    pub(crate) fn to_option_str(&self) -> &str {
        match self {
            FirewallOption::Dest(_) => FirewallOption::DEST,
            FirewallOption::Dport(_) => FirewallOption::DPORT,
            FirewallOption::Proto(_) => FirewallOption::PROTO,
            FirewallOption::Source(_) => FirewallOption::SOURCE,
            FirewallOption::Sport(_) => FirewallOption::SPORT,
            FirewallOption::IcmpType(_) => FirewallOption::ICMPTYPE,
        }
    }
}
