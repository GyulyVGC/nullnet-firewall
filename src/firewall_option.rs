use std::str::FromStr;
use etherparse::PacketHeaders;
use crate::{FirewallError, get_dest, get_dport, get_icmp_type, get_proto, get_source, get_sport};
use crate::ip_collection::IpCollection;
use crate::port_collection::PortCollection;

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
    const DEST: &'static str = "--dest";
    const DPORT: &'static str = "--dport";
    pub(crate) const ICMPTYPE: &'static str = "--icmp-type";
    pub(crate) const PROTO: &'static str = "--proto";
    const SOURCE: &'static str = "--source";
    const SPORT: &'static str = "--sport";

    pub(crate) fn new(option: &str, value: &str) -> Result<Self, FirewallError> {
        Ok(match option {
            FirewallOption::DEST => {
                Self::Dest(IpCollection::new(value, FirewallError::InvalidDestValue)?)
            }
            FirewallOption::DPORT => Self::Dport(PortCollection::new(
                value,
                FirewallError::InvalidDportValue,
            )?),
            FirewallOption::ICMPTYPE => {
                Self::IcmpType(u8::from_str(value).map_err(|_| FirewallError::InvalidIcmpTypeValue)?)
            }
            FirewallOption::PROTO => {
                Self::Proto(u8::from_str(value).map_err(|_| FirewallError::InvalidProtocolValue)?)
            }
            FirewallOption::SOURCE => {
                Self::Source(IpCollection::new(value, FirewallError::InvalidSourceValue)?)
            }
            FirewallOption::SPORT => Self::Sport(PortCollection::new(
                value,
                FirewallError::InvalidSportValue,
            )?),
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