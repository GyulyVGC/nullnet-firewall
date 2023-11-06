use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::str::FromStr;
use crate::FirewallError;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct IpCollection {
    pub(crate) ips: Vec<IpAddr>,
    pub(crate) ranges: Vec<RangeInclusive<IpAddr>>,
}

impl IpCollection {
    const SEPARATOR: char = ',';
    const RANGE_SEPARATOR: char = '-';

    pub(crate) fn new(str: &str, err: FirewallError) -> Result<Self, FirewallError> {
        let mut ips = Vec::new();
        let mut ranges = Vec::new();

        let parts: Vec<&str> = str.split(Self::SEPARATOR).collect();
        for part in parts {
            if part.contains(Self::RANGE_SEPARATOR) {
                // IP range
                let mut subparts = part.split(Self::RANGE_SEPARATOR);
                let (lower_bound, upper_bound) =
                    (subparts.next().ok_or(err)?, subparts.next().ok_or(err)?);
                let range = RangeInclusive::new(
                    IpAddr::from_str(lower_bound).map_err(|_| err)?,
                    IpAddr::from_str(upper_bound).map_err(|_| err)?,
                );
                ranges.push(range);
            } else {
                // individual IP
                let ip = IpAddr::from_str(part).map_err(|_| err)?;
                ips.push(ip);
            }
        }

        Ok(Self { ips, ranges })
    }

    pub(crate) fn contains(&self, ip: Option<IpAddr>) -> bool {
        if let Some(addr) = ip.as_ref() {
            for range in &self.ranges {
                if range.contains(addr) {
                    return true;
                }
            }
            self.ips.contains(addr)
        } else {
            false
        }
    }
}
