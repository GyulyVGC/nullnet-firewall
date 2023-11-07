use crate::FirewallError;
use std::ops::RangeInclusive;
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PortCollection {
    pub(crate) ports: Vec<u16>,
    pub(crate) ranges: Vec<RangeInclusive<u16>>,
}

impl PortCollection {
    const SEPARATOR: char = ',';
    const RANGE_SEPARATOR: char = ':';

    pub(crate) fn new(str: &str, err: FirewallError) -> Result<Self, FirewallError> {
        let mut ports = Vec::new();
        let mut ranges = Vec::new();

        let objects: Vec<&str> = str.split(Self::SEPARATOR).collect();
        for object in objects {
            if object.contains(Self::RANGE_SEPARATOR) {
                // port range
                let mut subparts = object.split(Self::RANGE_SEPARATOR);
                let (lower_bound, upper_bound) =
                    (subparts.next().ok_or(err)?, subparts.next().ok_or(err)?);
                let range = RangeInclusive::new(
                    u16::from_str(lower_bound).map_err(|_| err)?,
                    u16::from_str(upper_bound).map_err(|_| err)?,
                );
                ranges.push(range);
            } else {
                // individual port
                let port = u16::from_str(object).map_err(|_| err)?;
                ports.push(port);
            }
        }

        Ok(Self { ports, ranges })
    }

    pub(crate) fn contains(&self, port: Option<u16>) -> bool {
        if let Some(num) = port.as_ref() {
            for range in &self.ranges {
                if range.contains(num) {
                    return true;
                }
            }
            self.ports.contains(num)
        } else {
            false
        }
    }
}
