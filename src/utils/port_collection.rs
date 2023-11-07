use crate::firewall_option::FirewallOption;
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

    pub(crate) fn new(opt: &str, str: &str) -> Result<Self, FirewallError> {
        let err = match opt {
            FirewallOption::DPORT => FirewallError::InvalidDportValue(str.to_owned()),
            FirewallOption::SPORT => FirewallError::InvalidSportValue(str.to_owned()),
            _ => panic!("Should not happen!"),
        };
        let mut ports = Vec::new();
        let mut ranges = Vec::new();

        let objects: Vec<&str> = str.split(Self::SEPARATOR).collect();
        for object in objects {
            if object.contains(Self::RANGE_SEPARATOR) {
                // port range
                let mut subparts = object.split(Self::RANGE_SEPARATOR);
                let (lower_bound, upper_bound) = (
                    subparts.next().ok_or(err.clone())?,
                    subparts.next().ok_or(err.clone())?,
                );
                let range = RangeInclusive::new(
                    u16::from_str(lower_bound).map_err(|_| err.clone())?,
                    u16::from_str(upper_bound).map_err(|_| err.clone())?,
                );
                ranges.push(range);
            } else {
                // individual port
                let port = u16::from_str(object).map_err(|_| err.clone())?;
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

#[cfg(test)]
mod tests {
    use crate::firewall_option::FirewallOption;
    use crate::utils::port_collection::PortCollection;
    use crate::FirewallError;

    #[test]
    fn test_new_sport_collections() {
        assert_eq!(
            PortCollection::new(FirewallOption::SPORT, "1,2,3,4,999").unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4, 999],
                ranges: vec![]
            }
        );

        assert_eq!(
            PortCollection::new(FirewallOption::SPORT, "1,2,3,4,900:999").unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![900..=999]
            }
        );

        assert_eq!(
            PortCollection::new(FirewallOption::SPORT, "1:999").unwrap(),
            PortCollection {
                ports: vec![],
                ranges: vec![1..=999]
            }
        );

        assert_eq!(
            PortCollection::new(FirewallOption::SPORT, "1,2,10:20,3,4,999:1200").unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![10..=20, 999..=1200]
            }
        );
    }

    #[test]
    fn test_new_dport_collections() {
        assert_eq!(
            PortCollection::new(FirewallOption::DPORT, "1").unwrap(),
            PortCollection {
                ports: vec![1],
                ranges: vec![]
            }
        );

        assert_eq!(
            PortCollection::new(FirewallOption::DPORT, "1,2,3,4,900:999").unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![900..=999]
            }
        );

        assert_eq!(
            PortCollection::new(FirewallOption::DPORT, "55:999").unwrap(),
            PortCollection {
                ports: vec![],
                ranges: vec![55..=999]
            }
        );

        assert_eq!(
            PortCollection::new(FirewallOption::DPORT, "1,2,10:20,3,4,999:1200").unwrap(),
            PortCollection {
                ports: vec![1, 2, 3, 4],
                ranges: vec![10..=20, 999..=1200]
            }
        );
    }

    #[test]
    fn test_new_sport_collections_invalid() {
        assert_eq!(
            PortCollection::new(FirewallOption::SPORT, "1,2,10:20,3,4,:1200"),
            Err(FirewallError::InvalidSportValue)
        );

        assert_eq!(
            PortCollection::new(FirewallOption::SPORT, "1,2,10:20,3,4,999-1200"),
            Err(FirewallError::InvalidSportValue)
        );

        assert_eq!(
            PortCollection::new(FirewallOption::SPORT, "1,2,10:20,3,4,999-1200,"),
            Err(FirewallError::InvalidSportValue)
        );
    }

    #[test]
    fn test_new_dport_collections_invalid() {
        assert_eq!(
            PortCollection::new(FirewallOption::DPORT, "1,2,10:20,3,4,:1200"),
            Err(FirewallError::InvalidDportValue)
        );

        assert_eq!(
            PortCollection::new(FirewallOption::DPORT, "1,2,10:20,3,4,999-1200"),
            Err(FirewallError::InvalidDportValue)
        );

        assert_eq!(
            PortCollection::new(FirewallOption::DPORT, "1,2,10:20,3,4,999-1200,"),
            Err(FirewallError::InvalidDportValue)
        );
    }

    #[test]
    fn test_new_port_collections_invalid_option_proto() {
        let result =
            std::panic::catch_unwind(|| PortCollection::new(FirewallOption::PROTO, "55:999"));
        assert!(result.is_err());
    }

    #[test]
    fn test_new_port_collections_invalid_option_source() {
        let result =
            std::panic::catch_unwind(|| PortCollection::new(FirewallOption::SOURCE, "55:999"));
        assert!(result.is_err());
    }

    #[test]
    fn test_new_port_collections_invalid_option_dest() {
        let result =
            std::panic::catch_unwind(|| PortCollection::new(FirewallOption::DEST, "55:999"));
        assert!(result.is_err());
    }

    #[test]
    fn test_new_port_collections_invalid_option_icmp_type() {
        let result =
            std::panic::catch_unwind(|| PortCollection::new(FirewallOption::ICMPTYPE, "55:999"));
        assert!(result.is_err());
    }

    #[test]
    fn test_port_collection_contains() {
        for opt in [FirewallOption::DPORT, FirewallOption::SPORT] {
            let collection = PortCollection::new(opt, "1,2,25:30,55,101:117").unwrap();
            assert!(collection.contains(Some(1)));
            assert!(collection.contains(Some(2)));
            assert!(collection.contains(Some(25)));
            assert!(collection.contains(Some(27)));
            assert!(collection.contains(Some(30)));
            assert!(collection.contains(Some(55)));
            assert!(collection.contains(Some(101)));
            assert!(collection.contains(Some(109)));
            assert!(collection.contains(Some(117)));
            assert!(!collection.contains(None));
            assert!(!collection.contains(Some(4)));
            assert!(!collection.contains(Some(24)));
            assert!(!collection.contains(Some(31)));
            assert!(!collection.contains(Some(100)));
            assert!(!collection.contains(Some(118)));
            assert!(!collection.contains(Some(8080)));
        }
    }
}
