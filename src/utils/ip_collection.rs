use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::str::FromStr;

use crate::FirewallError;
use crate::firewall_option::FirewallOption;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct IpCollection {
    pub(crate) ips: Vec<IpAddr>,
    pub(crate) ranges: Vec<RangeInclusive<IpAddr>>,
}

impl IpCollection {
    const SEPARATOR: char = ',';
    const RANGE_SEPARATOR: char = '-';

    pub(crate) fn new(l: usize, opt: &str, str: &str) -> Result<Self, FirewallError> {
        let err = match opt {
            FirewallOption::DEST => FirewallError::InvalidDestValue(l, str.to_owned()),
            FirewallOption::SOURCE => FirewallError::InvalidSourceValue(l, str.to_owned()),
            _ => panic!("Should not happen!"),
        };
        let mut ips = Vec::new();
        let mut ranges = Vec::new();

        let objects: Vec<&str> = str.split(Self::SEPARATOR).collect();
        for object in objects {
            if object.contains(Self::RANGE_SEPARATOR) {
                // IP range
                let mut subparts = object.split(Self::RANGE_SEPARATOR);
                let (lower_bound, upper_bound) = (
                    subparts.next().ok_or(err.clone())?,
                    subparts.next().ok_or(err.clone())?,
                );
                let range = RangeInclusive::new(
                    IpAddr::from_str(lower_bound).map_err(|_| err.clone())?,
                    IpAddr::from_str(upper_bound).map_err(|_| err.clone())?,
                );
                ranges.push(range);
            } else {
                // individual IP
                let ip = IpAddr::from_str(object).map_err(|_| err.clone())?;
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::ops::RangeInclusive;
    use std::str::FromStr;

    use crate::FirewallError;
    use crate::firewall_option::FirewallOption;
    use crate::utils::ip_collection::IpCollection;
    use crate::utils::port_collection::PortCollection;

    #[test]
    fn test_new_source_collections() {
        assert_eq!(
            IpCollection::new(1, FirewallOption::SOURCE, "1.1.1.1,2.2.2.2").unwrap(),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap()
                ],
                ranges: vec![]
            }
        );

        assert_eq!(
            IpCollection::new(
                22,
                FirewallOption::SOURCE,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9",
            )
            .unwrap(),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap(),
                    IpAddr::from_str("9.9.9.9").unwrap()
                ],
                ranges: vec![
                    RangeInclusive::new(
                        IpAddr::from_str("3.3.3.3").unwrap(),
                        IpAddr::from_str("5.5.5.5").unwrap()
                    ),
                    RangeInclusive::new(
                        IpAddr::from_str("10.0.0.1").unwrap(),
                        IpAddr::from_str("10.0.0.255").unwrap()
                    )
                ]
            }
        );

        assert_eq!(
            IpCollection::new(3, FirewallOption::SOURCE, "aaaa::ffff,bbbb::1-cccc::2").unwrap(),
            IpCollection {
                ips: vec![IpAddr::from_str("aaaa::ffff").unwrap(),],
                ranges: vec![RangeInclusive::new(
                    IpAddr::from_str("bbbb::1").unwrap(),
                    IpAddr::from_str("cccc::2").unwrap()
                )]
            }
        );
    }

    #[test]
    fn test_new_dest_collections() {
        assert_eq!(
            IpCollection::new(44, FirewallOption::DEST, "1.1.1.1,2.2.2.2,8.8.8.8").unwrap(),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap(),
                    IpAddr::from_str("8.8.8.8").unwrap()
                ],
                ranges: vec![]
            }
        );

        assert_eq!(
            IpCollection::new(
                5,
                FirewallOption::DEST,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9",
            )
            .unwrap(),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("1.1.1.1").unwrap(),
                    IpAddr::from_str("2.2.2.2").unwrap(),
                    IpAddr::from_str("9.9.9.9").unwrap()
                ],
                ranges: vec![
                    RangeInclusive::new(
                        IpAddr::from_str("3.3.3.3").unwrap(),
                        IpAddr::from_str("5.5.5.5").unwrap()
                    ),
                    RangeInclusive::new(
                        IpAddr::from_str("10.0.0.1").unwrap(),
                        IpAddr::from_str("10.0.0.255").unwrap()
                    )
                ]
            }
        );

        assert_eq!(
            IpCollection::new(
                66,
                FirewallOption::DEST,
                "aaaa::ffff,bbbb::1-cccc::2,ff::dd"
            )
            .unwrap(),
            IpCollection {
                ips: vec![
                    IpAddr::from_str("aaaa::ffff").unwrap(),
                    IpAddr::from_str("ff::dd").unwrap()
                ],
                ranges: vec![RangeInclusive::new(
                    IpAddr::from_str("bbbb::1").unwrap(),
                    IpAddr::from_str("cccc::2").unwrap()
                )]
            }
        );
    }

    #[test]
    fn test_new_source_collections_invalid() {
        assert_eq!(
            IpCollection::new(
                7,
                FirewallOption::SOURCE,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9"
            ),
            Err(FirewallError::InvalidSourceValue(
                7,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9".to_owned()
            ))
        );

        assert_eq!(
            IpCollection::new(
                89,
                FirewallOption::SOURCE,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1:10.0.0.255,9.9.9.9"
            ),
            Err(FirewallError::InvalidSourceValue(
                89,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1:10.0.0.255,9.9.9.9".to_owned()
            ))
        );
    }

    #[test]
    fn test_new_dest_collections_invalid() {
        assert_eq!(
            IpCollection::new(
                6,
                FirewallOption::DEST,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9"
            ),
            Err(FirewallError::InvalidDestValue(
                6,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9".to_owned()
            ))
        );

        assert_eq!(
            IpCollection::new(
                8,
                FirewallOption::DEST,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1:10.0.0.255,9.9.9.9"
            ),
            Err(FirewallError::InvalidDestValue(
                8,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1:10.0.0.255,9.9.9.9".to_owned()
            ))
        );
    }

    #[test]
    fn test_new_ip_collections_invalid_option_proto() {
        let result = std::panic::catch_unwind(|| {
            IpCollection::new(7, FirewallOption::PROTO, "1.1.1.1,2.2.2.2")
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_new_ip_collections_invalid_option_sport() {
        let result = std::panic::catch_unwind(|| {
            IpCollection::new(7, FirewallOption::SPORT, "1.1.1.1,2.2.2.2")
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_new_ip_collections_invalid_option_dport() {
        let result = std::panic::catch_unwind(|| {
            IpCollection::new(6, FirewallOption::DPORT, "1.1.1.1,2.2.2.2")
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_new_ip_collections_invalid_option_icmp_type() {
        let result = std::panic::catch_unwind(|| {
            PortCollection::new(1, FirewallOption::ICMPTYPE, "1.1.1.1,2.2.2.2")
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_collection_contains() {
        for opt in [FirewallOption::DEST, FirewallOption::SOURCE] {
            let collection = IpCollection::new(
                11,
                opt,
                "1.1.1.1,2.2.2.2,3.3.3.3-5.5.5.5,10.0.0.1-10.0.0.255,9.9.9.9",
            )
            .unwrap();
            assert!(collection.contains(Some(IpAddr::from_str("1.1.1.1").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("2.2.2.2").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("3.3.3.3").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("4.0.0.0").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("5.5.5.5").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("9.9.9.9").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("10.0.0.1").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("10.0.0.128").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("10.0.0.255").unwrap())));
            assert!(!collection.contains(None));
            assert!(!collection.contains(Some(IpAddr::from_str("10.0.0.0").unwrap())));
            assert!(!collection.contains(Some(IpAddr::from_str("2.2.2.1").unwrap())));
            assert!(!collection.contains(Some(IpAddr::from_str("9.9.9.10").unwrap())));
            assert!(!collection.contains(Some(IpAddr::from_str("3.3.3.2").unwrap())));
        }
    }

    #[test]
    fn test_ip_collection_contains_ipv6() {
        for opt in [FirewallOption::DEST, FirewallOption::SOURCE] {
            let collection =
                IpCollection::new(1, opt, "2001:db8:1234:0000:0000:0000:0000:0000-2001:db8:1234:ffff:ffff:ffff:ffff:ffff,daa::aad,caa::aac").unwrap();
            assert!(collection.contains(Some(
                IpAddr::from_str("2001:db8:1234:0000:0000:0000:0000:0000").unwrap()
            )));
            assert!(collection.contains(Some(
                IpAddr::from_str("2001:db8:1234:ffff:ffff:ffff:ffff:ffff").unwrap()
            )));
            assert!(collection.contains(Some(
                IpAddr::from_str("2001:db8:1234:ffff:ffff:ffff:ffff:eeee").unwrap()
            )));
            assert!(collection.contains(Some(
                IpAddr::from_str("2001:db8:1234:aaaa:ffff:ffff:ffff:eeee").unwrap()
            )));
            assert!(collection.contains(Some(IpAddr::from_str("daa::aad").unwrap())));
            assert!(collection.contains(Some(IpAddr::from_str("caa::aac").unwrap())));
            assert!(!collection.contains(Some(
                IpAddr::from_str("2000:db8:1234:0000:0000:0000:0000:0000").unwrap()
            )));
            assert!(!collection.contains(Some(
                IpAddr::from_str("2001:db8:1235:ffff:ffff:ffff:ffff:ffff").unwrap()
            )));
            assert!(!collection.contains(Some(
                IpAddr::from_str("2001:eb8:1234:ffff:ffff:ffff:ffff:eeee").unwrap()
            )));
            assert!(!collection.contains(Some(IpAddr::from_str("da::aad").unwrap())));
            assert!(!collection.contains(Some(IpAddr::from_str("caa::aab").unwrap())));
        }
    }
}
