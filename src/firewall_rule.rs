use std::collections::HashMap;
use std::str::FromStr;

use crate::firewall_option::FirewallOption;
use crate::{Fields, FirewallAction, FirewallDirection, FirewallError};

/// A firewall rule
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FirewallRule {
    /// Direction associated with the rule
    pub(crate) direction: FirewallDirection,
    /// Action associated with the rule
    pub(crate) action: FirewallAction,
    /// Rule options
    pub(crate) options: Vec<FirewallOption>,
    /// Is this a quick rule?
    pub(crate) quick: bool,
}

impl FirewallRule {
    const SEPARATOR: char = ' ';
    const QUICK: char = '+';

    pub(crate) fn new(rule_str: &str) -> Result<Self, FirewallError> {
        let mut parts = rule_str.split(Self::SEPARATOR).filter(|s| !s.is_empty());
        let mut quick = false;

        let first = parts.next().ok_or(FirewallError::NotEnoughArguments)?;
        if first.eq(&Self::QUICK.to_string()) {
            quick = true;
        }

        // rule direction
        let direction_str = if quick {
            parts.next().ok_or(FirewallError::NotEnoughArguments)?
        } else {
            first
        };
        let direction = FirewallDirection::from_str(direction_str)?;

        // rule action
        let action_str = parts.next().ok_or(FirewallError::NotEnoughArguments)?;
        let action = FirewallAction::from_str(action_str)?;

        // rule options
        let mut options = Vec::new();
        loop {
            let option = parts.next();
            if let Some(option_str) = option {
                let firewall_option = FirewallOption::new(
                    option_str,
                    parts
                        .next()
                        .ok_or(FirewallError::EmptyOption(option_str.to_owned()))?,
                )?;
                options.push(firewall_option);
            } else {
                break;
            }
        }

        FirewallRule::validate_options(&options)?;

        Ok(Self {
            direction,
            action,
            options,
            quick,
        })
    }

    pub(crate) fn matches_packet(&self, fields: &Fields, direction: &FirewallDirection) -> bool {
        for option in &self.options {
            if !option.matches_packet(fields) {
                return false;
            }
        }
        self.direction.eq(direction)
    }

    fn validate_options(options: &Vec<FirewallOption>) -> Result<(), FirewallError> {
        let mut options_map = HashMap::new();

        // check there is no duplicate options
        for option in options {
            if options_map.insert(option.to_option_str(), option).is_some() {
                return Err(FirewallError::DuplicatedOption(
                    option.to_option_str().to_owned(),
                ));
            }
        }

        // if --icmp-type option is present, --proto 1 || --proto 58 must also be present
        // from Proxmox VE documentation: --icmp-type is only valid if --proto equals icmp or ipv6-icmp
        // icmp = 1, ipv6-icmp = 58 (<https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>)
        if options_map.contains_key(FirewallOption::ICMPTYPE) {
            match options_map.get(FirewallOption::PROTO) {
                None => {
                    return Err(FirewallError::NotApplicableIcmpType);
                }
                Some(FirewallOption::Proto(x)) if *x != 1 && *x != 58 => {
                    return Err(FirewallError::NotApplicableIcmpType);
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::firewall_option::FirewallOption;
    use crate::utils::ip_collection::IpCollection;
    use crate::utils::port_collection::PortCollection;
    use crate::utils::raw_packets::test_packets::{ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET};
    use crate::{DataLink, Fields, FirewallAction, FirewallDirection, FirewallError, FirewallRule};

    #[test]
    fn test_new_firewall_rules() {
        assert_eq!(
            FirewallRule::new("OUT REJECT").unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::REJECT,
                options: vec![],
                quick: false
            }
        );

        assert_eq!(
            FirewallRule::new("IN DENY --dest 8.8.8.8-8.8.8.10").unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![FirewallOption::Dest(
                    IpCollection::new(FirewallOption::SOURCE, "8.8.8.8-8.8.8.10").unwrap()
                )],
                quick: false
            }
        );

        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3")
                .unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::ACCEPT,
                options: vec![
                    FirewallOption::Source(
                        IpCollection::new(FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()
                    ),
                    FirewallOption::Dport(
                        PortCollection::new(FirewallOption::DPORT, "900:1000,1,2,3").unwrap()
                    )
                ],
                quick: false
            }
        );

        assert_eq!(
            FirewallRule::new("OUT REJECT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 1").unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::REJECT,
                options: vec![
                    FirewallOption::Source(IpCollection::new(FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()),
                    FirewallOption::Dport(PortCollection::new(FirewallOption::DPORT, "900:1000,1,2,3").unwrap()),
                    FirewallOption::IcmpType(8),
                    FirewallOption::Proto(1)
                ],
                quick: false
            }
        );

        assert_eq!(
            FirewallRule::new(
                "IN DENY --dest 8.8.8.8,7.7.7.7 --sport 900:1000,1,2,3 --icmp-type 1 --proto 58"
            )
            .unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![
                    FirewallOption::Dest(
                        IpCollection::new(FirewallOption::DEST, "8.8.8.8,7.7.7.7").unwrap()
                    ),
                    FirewallOption::Sport(
                        PortCollection::new(FirewallOption::SPORT, "900:1000,1,2,3").unwrap()
                    ),
                    FirewallOption::IcmpType(1),
                    FirewallOption::Proto(58)
                ],
                quick: false
            }
        );
    }

    #[test]
    fn test_rule_invalid_direction() {
        assert_eq!(
            FirewallRule::new("ACCEPT OUT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidDirection("ACCEPT".to_owned()))
        );

        assert_eq!(
            FirewallRule::new("UP ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidDirection("UP".to_owned()))
        );
    }

    #[test]
    fn test_rule_empty_option() {
        let err = FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport").unwrap_err();
        assert_eq!(err, FirewallError::EmptyOption("--dport".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error - the supplied option '--dport' is empty"
        );
    }

    #[test]
    fn test_rule_duplicated_option() {
        let err = FirewallRule::new(
            "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3",
        )
        .unwrap_err();
        assert_eq!(err, FirewallError::DuplicatedOption("--dport".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error - duplicated option '--dport' for the same rule"
        );

        assert_eq!(
            FirewallRule::new(
                "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --sport 900:1000,1,2,3 --sport 555"
            ),
            Err(FirewallError::DuplicatedOption("--sport".to_owned()))
        );
    }

    #[test]
    fn test_rule_invalid_option_value() {
        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3.3.3.3"),
            Err(FirewallError::InvalidDportValue(
                "900:1000,1,2,3.3.3.3".to_owned()
            ))
        );

        assert_eq!(
            FirewallRule::new(
                "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --dest 8.8.8-8"
            ),
            Err(FirewallError::InvalidDestValue("8.8.8-8".to_owned()))
        );

        // --source expects a value => the following options is interpreted as value
        assert_eq!(
            FirewallRule::new("OUT ACCEPT --source --dport 8"),
            Err(FirewallError::InvalidSourceValue("--dport".to_owned()))
        );
    }

    #[test]
    fn test_rule_not_applicable_icmp_type() {
        let err = FirewallRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8",
        )
        .unwrap_err();
        assert_eq!(err, FirewallError::NotApplicableIcmpType);
        assert_eq!(
            err.to_string(),
            "Firewall error - option '--icmp-type' is valid only if '--proto 1' or '--proto 58' is also specified"
        );

        assert_eq!(FirewallRule::new(
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 57"
        ), Err(FirewallError::NotApplicableIcmpType));
    }

    #[test]
    fn test_rule_invalid_action() {
        assert_eq!(
            FirewallRule::new("OUT PUTAWAY --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"),
            Err(FirewallError::InvalidAction("PUTAWAY".to_owned()))
        );
    }

    #[test]
    fn test_rule_not_enough_arguments() {
        let err = FirewallRule::new("").unwrap_err();
        assert_eq!(err, FirewallError::NotEnoughArguments);
        assert_eq!(
            err.to_string(),
            "Firewall error - not enough arguments supplied for rule"
        );

        assert_eq!(
            FirewallRule::new(" "),
            Err(FirewallError::NotEnoughArguments)
        );

        assert_eq!(
            FirewallRule::new("                    "),
            Err(FirewallError::NotEnoughArguments)
        );

        assert_eq!(
            FirewallRule::new("IN             "),
            Err(FirewallError::NotEnoughArguments)
        );

        assert_eq!(
            FirewallRule::new("           OUT             "),
            Err(FirewallError::NotEnoughArguments)
        );
    }

    #[test]
    fn test_rules_match_packets() {
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        let rule_1 = FirewallRule::new("OUT DENY").unwrap();
        assert!(rule_1.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_1.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(rule_1.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_1.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_2 = FirewallRule::new("IN DENY").unwrap();
        assert!(!rule_2.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_2.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_2.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_2.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_3_ok_out =
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001").unwrap();
        assert!(rule_3_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_3_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_3_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_3_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_4_ok_in =
            FirewallRule::new("IN REJECT --source 192.168.200.135 --dport 1999:2001").unwrap();
        assert!(!rule_4_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_4_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_4_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_4_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_5_ok_out =
            FirewallRule::new("OUT ACCEPT --source 192.168.200.135 --dport 1999:2001 --sport 6711")
                .unwrap();
        assert!(rule_5_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_5_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_5_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_5_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_6_ko =
            FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6710")
                .unwrap();
        assert!(!rule_6_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_6_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_6_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_6_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_7_ok_out = FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.21").unwrap();
        assert!(rule_7_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_7_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_7_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_7_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_8_ko = FirewallRule::new("OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.20").unwrap();
        assert!(!rule_8_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_8_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_8_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_8_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_9_ok_in = FirewallRule::new("IN ACCEPT --proto 6").unwrap();
        assert!(!rule_9_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_9_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_9_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_9_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_10_ko = FirewallRule::new("IN ACCEPT --proto 58").unwrap();
        assert!(!rule_10_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_10_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_10_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_10_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_11_ko = FirewallRule::new("+ IN ACCEPT --proto 1 --icmp-type 8").unwrap();
        assert!(!rule_11_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_11_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_11_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_11_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_12_ko = FirewallRule::new("OUT DENY --proto 1 --icmp-type 7").unwrap();
        assert!(!rule_12_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_12_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_12_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_12_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_13_ko = FirewallRule::new("+ OUT DENY --proto 1 --icmp-type 8").unwrap();
        assert!(!rule_13_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_13_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(rule_13_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_13_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
    }

    #[test]
    fn test_rules_match_ipv6() {
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        let rule_1 = FirewallRule::new("OUT DENY").unwrap();
        assert!(rule_1.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_1.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_2 = FirewallRule::new("IN DENY").unwrap();
        assert!(!rule_2.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(rule_2.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_3_ok_out =
            FirewallRule::new("+ OUT REJECT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17")
                .unwrap();
        assert!(rule_3_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_3_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_4_ok_in =
            FirewallRule::new("IN REJECT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17")
                .unwrap();
        assert!(!rule_4_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(rule_4_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_5_ok_out = FirewallRule::new(
            "+ OUT ACCEPT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17 --sport 545:560,43,53",
        )
        .unwrap();
        assert!(rule_5_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_5_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_6_ko = FirewallRule::new(
            "+ OUT ACCEPT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17 --sport 545:560,43,52",
        )
        .unwrap();
        assert!(!rule_6_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_6_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_9_ok_in =
            FirewallRule::new("IN ACCEPT --source 3ffe:501:4819::42,3ffe:501:4819::49").unwrap();
        assert!(!rule_9_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(rule_9_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_10_ko =
            FirewallRule::new("IN ACCEPT --source 3ffe:501:4819::47,3ffe:501:4819::49").unwrap();
        assert!(!rule_10_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_10_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
    }

    #[test]
    fn test_quick_rules() {
        assert_eq!(
            FirewallRule::new("+ IN DENY --dest 8.8.8.8-8.8.8.10").unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![FirewallOption::Dest(
                    IpCollection::new(FirewallOption::SOURCE, "8.8.8.8-8.8.8.10").unwrap()
                )],
                quick: true
            }
        );

        assert_eq!(
            FirewallRule::new("    +       IN DENY --dest 8.8.8.8-8.8.8.10").unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![FirewallOption::Dest(
                    IpCollection::new(FirewallOption::SOURCE, "8.8.8.8-8.8.8.10").unwrap()
                )],
                quick: true
            }
        );

        let err = FirewallRule::new(
            "+OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3",
        )
        .unwrap_err();
        assert_eq!(err, FirewallError::InvalidDirection("+OUT".to_owned()));

        assert_eq!(
            FirewallRule::new("- IN DENY --dest 8.8.8.8-8.8.8.10"),
            Err(FirewallError::InvalidDirection("-".to_string()))
        );

        assert_eq!(
            FirewallRule::new("# IN DENY --dest 8.8.8.8-8.8.8.10"),
            Err(FirewallError::InvalidDirection("#".to_string()))
        );
    }
}
