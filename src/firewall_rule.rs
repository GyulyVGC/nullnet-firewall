use std::collections::HashMap;

use crate::firewall_option::FirewallOption;
use crate::log_level::LogLevel;
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
    /// Log level related to this specific rule
    pub(crate) log_level: Option<LogLevel>,
}

impl FirewallRule {
    const SEPARATOR: char = ' ';
    const QUICK: char = '+';

    pub(crate) fn new(l: usize, rule_str: &str) -> Result<Self, FirewallError> {
        let mut parts = rule_str.split(Self::SEPARATOR).filter(|s| !s.is_empty());
        let mut quick = false;
        let mut log_level = None;

        let first = parts.next().ok_or(FirewallError::NotEnoughArguments(l))?;
        if first.eq(&Self::QUICK.to_string()) {
            quick = true;
        }

        // rule direction
        let direction_str = if quick {
            parts.next().ok_or(FirewallError::NotEnoughArguments(l))?
        } else {
            first
        };
        let direction = FirewallDirection::from_str_with_line(l, direction_str)?;

        // rule action
        let action_str = parts.next().ok_or(FirewallError::NotEnoughArguments(l))?;
        let action = FirewallAction::from_str_with_line(l, action_str)?;

        // rule options
        let mut options = Vec::new();
        loop {
            let option = parts.next();
            if let Some(option_str) = option {
                let firewall_option = FirewallOption::new(
                    l,
                    option_str,
                    parts
                        .next()
                        .ok_or(FirewallError::EmptyOption(l, option_str.to_owned()))?,
                )?;
                if let FirewallOption::LogLevel(level) = firewall_option {
                    log_level = Some(level);
                }
                options.push(firewall_option);
            } else {
                break;
            }
        }

        FirewallRule::validate_options(l, &options)?;

        // now that options have been validated, --log-level can be removed (if present)
        options.retain(|option| !matches!(option, FirewallOption::LogLevel(_)));

        Ok(Self {
            direction,
            action,
            options,
            quick,
            log_level,
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

    fn validate_options(l: usize, options: &Vec<FirewallOption>) -> Result<(), FirewallError> {
        let mut options_map = HashMap::new();

        // check there is no duplicate options
        for option in options {
            if options_map.insert(option.to_option_str(), option).is_some() {
                return Err(FirewallError::DuplicatedOption(
                    l,
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
                    return Err(FirewallError::NotApplicableIcmpType(l));
                }
                Some(FirewallOption::Proto(x)) if *x != 1 && *x != 58 => {
                    return Err(FirewallError::NotApplicableIcmpType(l));
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub(crate) fn get_match_info(&self) -> (Option<FirewallAction>, Option<LogLevel>) {
        (Some(self.action), self.log_level)
    }
}

#[cfg(test)]
mod tests {
    use crate::firewall_option::FirewallOption;
    use crate::utils::ip_collection::IpCollection;
    use crate::utils::port_collection::PortCollection;
    use crate::utils::raw_packets::test_packets::{ICMP_PACKET, TCP_PACKET, UDP_IPV6_PACKET};
    use crate::{
        DataLink, Fields, FirewallAction, FirewallDirection, FirewallError, FirewallRule, LogLevel,
    };

    #[test]
    fn test_new_firewall_rules() {
        assert_eq!(
            FirewallRule::new(1, "OUT REJECT --log-level console").unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::REJECT,
                options: vec![],
                quick: false,
                log_level: Some(LogLevel::Console),
            }
        );

        let rule2 = FirewallRule::new(1, "IN DENY --dest 8.8.8.8-8.8.8.10").unwrap();
        assert_eq!(rule2.get_match_info(), (Some(FirewallAction::DENY), None));
        assert_eq!(
            rule2,
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![FirewallOption::Dest(
                    IpCollection::new(1, FirewallOption::SOURCE, "8.8.8.8-8.8.8.10").unwrap()
                )],
                quick: false,
                log_level: None,
            }
        );

        assert_eq!(
            FirewallRule::new(
                1,
                "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
            )
            .unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::ACCEPT,
                options: vec![
                    FirewallOption::Source(
                        IpCollection::new(1, FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()
                    ),
                    FirewallOption::Dport(
                        PortCollection::new(1, FirewallOption::DPORT, "900:1000,1,2,3").unwrap()
                    )
                ],
                quick: false,
                log_level: None,
            }
        );

        assert_eq!(
            FirewallRule::new(1, "OUT REJECT --source 8.8.8.8,7.7.7.7 --log-level off --dport 900:1000,1,2,3 --icmp-type 8 --proto 1").unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::REJECT,
                options: vec![
                    FirewallOption::Source(IpCollection::new(1, FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()),
                    FirewallOption::Dport(PortCollection::new(1, FirewallOption::DPORT, "900:1000,1,2,3").unwrap()),
                    FirewallOption::IcmpType(8),
                    FirewallOption::Proto(1)
                ],
                quick: false,
                log_level: Some(LogLevel::Off),
            }
        );

        assert_eq!(
            FirewallRule::new(
                1,
                "IN DENY --dest 8.8.8.8,7.7.7.7 --sport 900:1000,1,2,3 --log-level all --icmp-type 1 --proto 58"
            )
            .unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![
                    FirewallOption::Dest(
                        IpCollection::new(1, FirewallOption::DEST, "8.8.8.8,7.7.7.7").unwrap()
                    ),
                    FirewallOption::Sport(
                        PortCollection::new(1, FirewallOption::SPORT, "900:1000,1,2,3").unwrap()
                    ),
                    FirewallOption::IcmpType(1),
                    FirewallOption::Proto(58)
                ],
                quick: false,
                log_level: Some(LogLevel::All),
            }
        );
    }

    #[test]
    fn test_rule_invalid_direction() {
        assert_eq!(
            FirewallRule::new(
                2,
                "ACCEPT OUT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
            ),
            Err(FirewallError::InvalidDirection(2, "ACCEPT".to_owned()))
        );

        assert_eq!(
            FirewallRule::new(
                23,
                "UP ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
            ),
            Err(FirewallError::InvalidDirection(23, "UP".to_owned()))
        );
    }

    #[test]
    fn test_rule_empty_option() {
        let err = FirewallRule::new(4, "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport").unwrap_err();
        assert_eq!(err, FirewallError::EmptyOption(4, "--dport".to_owned()));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 4 - the supplied option '--dport' is empty"
        );
    }

    #[test]
    fn test_rule_duplicated_option() {
        let err = FirewallRule::new(
            7,
            "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3",
        )
        .unwrap_err();
        assert_eq!(
            err,
            FirewallError::DuplicatedOption(7, "--dport".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "Firewall error at line 7 - duplicated option '--dport' for the same rule"
        );

        assert_eq!(
            FirewallRule::new(
                9,
                "OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --sport 900:1000,1,2,3 --sport 555"
            ),
            Err(FirewallError::DuplicatedOption(9, "--sport".to_owned()))
        );
    }

    #[test]
    fn test_rule_invalid_option_value() {
        assert_eq!(
            FirewallRule::new(
                18,
                "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3.3.3.3"
            ),
            Err(FirewallError::InvalidDportValue(
                18,
                "900:1000,1,2,3.3.3.3".to_owned()
            ))
        );

        assert_eq!(
            FirewallRule::new(
                15,
                "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --dest 8.8.8-8"
            ),
            Err(FirewallError::InvalidDestValue(15, "8.8.8-8".to_owned()))
        );

        // --source expects a value => the following options is interpreted as value
        assert_eq!(
            FirewallRule::new(6, "OUT ACCEPT --source --dport 8"),
            Err(FirewallError::InvalidSourceValue(6, "--dport".to_owned()))
        );
    }

    #[test]
    fn test_rule_not_applicable_icmp_type() {
        let err = FirewallRule::new(
            2,
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8",
        )
        .unwrap_err();
        assert_eq!(err, FirewallError::NotApplicableIcmpType(2));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 2 - option '--icmp-type' is valid only if '--proto 1' or '--proto 58' is also specified"
        );

        assert_eq!(FirewallRule::new(8,
            "OUT ACCEPT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --icmp-type 8 --proto 57"
        ), Err(FirewallError::NotApplicableIcmpType(8)));
    }

    #[test]
    fn test_rule_invalid_action() {
        assert_eq!(
            FirewallRule::new(
                1,
                "OUT PUTAWAY --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
            ),
            Err(FirewallError::InvalidAction(1, "PUTAWAY".to_owned()))
        );
    }

    #[test]
    fn test_rule_not_enough_arguments() {
        let err = FirewallRule::new(3, "").unwrap_err();
        assert_eq!(err, FirewallError::NotEnoughArguments(3));
        assert_eq!(
            err.to_string(),
            "Firewall error at line 3 - not enough arguments supplied for rule"
        );

        assert_eq!(
            FirewallRule::new(2, " "),
            Err(FirewallError::NotEnoughArguments(2))
        );

        assert_eq!(
            FirewallRule::new(10, "                    "),
            Err(FirewallError::NotEnoughArguments(10))
        );

        assert_eq!(
            FirewallRule::new(6, "IN             "),
            Err(FirewallError::NotEnoughArguments(6))
        );

        assert_eq!(
            FirewallRule::new(1, "           OUT             "),
            Err(FirewallError::NotEnoughArguments(1))
        );
    }

    #[test]
    fn test_rules_match_packets() {
        let tcp_packet_fields = Fields::new(&TCP_PACKET, DataLink::Ethernet);
        let icmp_packet_fields = Fields::new(&ICMP_PACKET, DataLink::Ethernet);
        let rule_1 = FirewallRule::new(1, "OUT DENY").unwrap();
        assert!(rule_1.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_1.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(rule_1.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_1.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_2 = FirewallRule::new(2, "IN DENY").unwrap();
        assert!(!rule_2.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_2.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_2.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_2.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_3_ok_out =
            FirewallRule::new(3, "OUT REJECT --source 192.168.200.135 --dport 1999:2001").unwrap();
        assert!(rule_3_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_3_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_3_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_3_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_4_ok_in =
            FirewallRule::new(4, "IN REJECT --source 192.168.200.135 --dport 1999:2001").unwrap();
        assert!(!rule_4_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_4_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_4_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_4_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_5_ok_out = FirewallRule::new(
            5,
            "OUT ACCEPT --source 192.168.200.135 --dport 1999:2001 --sport 6711",
        )
        .unwrap();
        assert!(rule_5_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_5_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_5_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_5_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_6_ko = FirewallRule::new(
            6,
            "OUT REJECT --log-level db --source 192.168.200.135 --dport 1999:2001 --sport 6710",
        )
        .unwrap();
        assert!(!rule_6_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_6_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_6_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_6_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_7_ok_out = FirewallRule::new(7, "OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.21").unwrap();
        assert!(rule_7_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_7_ok_out.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_7_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_7_ok_out.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_8_ko = FirewallRule::new(8, "OUT REJECT --source 192.168.200.135 --dport 1999:2001 --sport 6711 --dest 192.168.200.10-192.168.200.20").unwrap();
        assert!(!rule_8_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_8_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_8_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_8_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_9_ok_in = FirewallRule::new(9, "IN ACCEPT --proto 6").unwrap();
        assert!(!rule_9_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_9_ok_in.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_9_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_9_ok_in.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_10_ko = FirewallRule::new(10, "IN ACCEPT --proto 58").unwrap();
        assert!(!rule_10_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_10_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_10_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_10_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_11_ko = FirewallRule::new(
            11,
            "+ IN ACCEPT --proto 1 --log-level console --icmp-type 8",
        )
        .unwrap();
        assert!(!rule_11_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_11_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_11_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(rule_11_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_12_ko =
            FirewallRule::new(12, "OUT DENY --proto 1 --icmp-type 7 --log-level db").unwrap();
        assert!(!rule_12_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_12_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(!rule_12_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_12_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
        let rule_13_ko = FirewallRule::new(13, "+ OUT DENY --proto 1 --icmp-type 8").unwrap();
        assert!(!rule_13_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_13_ko.matches_packet(&tcp_packet_fields, &FirewallDirection::IN));
        assert!(rule_13_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_13_ko.matches_packet(&icmp_packet_fields, &FirewallDirection::IN));
    }

    #[test]
    fn test_rules_match_ipv6() {
        let udp_ipv6_packet_fields = Fields::new(&UDP_IPV6_PACKET, DataLink::Ethernet);
        let rule_1 = FirewallRule::new(1, "OUT DENY --log-level off").unwrap();
        assert!(rule_1.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_1.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_2 = FirewallRule::new(2, "IN DENY").unwrap();
        assert!(!rule_2.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(rule_2.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_3_ok_out = FirewallRule::new(
            3,
            "+ OUT REJECT --dest 3ffe:507:0:1:200:86ff:fe05:8da --log-level all --proto 17",
        )
        .unwrap();
        assert!(rule_3_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_3_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_4_ok_in = FirewallRule::new(
            4,
            "IN REJECT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17",
        )
        .unwrap();
        assert!(!rule_4_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(rule_4_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_5_ok_out = FirewallRule::new(
            5,
            "+ OUT ACCEPT --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17 --sport 545:560,43,53",
        )
        .unwrap();
        assert!(rule_5_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_5_ok_out.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_6_ko = FirewallRule::new(
            6,
            "+ OUT ACCEPT --log-level off --dest 3ffe:507:0:1:200:86ff:fe05:8da --proto 17 --sport 545:560,43,52",
        )
        .unwrap();
        assert!(!rule_6_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_6_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_9_ok_in =
            FirewallRule::new(7, "IN ACCEPT --source 3ffe:501:4819::42,3ffe:501:4819::49").unwrap();
        assert!(!rule_9_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(rule_9_ok_in.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
        let rule_10_ko =
            FirewallRule::new(8, "IN ACCEPT --source 3ffe:501:4819::47,3ffe:501:4819::49").unwrap();
        assert!(!rule_10_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::OUT));
        assert!(!rule_10_ko.matches_packet(&udp_ipv6_packet_fields, &FirewallDirection::IN));
    }

    #[test]
    fn test_new_quick_rules() {
        assert_eq!(
            FirewallRule::new(11, "+ IN DENY --dest 8.8.8.8-8.8.8.10 --log-level all").unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![FirewallOption::Dest(
                    IpCollection::new(11, FirewallOption::SOURCE, "8.8.8.8-8.8.8.10").unwrap()
                )],
                quick: true,
                log_level: Some(LogLevel::All),
            }
        );

        assert_eq!(
            FirewallRule::new(12, "    +       IN DENY --dest 8.8.8.8-8.8.8.10").unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![FirewallOption::Dest(
                    IpCollection::new(12, FirewallOption::SOURCE, "8.8.8.8-8.8.8.10").unwrap()
                )],
                quick: true,
                log_level: None,
            }
        );

        let err = FirewallRule::new(
            14,
            "+OUT ACCEPT --dport 8 --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3",
        )
        .unwrap_err();
        assert_eq!(err, FirewallError::InvalidDirection(14, "+OUT".to_owned()));

        assert_eq!(
            FirewallRule::new(41, "- IN DENY --dest 8.8.8.8-8.8.8.10"),
            Err(FirewallError::InvalidDirection(41, "-".to_string()))
        );

        assert_eq!(
            FirewallRule::new(1, "# IN DENY --dest 8.8.8.8-8.8.8.10"),
            Err(FirewallError::InvalidDirection(1, "#".to_string()))
        );
    }

    #[test]
    fn test_new_log_level_rules() {
        let rule1 = FirewallRule::new(11, "IN REJECT --log-level off").unwrap();
        assert_eq!(
            rule1.get_match_info(),
            (Some(FirewallAction::REJECT), Some(LogLevel::Off))
        );
        assert_eq!(
            rule1,
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::REJECT,
                options: vec![],
                quick: false,
                log_level: Some(LogLevel::Off),
            }
        );

        assert_eq!(
            FirewallRule::new(
                12,
                "    +       IN DENY --log-level db --dest 8.8.8.8-8.8.8.10"
            )
            .unwrap(),
            FirewallRule {
                direction: FirewallDirection::IN,
                action: FirewallAction::DENY,
                options: vec![FirewallOption::Dest(
                    IpCollection::new(12, FirewallOption::SOURCE, "8.8.8.8-8.8.8.10").unwrap()
                )],
                quick: true,
                log_level: Some(LogLevel::Db),
            }
        );

        assert_eq!(
            FirewallRule::new(
                1,
                "OUT ACCEPT --log-level console --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3"
            )
            .unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::ACCEPT,
                options: vec![
                    FirewallOption::Source(
                        IpCollection::new(1, FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()
                    ),
                    FirewallOption::Dport(
                        PortCollection::new(1, FirewallOption::DPORT, "900:1000,1,2,3").unwrap()
                    )
                ],
                quick: false,
                log_level: Some(LogLevel::Console),
            }
        );

        assert_eq!(
            FirewallRule::new(1, "OUT REJECT --source 8.8.8.8,7.7.7.7 --dport 900:1000,1,2,3 --log-level all --icmp-type 8 --proto 1").unwrap(),
            FirewallRule {
                direction: FirewallDirection::OUT,
                action: FirewallAction::REJECT,
                options: vec![
                    FirewallOption::Source(IpCollection::new(1, FirewallOption::SOURCE, "8.8.8.8,7.7.7.7").unwrap()),
                    FirewallOption::Dport(PortCollection::new(1, FirewallOption::DPORT, "900:1000,1,2,3").unwrap()),
                    FirewallOption::IcmpType(8),
                    FirewallOption::Proto(1)
                ],
                quick: false,
                log_level: Some(LogLevel::All),
            }
        );

        assert_eq!(
            FirewallRule::new(11, "IN DENY --log_level off").unwrap_err(),
            FirewallError::UnknownOption(11, "--log_level".to_owned())
        );

        assert_eq!(
            FirewallRule::new(12, "IN DENY --log-level off --log-level off").unwrap_err(),
            FirewallError::DuplicatedOption(12, "--log-level".to_owned())
        );

        assert_eq!(
            FirewallRule::new(12, "IN DENY --log-level off --log-level console").unwrap_err(),
            FirewallError::DuplicatedOption(12, "--log-level".to_owned())
        );

        assert_eq!(
            FirewallRule::new(21, "IN DENY --log-level off --log-level on").unwrap_err(),
            FirewallError::InvalidLogLevelValue(21, "on".to_owned())
        );

        assert_eq!(
            FirewallRule::new(21, "IN DENY --log-level    ").unwrap_err(),
            FirewallError::EmptyOption(21, "--log-level".to_owned())
        );

        assert_eq!(
            FirewallRule::new(21, "IN DENY --log off").unwrap_err(),
            FirewallError::UnknownOption(21, "--log".to_owned())
        );

        assert_eq!(
            FirewallRule::new(21, "IN DENY --log    ").unwrap_err(),
            FirewallError::EmptyOption(21, "--log".to_owned())
        );
    }
}
