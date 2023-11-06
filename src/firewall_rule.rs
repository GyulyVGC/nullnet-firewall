use std::collections::HashMap;
use std::str::FromStr;
use crate::{FirewallAction, FirewallDirection, FirewallError};
use crate::firewall_option::FirewallOption;

/// A firewall rule
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FirewallRule {
    pub(crate) direction: FirewallDirection,
    pub(crate) action: FirewallAction,
    pub(crate) options: Vec<FirewallOption>,
}

impl FirewallRule {
    const SEPARATOR: char = ' ';

    pub(crate) fn new(rule_str: &str) -> Result<Self, FirewallError> {
        let mut parts = rule_str.split(Self::SEPARATOR);

        // rule direction
        let direction_str = parts.next().ok_or(FirewallError::NotEnoughArguments)?;
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
                    parts.next().ok_or(FirewallError::EmptyOption)?,
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
        })
    }

    pub(crate) fn matches_packet(&self, packet: &[u8], direction: &FirewallDirection) -> bool {
        for option in &self.options {
            if !option.matches_packet(packet) {
                return false;
            }
        }
        self.direction.eq(direction)
    }

    pub(crate) fn specificity(&self) -> usize {
        self.options.len()
    }

    fn validate_options(options: &Vec<FirewallOption>) -> Result<(), FirewallError> {
        let mut options_map = HashMap::new();

        // check there is no duplicate options
        for option in options {
            if options_map.insert(option.to_option_str(), option).is_some() {
                return Err(FirewallError::DuplicatedOption);
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