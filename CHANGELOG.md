# Changelog

All releases with the relative changes are documented in this file.

## [0.2.1] - 2024-01-15
### Added
- `Firewall::data_link` method to set the `DataLink` type of the `Firewall`: in addition to Ethernet, now also raw IP is supported.
- `Firewall::log` method to allow users enable or disable logging (it's still enabled by default).

## [0.2.0] - 2023-11-23
### Added
- Log capabilities for the firewall: packets are logged both in standard output 
  and in a SQLite database with path `./log.sqlite` ([#1](https://github.com/GyulyVGC/nullnet-firewall/pull/1)).
- `Firewall::update_rules` to update the rules of a previously instantiated firewall.
- Quick rules: each of the rules can now  be preceded by a `+` character 
  that will make it have higher priority (quick rule).
- Comments: the file defining firewall rules can now contain comment lines
  (starting with `#`).
### Changed
- Rules precedence logic changed from "rule with more options wins" to "rule that comes first wins"
  and now quick rules are supported.
- `Firewall::resolve_packet` now accepts a `FirewallDirection` by value instead of by reference.
- Renamed `Firewall::set_policy_in` to `Firewall::policy_in`.
- Renamed `Firewall::set_policy_out` to `Firewall::policy_out`.

## [0.1.0] - 2023-11-09
- `nullnet-firewall` first release
