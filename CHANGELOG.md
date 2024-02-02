# Changelog

All releases with the relative changes are documented in this file.

## [UNRELEASED]
### Added
- `LogLevel` enum to represent all the available logging strategies (`Off`, `Console`, `Db`, `All`).
- New option `--log-level` for user-defined firewall rules, which allows to specify the logging strategy to use for traffic matching a given rule; if this option is not set, the default firewall logging strategy will be used.
### Changed
- `Firewall::log` method (that was accepting a boolean parameter) has been renamed to `Firewall::log_level` and now accepts a `LogLevel` parameter, useful to set the default firewall logging strategy.
- Renamed `Firewall::update_rules` to `Firewall::set_rules`.
- `Firewall::new` no longer takes a file path as argument, and returns a firewall without any defined rules; firewall rules can now be set exclusively via `Firewall::set_rules`.
### Fixed
- Only spawn logger thread if a valid firewall was instantiated.
- Added `bundled` feature to `rusqlite` dependency to properly work on Windows.

## [0.2.2] - 2024-01-19
### Changed
- `FirewallError`s now also include information about the file line number responsible for the error, enabling an easier debugging activity.

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
