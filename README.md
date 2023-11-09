# nullnet-firewall

[![Crates](https://img.shields.io/crates/v/nullnet-firewall?&logo=rust)](https://crates.io/crates/nullnet-firewall)
[![CI](https://github.com/gyulyvgc/nullnet-firewall/workflows/CI/badge.svg)](https://github.com/GyulyVGC/nullnet-firewall/actions/)
[![Docs](https://docs.rs/nullnet-firewall/badge.svg)](https://docs.rs/nullnet-firewall/latest/)

**Rust-based firewall for network drivers.**

## Purpose

This library is used to match network packets against a set of constraints (here called *firewall rules*)
with the aim of deciding whether to permit or deny incoming/outgoing traffic.

Given a set of firewall rules and a network packet, the library will *inform* the user
about *how* to handle the packet.

The library assumes that users are able to manipulate the stream of network packets in a way such
it's possible to take proper actions to allow or deny the forwarding of single packets
between the operating system and the network card; consequently, this framework is mainly intended
to be used at the level of *network drivers*.

## Firewall rules definition

A new `Firewall` object is defined as a set of rules specified in a textual file.

Each of the **rules** defined in the file is placed on a new line and has the following structure:
``` txt
DIRECTION ACTION [OPTIONS]
```

* `DIRECTION` can be either `IN` or `OUT` and represents the traffic directionality.

* `ACTION` can be either `ACCEPT`, `DENY`, or `REJECT` and represents the action
associated with the rule.

* For each rule, a list of **options** can be specified to match the desired traffic:
  * `--dest`: destination IP addresses; the value is expressed in the form of a comma-separated
    list of IP addresses, in which each entry can also represent an address range (using the `-` character).
  * `--dport`: destination transport ports; the value is expressed in the form of a comma-separated
    list of port numbers, in which each entry can also represent a port range (using the `:` character).
  * `--icmp-type`: ICMP message type; the value is expressed as a number representing
    a specific message type (see [here](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types) for more info).
  * `--proto`: Internet Protocol number; the value is expressed as a number representing
    a specific protocol number (see [here](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1) for more info).
  * `--source`: source IP addresses; the value is expressed in the form of a comma-separated
    list of IP addresses, in which each entry can also represent an address range (using the `-` character).
  * `--sport`: source transport ports; the value is expressed in the form of a comma-separated
    list of port numbers, in which each entry can also represent a port range (using the `:` character).

A **sample** firewall configuration file is reported in the following:

``` txt
OUT REJECT --source 8.8.8.8 --sport 6700:6800,8080
OUT DENY --source 192.168.200.0-192.168.200.255 --sport 6700:6800,8080 --dport 1,2,2000
IN ACCEPT --source 2.1.1.2,2.1.1.3 --dest 2.1.1.1 --proto 1
IN REJECT --source 2.1.1.2 --dest 2.1.1.1 --proto 1 --icmp-type 8
OUT REJECT
IN ACCEPT
```

In case of invalid firewall configurations, a specific `FirewallError` will be raised.

## Usage

A defined `Firewall` object can be used to determine which action to take for each
of the netwrok packets in transit.

This is done by invoking `Firewall::resolve_packet`, which will answer with the
action to take for the supplied packet.

``` rs
use nullnet_firewall::{Firewall, FirewallDirection, FirewallAction};

// build the firewall from the rules in a file
let firewall = Firewall::new("./samples/firewall.txt").unwrap();

// here we suppose to have a packet to match against the firewall
let packet = [/* ... */];

// determine action for packet, supposing incoming direction for packet
let action = firewall.resolve_packet(&packet, &FirewallDirection::IN);

// act accordingly
match action {
    FirewallAction::ACCEPT => {/* ... */}
    FirewallAction::DENY => {/* ... */}
    FirewallAction::REJECT => {/* ... */}
}
```
