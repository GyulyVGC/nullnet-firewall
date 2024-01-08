/// Data link type associated with packets processed by the firewall.
///
/// If not specified, Ethernet will be used.
#[derive(Default, Copy, Clone)]
pub enum DataLink {
    /// Suitable for packets starting with an Ethernet header.
    #[default]
    Ethernet,
    /// Suitable for packets starting with an IPv4 or IPv6 header.
    RawIP,
}
