// use std::fmt::{Display, Formatter};
//
// #[derive(Debug)]
// // #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
// pub(crate) enum IcmpType {
//     V4(V4Type),
//     V6(V6Type)
// }
//
// enum V4Type {
//     EchoReply,
//     DestinationUnreachable,
//     SourceQuench,
//     Redirect,
//     AlternateHostAddress,
//     Echo,
//     RouterAdvertisement,
//     RouterSolicitation,
//     TimeExceeded,
//     ParameterProblem,
//     Timestamp,
//     TimestampReply,
//     InformationRequest,
//     InformationReply,
//     AddressMaskRequest,
//     AddressMaskReply,
//     Traceroute,
//     DatagramConversionError,
//     MobileHostRedirect,
//     Ipv6WhereAreYou,
//     Ipv6IAmHere,
//     MobileRegistrationRequest,
//     MobileRegistrationReply,
//     DomainNameRequest,
//     DomainNameReply,
//     Skip,
//     Photuris,
//     ExtendedEchoRequest,
//     ExtendedEchoReply,
// }
//
// enum V6Type {
//     DestinationUnreachable,
//     PacketTooBig,
//     TimeExceeded,
//     ParameterProblem,
//     EchoRequest,
//     EchoReply,
//     MulticastListenerQuery,
//     MulticastListenerReport,
//     MulticastListenerDone,
//     RouterSolicitation,
//     RouterAdvertisement,
//     NeighborSolicitation,
//     NeighborAdvertisement,
//     RedirectMessage,
//     RouterRenumbering,
//     IcmpNodeInformationQuery,
//     IcmpNodeInformationResponse,
//     InverseNeighborDiscoverySolicitationMessage,
//     InverseNeighborDiscoveryAdvertisementMessage,
//     Version2MulticastListenerReport,
//     HomeAgentAddressDiscoveryRequestMessage,
//     HomeAgentAddressDiscoveryReplyMessage,
//     MobilePrefixSolicitation,
//     MobilePrefixAdvertisement,
//     CertificationPathSolicitationMessage,
//     CertificationPathAdvertisementMessage,
//     MulticastRouterAdvertisement,
//     MulticastRouterSolicitation,
//     MulticastRouterTermination,
//     FmIpv6Messages,
//     RplControlMessage,
//     Ilnpv6LocatorUpdateMessage,
//     DuplicateAddressRequest,
//     DuplicateAddressConfirmation,
//     MplControlMessage,
//     ExtendedEchoRequest,
//     ExtendedEchoReply,
// }
//
// impl IcmpType {
//     #[allow(clippy::too_many_lines)]
//     pub(crate) fn from_number(num: Option<u8>) -> IcmpType {
//         if let Some(proto) = num {
//             return match proto {
//                 0 => Proto::HOPOPT,
//                 _ => Proto::Unknown,
//             };
//         }
//         Proto::Unknown
//     }
// }
//
// impl Display for Proto {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         let proto = match self {
//             Proto::BBN_RCC_MON => "BBN-RCC-MON".to_string(),
//             Proto::Unknown => "-".to_string(),
//             _ => {
//                 format!("{self:?}")
//             }
//         };
//
//         write!(f, "{proto}")
//     }
// }
