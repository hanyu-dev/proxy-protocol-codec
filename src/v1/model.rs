//! PROXY Protocol v1 header models

use core::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "feat-codec-decode")]
use crate::v1::Header;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// The address type, which can be either an IPv4/IPv6 address or a UNIX socket
/// address.
pub enum AddressPair {
    /// Unknown
    Unspecified,

    /// The address is an IPv4 address.
    Inet {
        /// SRC IPv4 address.
        src_ip: Ipv4Addr,

        /// DST IPv4 address.
        dst_ip: Ipv4Addr,

        /// SRC port.
        src_port: u16,

        /// DST port.
        dst_port: u16,
    },

    /// The address is an IPv6 address.
    Inet6 {
        /// SRC IPv4 address.
        src_ip: Ipv6Addr,

        /// DST IPv4 address.
        dst_ip: Ipv6Addr,

        /// SRC port.
        src_port: u16,

        /// DST port.
        dst_port: u16,
    },
}

#[cfg(feature = "feat-codec-decode")]
#[derive(Debug)]
/// The result of decoding a PROXY Protocol v1 header.
pub enum Decoded {
    /// The PROXY Protocol v1 header and its extensions decoded.
    Some(Header),

    /// Partial data, the caller should read more data.
    ///
    /// However, it's hard to determine how much more data is needed like PROXY
    /// Protocol v2.
    Partial,

    /// Not a PROXY Protocol v1 header.
    None,
}
