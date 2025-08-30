//! PROXY Protocol v1 header models

use core::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "feat-uni-addr")]
use std::io;

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

impl AddressPair {
    #[cfg(feature = "feat-uni-addr")]
    /// Returns the source address.
    pub fn src_uni_addr(&self) -> io::Result<Option<uni_addr::SocketAddr>> {
        use core::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

        match self {
            Self::Unspecified => Ok(None),
            Self::Inet { src_ip, src_port, .. } => Ok(Some(uni_addr::SocketAddr::Inet(SocketAddr::V4(
                SocketAddrV4::new(*src_ip, *src_port),
            )))),
            Self::Inet6 { src_ip, src_port, .. } => Ok(Some(uni_addr::SocketAddr::Inet(SocketAddr::V6(
                SocketAddrV6::new(*src_ip, *src_port, 0, 0),
            )))),
        }
    }

    #[cfg(feature = "feat-uni-addr")]
    /// Returns the destination address.
    pub fn dst_uni_addr(&self) -> io::Result<Option<uni_addr::SocketAddr>> {
        use core::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

        match self {
            Self::Unspecified => Ok(None),
            Self::Inet { dst_ip, dst_port, .. } => Ok(Some(uni_addr::SocketAddr::Inet(SocketAddr::V4(
                SocketAddrV4::new(*dst_ip, *dst_port),
            )))),
            Self::Inet6 { dst_ip, dst_port, .. } => Ok(Some(uni_addr::SocketAddr::Inet(SocketAddr::V6(
                SocketAddrV6::new(*dst_ip, *dst_port, 0, 0),
            )))),
        }
    }
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
