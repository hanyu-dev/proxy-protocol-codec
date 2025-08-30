//! PROXY Protocol v2 header models

#[cfg(feature = "feat-codec-encode")]
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "feat-uni-addr")]
use std::io;

#[cfg(feature = "feat-codec-decode")]
use slicur::Reader;

#[cfg(feature = "feat-codec-v1")]
use crate::v1;
#[cfg(feature = "feat-codec-decode")]
use crate::v2::DecodeError;

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
/// Fixed version byte for PROXY Protocol v2.
pub(crate) const BYTE_VERSION: u8 = 0x20;

/// Size of the PROXY Protocol v2 header in bytes.
pub const HEADER_SIZE: usize = 16;

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
/// Size of addresses for IPv4
pub(crate) const ADDR_INET_SIZE: usize = 12; // 2 * 4 bytes for IPv4 + 2 * 2 bytes for port

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
/// Size of addresses for IPv6
pub(crate) const ADDR_INET6_SIZE: usize = 36; // 2 * 16 bytes for IPv6 + 2 * 2 bytes for port

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
/// Size of addresses for Unix sockets
pub(crate) const ADDR_UNIX_SIZE: usize = 216; // 2 * 108 bytes for Unix socket addresses

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// The supported `Command`s for a PROXY protocol header.
pub enum Command {
    /// The connection was established on purpose by the proxy
    /// without being relayed. The connection endpoints are the sender and the
    /// receiver. Such connections exist when the proxy sends health-checks to
    /// the server. The receiver must accept this connection as valid and
    /// must use the real connection endpoints and discard the protocol
    /// block including the family which is ignored.
    Local = 0x00,

    /// the connection was established on behalf of another node, and reflects
    /// the original connection endpoints. The receiver must then use the
    /// information provided in the protocol block to get original the address.
    Proxy = 0x01,
}

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// The address family.
pub(crate) enum Family {
    /// The connection is forwarded for an unknown, unspecified or unsupported
    /// protocol. The sender should use this family when sending LOCAL commands
    /// or when dealing with unsupported protocol families. The receiver is free
    /// to accept the connection anyway and use the real endpoint addresses or
    /// to reject it. The receiver should ignore address information.
    Unspecified = 0x00,

    /// The forwarded connection uses the `AF_INET` address family (IPv4). The
    /// addresses are exactly 4 bytes each in network byte order, followed by
    /// transport protocol information (typically ports).
    Inet = 0x10,

    /// The forwarded connection uses the `AF_INET6` address family (IPv6). The
    /// addresses are exactly 16 bytes each in network byte order, followed by
    /// transport protocol information (typically ports).
    Inet6 = 0x20,

    /// The forwarded connection uses the `AF_UNIX` address family (UNIX). The
    /// addresses are exactly 108 bytes each.
    Unix = 0x30,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// The transport protocol.
pub enum Protocol {
    /// The connection is forwarded for an unknown, unspecified or unsupported
    /// protocol. The sender should use this protocol when sending LOCAL
    /// commands or when dealing with unsupported protocols. The receiver is
    /// free to accept the connection anyway and use the real endpoint
    /// addresses or to reject it.
    Unspecified = 0x00,

    /// The forwarded connection uses a `SOCK_STREAM` protocol (eg: TCP or
    /// `UNIX_STREAM`). When used with `AF_INET/AF_INET6` (TCP), the addresses
    /// are followed by the source and destination ports represented on 2
    /// bytes each in network byte order.
    Stream = 0x01,

    /// The forwarded connection uses a `SOCK_DGRAM` protocol (eg: UDP or
    /// `UNIX_DGRAM`). When used with `AF_INET/AF_INET6` (UDP), the addresses
    /// are followed by the source and destination ports represented on 2
    /// bytes each in network byte order.
    Dgram = 0x02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// The address type, which can be either an IPv4/IPv6 address or a UNIX socket
/// address.
pub enum AddressPair {
    /// Address unspecified
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

    /// The address is a UNIX socket address.
    Unix {
        /// The src address bytes (with null terminator).
        src_addr: [u8; 108],

        /// The address bytes (with null terminator).
        dst_addr: [u8; 108],
    },
}

#[cfg(feature = "feat-codec-v1")]
impl From<v1::AddressPair> for AddressPair {
    fn from(addr: v1::AddressPair) -> Self {
        AddressPair::from_v1(addr)
    }
}

impl AddressPair {
    #[cfg(feature = "feat-codec-v1")]
    #[inline]
    /// Converts a [`v1::AddressPair`] to an [`AddressPair`].
    pub const fn from_v1(addr: v1::AddressPair) -> Self {
        match addr {
            v1::AddressPair::Unspecified => Self::Unspecified,
            v1::AddressPair::Inet {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => Self::Inet {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            },
            v1::AddressPair::Inet6 {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => Self::Inet6 {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            },
        }
    }

    #[cfg(feature = "feat-codec-encode")]
    #[inline]
    pub(crate) const fn address_family(&self) -> Family {
        match self {
            Self::Unspecified => Family::Unspecified,
            Self::Inet { .. } => Family::Inet,
            Self::Inet6 { .. } => Family::Inet6,
            Self::Unix { .. } => Family::Unix,
        }
    }

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
            #[cfg(unix)]
            Self::Unix { src_addr, .. } => uni_addr::unix::SocketAddr::from_bytes_until_nul(src_addr)
                .map(uni_addr::SocketAddr::Unix)
                .map(Some),
            #[cfg(not(unix))]
            Self::Unix { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix socket addresses are not supported on this platform",
            )),
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
            #[cfg(unix)]
            Self::Unix { dst_addr, .. } => uni_addr::unix::SocketAddr::from_bytes_until_nul(dst_addr)
                .map(uni_addr::SocketAddr::Unix)
                .map(Some),
            #[cfg(not(unix))]
            Self::Unix { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix socket addresses are not supported on this platform",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Supported types for `TypeLengthValue` payloads.
pub enum ExtensionType {
    /// Application-Layer Protocol Negotiation (ALPN). It is a byte sequence
    /// defining the upper layer protocol in use over the connection. The most
    /// common use case will be to pass the exact copy of the ALPN extension of
    /// the Transport Layer Security (TLS) protocol as defined by RFC7301.
    ALPN = 0x01,

    /// Contains the host name value passed by the client, as an UTF8-encoded
    /// string. In case of TLS being used on the client connection, this is the
    /// exact copy of the "`server_name`" extension as defined by RFC3546,
    /// section 3.1, often referred to as "SNI". There are probably other
    /// situations where an authority can be mentioned on a connection without
    /// TLS being involved at all.
    Authority = 0x02,

    /// The value of the type `PP2_TYPE_CRC32C` is a 32-bit number storing the
    /// `CRC32c` checksum of the PROXY protocol header.
    ///
    /// When the checksum is supported by the sender after constructing the
    /// header the sender MUST:
    ///
    ///  - Initialize the checksum field to '0's.
    ///  - Calculate the `CRC32c` checksum of the PROXY header as described in
    ///    RFC4960, Appendix B.
    ///  - Put the resultant value into the checksum field, and leave the rest
    ///    of the bits unchanged.
    ///
    /// If the checksum is provided as part of the PROXY header and the checksum
    /// functionality is supported by the receiver, the receiver MUST:
    ///
    ///  - Store the received `CRC32c` checksum value aside.
    ///  - Replace the 32 bits of the checksum field in the received PROXY
    ///    header with all '0's and calculate a `CRC32c` checksum value of the
    ///    whole PROXY header.
    ///  - Verify that the calculated `CRC32c` checksum is the same as the
    ///    received `CRC32c` checksum. If it is not, the receiver MUST treat the
    ///    TCP connection providing the header as invalid.
    ///
    /// The default procedure for handling an invalid TCP connection is to abort
    /// it.
    CRC32C = 0x03,

    /// The TLV of this type should be ignored when parsed. The value is zero or
    /// more bytes. Can be used for data padding or alignment. Note that it can
    /// be used to align only by 3 or more bytes because a TLV can not be
    /// smaller than that.
    NoOp = 0x04,

    /// The value of the type `PP2_TYPE_UNIQUE_ID` is an opaque byte sequence of
    /// up to 128 bytes generated by the upstream proxy that uniquely identifies
    /// the connection.
    ///
    /// The unique ID can be used to easily correlate connections across
    /// multiple layers of proxies, without needing to look up IP addresses and
    /// port numbers.
    UniqueId = 0x05,

    /// The type `PP2_TYPE_NETNS` defines the value as the US-ASCII string
    /// representation of the namespace's name.
    NetworkNamespace = 0x30,
}

impl ExtensionType {
    #[inline]
    const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            v if v == Self::ALPN as u8 => Self::ALPN,
            v if v == Self::Authority as u8 => Self::Authority,
            v if v == Self::CRC32C as u8 => Self::CRC32C,
            v if v == Self::NoOp as u8 => Self::NoOp,
            v if v == Self::UniqueId as u8 => Self::UniqueId,
            v if v == Self::NetworkNamespace as u8 => Self::NetworkNamespace,
            _ => return None,
        })
    }
}

/// A type-length-value (TLV) extension in the PROXY Protocol v2 header.
#[derive(Debug, Clone, Copy)]
pub struct ExtensionRef<'a> {
    /// The type of the extension.
    typ: u8,

    #[allow(unused)]
    /// The length of the value in bytes.
    len: u16,

    /// The value of the extension.
    payload: &'a [u8],
}

impl<'a> ExtensionRef<'a> {
    #[inline]
    /// Creates a new `ExtensionRef` from the given given type and payload.
    ///
    /// If the length of the payload exceeds `u16::MAX`, returns `None`.
    pub const fn new(typ: ExtensionType, payload: &'a [u8]) -> Option<Self> {
        Self::new_custom(typ as u8, payload)
    }

    #[inline]
    /// Creates a new `ExtensionRef` from the given custom type and payload.
    pub const fn new_custom(typ: u8, payload: &'a [u8]) -> Option<Self> {
        let len = payload.len();

        if len > u16::MAX as usize {
            return None; // Length exceeds maximum allowed size
        }

        Some(Self {
            typ,
            len: len as u16,
            payload,
        })
    }

    #[inline]
    /// Returns the type of the extension.
    ///
    /// If the type is not recognized, returns an `Err` with the raw type byte.
    pub const fn typ(&self) -> Result<ExtensionType, u8> {
        match ExtensionType::from_u8(self.typ) {
            Some(typ) => Ok(typ),
            None => Err(self.typ),
        }
    }

    #[inline]
    /// Returns the payload of the extension.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    #[inline]
    #[cfg(feature = "feat-codec-encode")]
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len as usize);
        buf.push(self.typ);
        buf.extend(&self.len.to_be_bytes());
        buf.extend(self.payload);
    }

    #[inline]
    #[cfg(feature = "feat-codec-decode")]
    /// Decodes a single "type-length-value" extension from the provided reader.
    ///
    /// # Safety
    ///
    /// The caller must validate the header's total length before calling this
    /// method. Returns `Err(())` if the header is malformed or corrupted.
    pub(crate) fn decode(reader: &mut Reader<'a>) -> Result<Option<Self>, DecodeError> {
        let Ok(typ) = reader.read_u8() else {
            // No more extensions to read
            return Ok(None);
        };
        let Ok(len) = reader.read_u16() else {
            return Err(DecodeError::MalformedData);
        };
        let Ok(payload) = reader.take(len as usize) else {
            return Err(DecodeError::MalformedData);
        };

        Ok(Some(Self { typ, len, payload }))
    }
}
