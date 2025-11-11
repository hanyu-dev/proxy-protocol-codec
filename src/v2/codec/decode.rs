//! PROXY Protocol v2 header decoder

#[cfg(feature = "feat-alloc")]
use alloc::vec::Vec;
use core::cmp::min;
use core::iter::FusedIterator;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::num::NonZeroUsize;

use slicur::Reader;

use crate::v2::model::{
    AddressPair, Command, ExtensionRef, Family, Protocol, ADDR_INET6_SIZE, ADDR_INET_SIZE, ADDR_UNIX_SIZE,
    BYTE_VERSION, HEADER_SIZE,
};
use crate::v2::Header;

#[derive(Debug)]
/// PROXY Protocol v2 header decoder.
///
/// See [`decode`](Self::decode) for more details.
pub struct HeaderDecoder;

// Masks the right 4-bits so only the left 4-bits are
// present.
const MASK_HI: u8 = 0xF0;

// Masks the left 4-bits so only the right 4-bits are
// present.
const MASK_LO: u8 = 0x0F;

/// See [`Command`].
const COMMAND_LOCAL: u8 = Command::Local as u8;

/// See [`Command`].
const COMMAND_PROXY: u8 = Command::Proxy as u8;

/// See [`Family`].
const FAMILY_UNSPECIFIED: u8 = Family::Unspecified as u8;

/// See [`Family`].
const FAMILY_INET: u8 = Family::Inet as u8;

/// See [`Family`].
const FAMILY_INET6: u8 = Family::Inet6 as u8;

/// See [`Family`].
const FAMILY_UNIX: u8 = Family::Unix as u8;

/// See [`Protocol`].
const PROTOCOL_UNSPECIFIED: u8 = Protocol::Unspecified as u8;

/// See [`Protocol`].
const PROTOCOL_STREAM: u8 = Protocol::Stream as u8;

/// See [`Protocol`].
const PROTOCOL_DGRAM: u8 = Protocol::Dgram as u8;

impl HeaderDecoder {
    #[allow(clippy::missing_panics_doc)]
    /// Attempts to decode the PROXY Protocol v2 header from its bytes
    /// representation.
    ///
    /// The caller MAY first **peek** exactly **[`HEADER_SIZE`]** bytes from the
    /// network input into a buffer and then [`decode`](Self::decode) it, to
    /// detect the presence of a PROXY Protocol v2 header. If less than 16
    /// bytes are peeked, the caller MAY reject the connection, or treat the
    /// connection as a normal one w/o PROXY Protocol v2 header.
    ///
    /// When the buffer is not prefixed with PROXY Protocol v2 header
    /// [`MAGIC`](Header::MAGIC), this method returns [`Decoded::None`]. The
    /// caller MAY reject the connection, or treat the connection as a
    /// normal one w/o PROXY Protocol v2 header.
    ///
    /// When a PROXY protocol v2 header is detected, [`Decoded::Partial`] is
    /// returned (this is what we expect, since we only have the MAGIC bytes
    /// peeked). The caller SHOULD then **read** exactly [`HEADER_SIZE`] +
    /// `remaining_bytes` bytes into a buffer (may reuse the buffer peeking
    /// the MAGIC bytes) and [`decode`](Self::decode) it again.
    ///
    /// When any error is returned, the caller SHOULD reject the connection.
    ///
    /// When there're extensions in the PROXY Protocol v2 header, the caller
    /// SHOULD read the extensions to check if they are malformed or not.
    /// See [`DecodedExtensions`] for more details.
    pub fn decode(buf: &[u8]) -> Result<Decoded<'_>, DecodeError> {
        // 1. Magic bytes
        {
            let magic_length = min(Header::MAGIC.len(), buf.len());

            if buf[..magic_length] != Header::MAGIC[..magic_length] {
                return Ok(Decoded::None);
            }
        }

        // 2. Read header
        match HEADER_SIZE.checked_sub(buf.len()).and_then(NonZeroUsize::new) {
            None => {}
            Some(remaining_bytes) => {
                // The caller should read 16 bytes first, in fact.
                #[cfg(feature = "feat-nightly")]
                core::hint::cold_path();

                return Ok(Decoded::Partial(remaining_bytes));
            }
        }

        // 2.1. version
        match buf[12] & MASK_HI {
            BYTE_VERSION => {}
            v => {
                #[cfg(feature = "feat-nightly")]
                core::hint::cold_path();

                return Err(DecodeError::InvalidVersion(v));
            }
        };

        // 2.2. command
        let command = match buf[12] & MASK_LO {
            COMMAND_LOCAL => Command::Local,
            COMMAND_PROXY => Command::Proxy,
            c => {
                #[cfg(feature = "feat-nightly")]
                core::hint::cold_path();

                return Err(DecodeError::InvalidCommand(c));
            }
        };

        // 3.1. addr_family
        let addr_family = match buf[13] & MASK_HI {
            FAMILY_UNSPECIFIED => Family::Unspecified,
            FAMILY_INET => Family::Inet,
            FAMILY_INET6 => Family::Inet6,
            FAMILY_UNIX => Family::Unix,
            f => {
                #[cfg(feature = "feat-nightly")]
                core::hint::cold_path();

                return Err(DecodeError::InvalidFamily(f));
            }
        };

        // 3.2. protocol
        let protocol = match buf[13] & MASK_LO {
            PROTOCOL_UNSPECIFIED => Protocol::Unspecified,
            PROTOCOL_STREAM => Protocol::Stream,
            PROTOCOL_DGRAM => Protocol::Dgram,
            p => {
                #[cfg(feature = "feat-nightly")]
                core::hint::cold_path();

                return Err(DecodeError::InvalidProtocol(p));
            }
        };

        // 4. remaining_len
        let remaining_len = u16::from_be_bytes([buf[14], buf[15]]);

        // Check if the buffer has enough data for the the payload
        let payload = match HEADER_SIZE
            .checked_add(remaining_len as usize)
            .ok_or(DecodeError::MalformedData)?
            .checked_sub(buf.len())
            .map(NonZeroUsize::new)
        {
            Some(None) => &buf[HEADER_SIZE..],
            Some(Some(remaining_bytes)) => return Ok(Decoded::Partial(remaining_bytes)),
            None => {
                #[cfg(feature = "feat-nightly")]
                core::hint::cold_path();

                // HEADER_SIZE + remaining_len < buf.len(), reject trailing data
                return Err(DecodeError::TrailingData);
            }
        };

        let (address_pair, extensions) = match addr_family {
            Family::Unspecified => (AddressPair::Unspecified, payload),
            Family::Inet => {
                if payload.len() < ADDR_INET_SIZE {
                    #[cfg(feature = "feat-nightly")]
                    core::hint::cold_path();

                    return Err(DecodeError::MalformedData);
                }

                (
                    AddressPair::Inet {
                        src_ip: Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(&payload[0..4]).unwrap()),
                        dst_ip: Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(&payload[4..8]).unwrap()),
                        src_port: u16::from_be_bytes([payload[8], payload[9]]),
                        dst_port: u16::from_be_bytes([payload[10], payload[11]]),
                    },
                    &payload[ADDR_INET_SIZE..],
                )
            }
            Family::Inet6 => {
                if payload.len() < ADDR_INET6_SIZE {
                    #[cfg(feature = "feat-nightly")]
                    core::hint::cold_path();

                    return Err(DecodeError::MalformedData);
                }

                (
                    AddressPair::Inet6 {
                        src_ip: Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(&payload[0..16]).unwrap()),
                        dst_ip: Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(&payload[16..32]).unwrap()),
                        src_port: u16::from_be_bytes([payload[32], payload[33]]),
                        dst_port: u16::from_be_bytes([payload[34], payload[35]]),
                    },
                    &payload[ADDR_INET6_SIZE..],
                )
            }
            Family::Unix => {
                if payload.len() < ADDR_UNIX_SIZE {
                    #[cfg(feature = "feat-nightly")]
                    core::hint::cold_path();

                    return Err(DecodeError::MalformedData);
                }

                (
                    AddressPair::Unix {
                        src_addr: payload[0..108].try_into().unwrap(),
                        dst_addr: payload[108..216].try_into().unwrap(),
                    },
                    &payload[ADDR_UNIX_SIZE..],
                )
            }
        };

        match command {
            Command::Local => Ok(Decoded::Some(DecodedHeader {
                header: Header::new_local(),
                extensions: DecodedExtensions::const_from(extensions),
            })),
            Command::Proxy => Ok(Decoded::Some(DecodedHeader {
                header: Header::new_proxy(protocol, address_pair),
                extensions: DecodedExtensions::const_from(extensions),
            })),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
/// The result of decoding a PROXY Protocol v2 header.
pub enum Decoded<'a> {
    /// The PROXY Protocol v2 header and its extensions decoded.
    Some(DecodedHeader<'a>),

    /// Partial data, the caller should read more data.
    Partial(NonZeroUsize),

    /// Not a PROXY Protocol v2 header.
    None,
}

#[derive(Debug)]
/// A wrapper around the PROXY Protocol v2 header and its extensions.
pub struct DecodedHeader<'a> {
    /// The PROXY Protocol v2 header.
    pub header: Header,

    /// Extensions of the PROXY Protocol v2 header.
    pub extensions: DecodedExtensions<'a>,
}

wrapper_lite::wrapper! {
    #[wrapper_impl(Deref<[u8]>)]
    #[derive(Debug)]
    /// A wrapper around a slice of bytes representing the encoded extensions
    /// of the PROXY Protocol v2 header.
    ///
    /// This implements `IntoIterator` to iterate over the extensions. See
    /// [`DecodedExtensionsIter`] for more details.
    pub struct DecodedExtensions<'a>(&'a [u8]);
}

impl<'a> DecodedExtensions<'a> {
    #[cfg(feature = "feat-alloc")]
    /// Iterates over the extensions of the PROXY Protocol v2 header and
    /// collects them into a `Vec<ExtensionRef>`.
    pub fn collect(self) -> Result<Vec<ExtensionRef<'a>>, DecodeError> {
        self.into_iter().collect()
    }
}

impl<'a> IntoIterator for DecodedExtensions<'a> {
    type IntoIter = DecodedExtensionsIter<'a>;
    type Item = Result<ExtensionRef<'a>, DecodeError>;

    fn into_iter(self) -> Self::IntoIter {
        DecodedExtensionsIter {
            inner: Some(Reader::init(self.inner)),
        }
    }
}

#[derive(Debug)]
/// Iterator over the extensions of the PROXY Protocol v2 header.
///
/// This iterator yields [`ExtensionRef`]s, which are references to the
/// decoded extensions. If an error occurs while decoding an extension, the
/// iterator will yield an `Err(DecodeError)` instead.
///
/// The iterator is fused, meaning that once it returns `None`, it will
/// continue to return `None` on subsequent calls.
pub struct DecodedExtensionsIter<'a> {
    inner: Option<Reader<'a>>,
}

impl<'a> Iterator for DecodedExtensionsIter<'a> {
    type Item = Result<ExtensionRef<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.as_mut() {
            Some(reader) => match ExtensionRef::decode(reader) {
                Ok(Some(extension)) => Some(Ok(extension)),
                Ok(None) => {
                    // No more extensions, stop iterating.
                    self.inner = None;

                    None
                }
                Err(err) => {
                    // An error occurred while decoding an extension, return the error.
                    self.inner = None;

                    Some(Err(err))
                }
            },
            None => None,
        }
    }
}

impl<'a> FusedIterator for DecodedExtensionsIter<'a> {}

#[derive(Debug)]
#[derive(thiserror::Error)]
/// Errors that can occur while decoding a PROXY Protocol v2 header.
pub enum DecodeError {
    #[error("Invalid PROXY Protocol version: {0}")]
    /// Invalid PROXY Protocol version
    InvalidVersion(u8),

    #[error("Invalid PROXY Protocol command: {0}")]
    /// Invalid PROXY Protocol command
    InvalidCommand(u8),

    #[error("Invalid proxy address family: {0}")]
    /// Invalid proxy address family
    InvalidFamily(u8),

    #[error("Invalid proxy transport protocol: {0}")]
    /// Invalid proxy transport protocol
    InvalidProtocol(u8),

    #[error("Trailing data after the header")]
    /// The buffer contains trailing data after the PROXY Protocol v2 header.
    TrailingData,

    #[error("Malformed data")]
    /// The data is malformed, e.g. the length of an extension does not match
    /// the actual data length.
    MalformedData,
}
