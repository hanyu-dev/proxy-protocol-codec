//! PROXY Protocol v2 header encoder

pub mod stage;

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::v2::codec::encode::stage::{Addr, FamProto, Finished, Len, Magic, VerCmd};
use crate::v2::model::{
    AddressPair, Command, ExtensionRef, ExtensionType, Family, Protocol, ADDR_INET6_SIZE, ADDR_INET_SIZE,
    ADDR_UNIX_SIZE, BYTE_VERSION, HEADER_SIZE,
};
use crate::v2::Header;

#[derive(Debug)]
/// Encoder for a PROXY Protocol v2 header.
pub struct HeaderEncoder<Stage = Magic> {
    inner: Vec<u8>,

    /// Marker to indicate the encoding / encoding stage.
    _stage: PhantomData<Stage>,
}

impl HeaderEncoder<Magic> {
    /// Encodes a PROXY Protocol v2 header from the given `Header`.
    pub fn encode(header: &Header) -> HeaderEncoder<Finished> {
        let this = Self {
            inner: Vec::with_capacity(HEADER_SIZE),
            _stage: PhantomData,
        };

        match header.command() {
            Command::Local => this
                .write_magic()
                .write_ver_cmd(Command::Local)
                .write_fam_proto(Family::Unspecified, Protocol::Unspecified)
                .write_len(0)
                .write_addr(&AddressPair::Unspecified),
            Command::Proxy => this
                .write_magic()
                .write_ver_cmd(Command::Proxy)
                .write_fam_proto(header.address_pair().address_family(), *header.protocol())
                .write_len(0)
                .write_addr(header.address_pair()),
        }
    }

    #[inline(always)]
    fn write_magic(mut self) -> HeaderEncoder<VerCmd> {
        self.inner.extend(Header::MAGIC);

        HeaderEncoder {
            inner: self.inner,
            _stage: PhantomData,
        }
    }
}

impl HeaderEncoder<VerCmd> {
    #[inline(always)]
    fn write_ver_cmd(mut self, command: Command) -> HeaderEncoder<FamProto> {
        self.inner.push(BYTE_VERSION | command as u8);

        HeaderEncoder {
            inner: self.inner,
            _stage: PhantomData,
        }
    }
}

impl HeaderEncoder<FamProto> {
    #[inline(always)]
    fn write_fam_proto(mut self, family: Family, protocol: Protocol) -> HeaderEncoder<Len> {
        self.inner.push(family as u8 | protocol as u8);

        HeaderEncoder {
            inner: self.inner,
            _stage: PhantomData,
        }
    }
}

impl HeaderEncoder<Len> {
    #[inline(always)]
    fn write_len(mut self, len: u16) -> HeaderEncoder<Addr> {
        self.inner.extend(len.to_be_bytes());

        HeaderEncoder {
            inner: self.inner,
            _stage: PhantomData,
        }
    }
}

impl HeaderEncoder<Addr> {
    #[inline(always)]
    fn write_addr(mut self, address_pair: &AddressPair) -> HeaderEncoder<Finished> {
        match address_pair {
            AddressPair::Unspecified => HeaderEncoder {
                inner: self.inner,
                _stage: PhantomData,
            },
            AddressPair::Inet {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => {
                self.inner.reserve(ADDR_INET_SIZE);
                self.inner.extend(src_ip.octets());
                self.inner.extend(dst_ip.octets());
                self.inner.extend(src_port.to_be_bytes());
                self.inner.extend(dst_port.to_be_bytes());

                HeaderEncoder {
                    inner: self.inner,
                    _stage: PhantomData,
                }
            }
            AddressPair::Inet6 {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => {
                self.inner.reserve(ADDR_INET6_SIZE);
                self.inner.extend(src_ip.octets());
                self.inner.extend(dst_ip.octets());
                self.inner.extend(src_port.to_be_bytes());
                self.inner.extend(dst_port.to_be_bytes());

                HeaderEncoder {
                    inner: self.inner,
                    _stage: PhantomData,
                }
            }
            AddressPair::Unix { src_addr, dst_addr } => {
                self.inner.reserve(ADDR_UNIX_SIZE);
                self.inner.extend(src_addr);
                self.inner.extend(dst_addr);

                HeaderEncoder {
                    inner: self.inner,
                    _stage: PhantomData,
                }
            }
        }
    }
}

impl HeaderEncoder<Finished> {
    #[inline]
    /// Writes the `ALPN` extension bytes to the header.
    ///
    /// See [`ExtensionType::ALPN`].
    pub fn write_ext_alpn(self, alpn: &[u8]) -> Result<Self, EncodeError> {
        Ok(self.write_ext_custom(ExtensionRef::new(ExtensionType::ALPN, alpn).ok_or(EncodeError::ExtensionTooLong)?))
    }

    #[inline]
    /// Writes the `Authority` extension bytes to the header.
    ///
    /// See [`ExtensionType::Authority`].
    pub fn write_ext_authority(self, authority: &[u8]) -> Result<Self, EncodeError> {
        Ok(self.write_ext_custom(
            ExtensionRef::new(ExtensionType::Authority, authority).ok_or(EncodeError::ExtensionTooLong)?,
        ))
    }

    #[inline]
    /// Writes padding zeros to the header, the total size is `3 + padding`.
    ///
    /// See [`ExtensionType::NoOp`].
    pub fn write_ext_no_op(mut self, padding: u16) -> Result<Self, EncodeError> {
        self.inner.push(ExtensionType::NoOp as u8);
        self.inner.extend(padding.to_be_bytes());
        self.inner.resize(self.inner.len() + padding as usize, 0);
        Ok(self)
    }

    #[inline]
    #[allow(clippy::missing_panics_doc)]
    /// Writes the `UniqueId` extension bytes to the header.
    ///
    /// See [`ExtensionType::UniqueId`].
    pub fn write_ext_unique_id(self, payload: &[u8]) -> Result<Self, EncodeError> {
        if payload.len() > 128 {
            return Err(EncodeError::ExtensionTooLong);
        }

        // Safety: payload.len() <= 128 < u16::MAX
        Ok(self.write_ext_custom(ExtensionRef::new(ExtensionType::NetworkNamespace, payload).unwrap()))
    }

    #[inline]
    /// Writes the `NetworkNamespace` extension bytes to the header.
    ///
    /// See [`ExtensionType::NetworkNamespace`].
    pub fn write_ext_network_namespace(self, payload: &[u8]) -> Result<Self, EncodeError> {
        Ok(self.write_ext_custom(
            ExtensionRef::new(ExtensionType::NetworkNamespace, payload).ok_or(EncodeError::ExtensionTooLong)?,
        ))
    }

    #[inline]
    /// Writes a custom extension to the header.
    ///
    /// Notice: will not check if the `typ` is valid.
    pub fn write_ext_custom(mut self, extension: ExtensionRef<'_>) -> Self {
        extension.encode(&mut self.inner);
        self
    }

    #[inline]
    fn update_length(&mut self, additional: u16) -> Result<(), EncodeError> {
        let Ok(length) = u16::try_from(self.inner.len() - HEADER_SIZE) else {
            return Err(EncodeError::HeaderTooLong);
        };

        self.inner[14..16].copy_from_slice(&(length + additional).to_be_bytes());

        Ok(())
    }

    #[cfg(feature = "feat-codec-v2-crc32c")]
    #[allow(clippy::missing_panics_doc)]
    /// Calculates and writes the `CRC32C` extension bytes to the header and
    /// finalizes the header encoding.
    pub fn finish_with_crc32c(mut self) -> Result<Vec<u8>, EncodeError> {
        const FIXED_CRC32C_EXTENSION: [u8; 6] = [
            ExtensionType::CRC32C as u8,
            (u32::BITS / 8) as u8, // Length of the CRC32C value
            0,
            0,
            0,
            0, // Placeholder for the CRC32C value
        ];

        self.update_length(FIXED_CRC32C_EXTENSION.len() as u16)?;

        let crc32c_bytes =
            crc32c::crc32c_append(crc32c::crc32c_append(0, &self.inner), &FIXED_CRC32C_EXTENSION).to_be_bytes();

        // Safety: FIXED_CRC32C_EXTENSION.len() == 6 < u16::MAX
        self.write_ext_custom(ExtensionRef::new(ExtensionType::CRC32C, &crc32c_bytes).unwrap())
            .finish()
    }

    #[inline(always)]
    /// Finalizes the header encoding.
    pub fn finish(mut self) -> Result<Vec<u8>, EncodeError> {
        self.update_length(0)?;

        Ok(self.inner)
    }
}

#[cfg(feature = "feat-codec-encode")]
#[derive(Debug)]
#[derive(thiserror::Error)]
/// Errors that can occur while encoding a PROXY Protocol v2 header.
pub enum EncodeError {
    #[error("The src / dst address families do not match.")]
    /// The src / dst address families do not match.
    FamilyMismatch,

    #[error("The address is not a valid Unix address")]
    /// The address is not a valid Unix address (e.g., length out-of-bounds).
    InvalidUnixAddress,

    #[error("Header bytes too long")]
    /// Header bytes too long
    HeaderTooLong,

    #[error("The extension payload is too long.")]
    /// The extension payload is too long.
    ExtensionTooLong,
}
