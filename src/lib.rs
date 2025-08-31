//! PROXY Protocol codec.
//!
//! See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

#![no_std]
#![cfg_attr(feature = "feat-nightly", feature(cold_path))]

#[cfg(feature = "feat-codec-v2-uni-addr")]
compile_error!("The `feat-codec-v2-uni-addr` feature is deprecated. Please use the `feat-uni-addr` feature instead.");

#[cfg(feature = "feat-codec-v1")]
pub mod v1;
#[cfg(feature = "feat-codec-v2")]
pub mod v2;

#[cfg(any(test, feature = "feat-alloc"))]
extern crate alloc;

#[cfg(any(test, feature = "feat-std"))]
extern crate std;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The supported PROXY Protocol versions.
pub enum Version {
    /// PROXY Protocol version 1
    V1,

    /// PROXY Protocol version 2
    V2,
}

impl Version {
    /// The magic bytes that indicate a PROXY Protocol v1 header.
    pub const MAGIC_V1: &'static str = "PROXY";
    /// The magic bytes that indicate a PROXY Protocol v2 header.
    pub const MAGIC_V2: &'static [u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

    #[allow(clippy::result_unit_err)]
    #[inline]
    /// Peeks into the given buffer to determine if it contains a valid PROXY
    /// Protocol version magic.
    ///
    /// ## Behaviours
    ///
    /// If the buffer is too short to determine the version, `Ok(None)` is
    /// returned. If the buffer contains a valid version magic,
    /// `Ok(Some(Version))` is returned. Otherwise, `Err(())` is returned.
    pub fn peek(buf: &[u8]) -> Result<Option<Self>, ()> {
        const V1_MAGIC_LEN: usize = Version::MAGIC_V1.len();
        const V2_MAGIC_LEN: usize = Version::MAGIC_V2.len();

        #[allow(overlapping_range_endpoints)]
        // Rust 1.77 doesn't support exclusive range endpoints in pattern matching.
        match buf.len() {
            0 => Ok(None),
            V2_MAGIC_LEN.. if buf.starts_with(Self::MAGIC_V2) => Ok(Some(Self::V2)),
            V1_MAGIC_LEN.. if buf.starts_with(Self::MAGIC_V1.as_bytes()) => Ok(Some(Self::V1)),
            1..=V2_MAGIC_LEN if Self::MAGIC_V2.starts_with(buf) => Ok(None),
            1..=V1_MAGIC_LEN if Self::MAGIC_V1.as_bytes().starts_with(buf) => Ok(None),
            _ => Err(()),
        }
    }
}
