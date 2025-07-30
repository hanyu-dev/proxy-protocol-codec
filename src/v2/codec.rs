//! PROXY Protocol v2 header encoding and decoding.

#[cfg(feature = "feat-codec-decode")]
pub mod decode;
#[cfg(feature = "feat-codec-encode")]
pub mod encode;

#[cfg(feature = "feat-codec-decode")]
pub use decode::{DecodeError, Decoded, DecodedExtensionsIter, DecodedHeader, HeaderDecoder};
#[cfg(feature = "feat-codec-encode")]
pub use encode::{EncodeError, Encoded, HeaderEncoder};
