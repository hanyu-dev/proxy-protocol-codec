#![doc = include_str!("../README.md")]
#![no_std]
#![allow(clippy::must_use_candidate, reason = "XXX")]
#![allow(clippy::return_self_not_must_use, reason = "XXX")]

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

    #[allow(clippy::result_unit_err, reason = "XXX")]
    #[allow(clippy::missing_errors_doc, reason = "XXX")]
    #[inline]
    /// Peeks into the given buffer to determine if it contains a valid PROXY
    /// Protocol version magic.
    ///
    /// ## Behaviours
    ///
    /// If the buffer is too short to determine the version, `Ok(None)` is
    /// returned. If the buffer contains a valid version magic,
    /// `Ok(Some(Version))` is returned. Otherwise, `Err(())` is returned.
    ///
    /// ```
    /// # use proxy_protocol_codec::Version;
    /// let v1_magic = Version::MAGIC_V1.as_bytes();
    /// let v2_magic = Version::MAGIC_V2;
    /// assert_eq!(Version::peek(v1_magic), Ok(Some(Version::V1)));
    /// assert_eq!(Version::peek(&v1_magic[..3]), Ok(None));
    /// assert_eq!(Version::peek(v2_magic), Ok(Some(Version::V2)));
    /// assert_eq!(Version::peek(&v2_magic[..6]), Ok(None));
    /// # assert_eq!(Version::peek(&[0]), Err(()));
    /// ```
    pub fn peek(buf: &[u8]) -> Result<Option<Self>, ()> {
        const V1_MAGIC_LEN: usize = Version::MAGIC_V1.len();
        const V2_MAGIC_LEN: usize = Version::MAGIC_V2.len();

        match buf.len() {
            0 => Ok(None),
            V2_MAGIC_LEN.. if buf.starts_with(Self::MAGIC_V2) => Ok(Some(Self::V2)),
            1..V2_MAGIC_LEN if Self::MAGIC_V2.starts_with(buf) => Ok(None),
            V1_MAGIC_LEN.. if buf.starts_with(Self::MAGIC_V1.as_bytes()) => Ok(Some(Self::V1)),
            1..V1_MAGIC_LEN if Self::MAGIC_V1.as_bytes().starts_with(buf) => Ok(None),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod smoking {
    #[test]
    fn test_v1() {
        use crate::v1::{AddressPair, Header};

        // PROXY Protocol v1 (text format), TCP4
        let address_pair = AddressPair::Inet {
            src_ip: "127.0.0.1".parse().unwrap(),
            dst_ip: "127.0.0.2".parse().unwrap(),
            src_port: 8080,
            dst_port: 80,
        };
        let header = Header::new(address_pair);

        assert_eq!(header.encode(), "PROXY TCP4 127.0.0.1 127.0.0.2 8080 80\r\n");

        // PROXY Protocol v1 (text format), TCP6
        let address_pair = AddressPair::Inet6 {
            src_ip: "::1".parse().unwrap(),
            dst_ip: "::2".parse().unwrap(),
            src_port: 8080,
            dst_port: 80,
        };
        let header = Header::new(address_pair);

        assert_eq!(header.encode(), "PROXY TCP6 ::1 ::2 8080 80\r\n");

        // PROXY Protocol v1 (text format), UNKNOWN
        let address_pair = AddressPair::Unspecified;
        let header = Header::new(address_pair);

        assert_eq!(header.encode(), "PROXY UNKNOWN\r\n");
    }

    #[test]
    fn test_v2() {
        use crate::v2::{AddressPair, Decoded, DecodedHeader, Header, Protocol};

        // PROXY Protocol v1 (binary format)
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        let encoded = header
            .encode()
            .write_ext_alpn(b"h2")
            .unwrap()
            .write_ext_authority(b"example.com")
            .unwrap()
            .write_ext_no_op(0)
            .unwrap()
            .write_ext_unique_id(b"unique_id")
            .unwrap()
            .write_ext_network_namespace(b"network_namespace")
            .unwrap()
            .finish()
            .unwrap();

        let Decoded::Some(DecodedHeader {
            header: decoded_header,
            extensions: _,
        }) = Header::decode(&encoded).unwrap()
        else {
            panic!("failed to decode v2 header");
        };

        assert_eq!(header, decoded_header);
    }
}
