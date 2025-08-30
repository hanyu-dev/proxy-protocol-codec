//! PROXY Protocol v1.

pub mod model;

#[cfg(feature = "feat-codec-encode")]
use alloc::string::{String, ToString};
use core::{fmt, str};

pub use model::AddressPair;
#[cfg(feature = "feat-codec-decode")]
pub use model::Decoded;

/// The maximum length of a PROXY Protocol v1 header, including the magic bytes,
/// protocol, addresses, ports, and the CRLF at the end.
pub const MAXIMUM_LENGTH: usize = 107;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The PROXY Protocol v1 header.
pub struct Header {
    /// The address family and protocol used in the PROXY Protocol v1 header.
    protocol: FamProto,

    /// The source address in the PROXY Protocol v1 header.
    address_pair: AddressPair,
}

#[cfg(feature = "feat-codec-encode")]
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address_pair {
            AddressPair::Unspecified => write!(f, "{} {FAM_PROTO_UNKNOWN}\r\n", Self::MAGIC),
            AddressPair::Inet {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => write!(
                f,
                "{} {FAM_PROTO_TCP4} {src_ip} {dst_ip} {src_port} {dst_port}\r\n",
                Self::MAGIC
            ),
            AddressPair::Inet6 {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => write!(
                f,
                "{} {FAM_PROTO_TCP6} {src_ip} {dst_ip} {src_port} {dst_port}\r\n",
                Self::MAGIC
            ),
        }
    }
}

impl Header {
    /// PROXY Protocol v1 magic bytes.
    pub const MAGIC: &'static str = crate::Version::MAGIC_V1;

    /// Creates a new PROXY Protocol v1 header.
    pub const fn new(address_pair: AddressPair) -> Self {
        Header {
            protocol: match &address_pair {
                AddressPair::Inet { .. } => FamProto::TCP4,
                AddressPair::Inet6 { .. } => FamProto::TCP6,
                AddressPair::Unspecified => FamProto::Unknown,
            },
            address_pair,
        }
    }

    #[inline]
    /// Returns the address pair of the PROXY Protocol v1 header.
    pub const fn address_pair(self) -> AddressPair {
        self.address_pair
    }

    #[inline]
    #[cfg(feature = "feat-codec-encode")]
    /// Encodes the PROXY Protocol v1 header into a string representation.
    pub fn encode(&self) -> String {
        self.to_string()
    }

    #[cfg(feature = "feat-codec-decode")]
    /// Try to decode the PROXY Protocol v1 header from the given buffer.
    ///
    /// The caller SHOULD first **peek** exactly **5** bytes from the network
    /// input into a buffer and [`decode`](Self::decode) it, to detect the
    /// presence of a PROXY Protocol v1 header.
    ///
    /// When the buffer is not prefixed with PROXY Protocol v1 header
    /// [`MAGIC`](Header::MAGIC), this method returns [`Decoded::None`]. The
    /// caller MAY reject the connection, or treat the connection as a
    /// normal one w/o PROXY Protocol v1 header.
    ///
    /// When a PROXY protocol v1 header is detected, [`Decoded::Partial`] is
    /// returned (this is what we expect, since we only have the MAGIC bytes
    /// peeked). The caller SHOULD read from network input into a buffer (may
    /// reuse the buffer peeking the MAGIC bytes) until the first `\n`, then
    /// [`decode`](Self::decode) it. This method will reject bytes w/o CRLF, and
    /// any trailing bytes after CRLF.
    ///
    /// The caller MAY ensure that the length of the `header_bytes` does not
    /// exceed the [`MAXIMUM_LENGTH`].
    ///
    /// When any error is returned, the caller SHOULD reject the connection.
    pub fn decode(header_bytes: &[u8]) -> Result<Decoded, DecodeError> {
        // 1. Magic bytes flight check
        {
            use core::cmp::min;

            let magic_length = min(Header::MAGIC.len(), header_bytes.len());

            if header_bytes[..magic_length] != Header::MAGIC.as_bytes()[..magic_length] {
                return Ok(Decoded::None);
            }
        }

        if header_bytes.len() > MAXIMUM_LENGTH {
            // Too long, will never be a valid PROXY Protocol v1 header.
            return Err(DecodeError::MalformedData("bytes too long"));
        }

        let header_str = str::from_utf8(header_bytes).map_err(|_| DecodeError::MalformedData("not UTF-8"))?;

        // CRLF must be at the end of the header.
        if !header_str.ends_with("\r\n") {
            return Err(DecodeError::MalformedData("missing CRLF or trailing data"));
        }

        let mut header_parts_iter = header_str.split_whitespace();

        // 1. Magic bytes
        let magic = header_parts_iter
            .next()
            .ok_or(DecodeError::MalformedData("missing MAGIC"))?;

        if magic != Header::MAGIC {
            return Ok(Decoded::None);
        }

        // 2. Check the FamProto
        let Some(family_protocol) = header_parts_iter.next() else {
            return Err(DecodeError::InvalidFamProto);
        };

        // 3. Check the address family and protocol.
        let (protocol, address_pair) = match family_protocol {
            FAM_PROTO_TCP4 => {
                let src_ip = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("SRC_IP"))
                    .and_then(|s| s.parse().map_err(|_| DecodeError::MalformedData("SRC_IP")))?;

                let dst_ip = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("DST_IP"))
                    .and_then(|s| s.parse().map_err(|_| DecodeError::MalformedData("DST_IP")))?;

                let src_port = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("SRC_PORT"))
                    .and_then(|s| s.parse::<u16>().map_err(|_| DecodeError::MalformedData("SRC_PORT")))?;

                let dst_port = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("DST_PORT"))
                    .and_then(|s| s.parse::<u16>().map_err(|_| DecodeError::MalformedData("DST_PORT")))?;

                (
                    FamProto::TCP4,
                    AddressPair::Inet {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    },
                )
            }
            FAM_PROTO_TCP6 => {
                let src_ip = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("SRC_IP"))
                    .and_then(|s| s.parse().map_err(|_| DecodeError::MalformedData("SRC_IP")))?;

                let dst_ip = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("DST_IP"))
                    .and_then(|s| s.parse().map_err(|_| DecodeError::MalformedData("DST_IP")))?;

                let src_port = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("SRC_PORT"))
                    .and_then(|s| s.parse::<u16>().map_err(|_| DecodeError::MalformedData("SRC_PORT")))?;

                let dst_port = header_parts_iter
                    .next()
                    .ok_or(DecodeError::MissingData("DST_PORT"))
                    .and_then(|s| s.parse::<u16>().map_err(|_| DecodeError::MalformedData("DST_PORT")))?;

                (
                    FamProto::TCP6,
                    AddressPair::Inet6 {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    },
                )
            }
            FAM_PROTO_UNKNOWN => {
                // Ignore anything presented before the CRLF
                (FamProto::Unknown, AddressPair::Unspecified)
            }
            _ => {
                return Err(DecodeError::InvalidFamProto);
            }
        };

        Ok(Decoded::Some(Self { protocol, address_pair }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The address family and the transport protocol used in the PROXY Protocol v1
/// header.
enum FamProto {
    /// Unspecified address family and protocol.
    Unknown,

    /// TCP protocol, IPv4.
    TCP4,

    /// TCP protocol, IPv6.
    TCP6,
}

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
const FAM_PROTO_UNKNOWN: &str = "UNKNOWN";

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
const FAM_PROTO_TCP4: &str = "TCP4";

#[cfg(any(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
const FAM_PROTO_TCP6: &str = "TCP6";

#[cfg(feature = "feat-codec-decode")]
#[derive(Debug)]
#[derive(thiserror::Error)]
/// Errors that can occur while decoding a PROXY Protocol v1 header.
pub enum DecodeError {
    #[error("Invalid PROXY addr family & protocol")]
    /// Invalid PROXY addr family & protocol
    InvalidFamProto,

    #[error("Missing data: {0}")]
    /// Invalid PROXY Protocol command
    MissingData(&'static str),

    #[error("Malformed data: {0}")]
    /// The data is malformed, e.g. the length of an extension does not match
    /// the actual data length.
    MalformedData(&'static str),

    #[error("Trailing data after the PROXY Protocol v1 header")]
    /// The buffer contains trailing data after the PROXY Protocol v1 header.
    TrailingData,
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_header_new_tcp4() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1);
        let src_port = 8080;
        let dst_port = 80;

        let address_pair = AddressPair::Inet {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let header = Header::new(address_pair);

        assert_eq!(header.protocol, FamProto::TCP4);
        match header.address_pair {
            AddressPair::Inet {
                src_ip: s_ip,
                dst_ip: d_ip,
                src_port: s_port,
                dst_port: d_port,
            } => {
                assert_eq!(s_ip, src_ip);
                assert_eq!(d_ip, dst_ip);
                assert_eq!(s_port, src_port);
                assert_eq!(d_port, dst_port);
            }
            _ => panic!("Expected Inet address pair"),
        }
    }

    #[test]
    fn test_header_new_tcp6() {
        let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let src_port = 8080;
        let dst_port = 80;

        let address_pair = AddressPair::Inet6 {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let header = Header::new(address_pair);

        assert_eq!(header.protocol, FamProto::TCP6);
        match header.address_pair {
            AddressPair::Inet6 {
                src_ip: s_ip,
                dst_ip: d_ip,
                src_port: s_port,
                dst_port: d_port,
            } => {
                assert_eq!(s_ip, src_ip);
                assert_eq!(d_ip, dst_ip);
                assert_eq!(s_port, src_port);
                assert_eq!(d_port, dst_port);
            }
            _ => panic!("Expected Inet6 address pair"),
        }
    }

    #[test]
    fn test_header_new_unknown() {
        let header = Header::new(AddressPair::Unspecified);
        assert_eq!(header.protocol, FamProto::Unknown);
        assert_eq!(header.address_pair, AddressPair::Unspecified);
    }

    #[test]
    #[cfg(feature = "feat-codec-encode")]
    fn test_encode_tcp4() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1);
        let src_port = 8080;
        let dst_port = 80;

        let address_pair = AddressPair::Inet {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let header = Header::new(address_pair);

        let encoded = header.encode();
        assert_eq!(encoded, "PROXY TCP4 192.168.1.1 10.0.0.1 8080 80\r\n");
    }

    #[test]
    #[cfg(feature = "feat-codec-encode")]
    fn test_encode_tcp6() {
        let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let src_port = 8080;
        let dst_port = 80;

        let address_pair = AddressPair::Inet6 {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let header = Header::new(address_pair);

        let encoded = header.encode();
        assert_eq!(encoded, "PROXY TCP6 2001:db8::1 fe80::1 8080 80\r\n");
    }

    #[test]
    #[cfg(feature = "feat-codec-encode")]
    fn test_encode_unknown() {
        let header = Header::new(AddressPair::Unspecified);
        let encoded = header.encode();
        assert_eq!(encoded, "PROXY UNKNOWN\r\n");
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_valid() {
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1 8080 80\r\n";
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::TCP4);
        match header.address_pair {
            AddressPair::Inet {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => {
                assert_eq!(src_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(src_port, 8080);
                assert_eq!(dst_ip, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(dst_port, 80);
            }
            _ => panic!("Expected Inet address pair"),
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp6_valid() {
        let input = b"PROXY TCP6 2001:db8::1 fe80::1 8080 80\r\n";
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::TCP6);
        match header.address_pair {
            AddressPair::Inet6 {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => {
                assert_eq!(src_ip, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
                assert_eq!(src_port, 8080);
                assert_eq!(dst_ip, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
                assert_eq!(dst_port, 80);
            }
            _ => panic!("Expected Inet6 address pair"),
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_unknown_valid() {
        let input = b"PROXY UNKNOWN\r\n";
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::Unknown);
        assert_eq!(header.address_pair, AddressPair::Unspecified);
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_unknown_with_extra_data() {
        let input = b"PROXY UNKNOWN some extra data here\r\n";
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::Unknown);
        assert_eq!(header.address_pair, AddressPair::Unspecified);
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_too_long() {
        // Create a buffer that's too long
        let mut input = [b'A'; MAXIMUM_LENGTH + 1];
        input[0] = b'P';
        input[1] = b'R';
        input[2] = b'O';
        input[3] = b'X';
        input[4] = b'Y';

        let result = Header::decode(&input);

        assert!(matches!(result, Err(DecodeError::MalformedData("bytes too long"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_not_utf8() {
        let input = b"PROXY TCP4 \xff\xff\xff\xff 10.0.0.1 8080 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MalformedData("not UTF-8"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_missing_crlf() {
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1 8080 80";
        let result = Header::decode(input);

        assert!(matches!(
            result,
            Err(DecodeError::MalformedData("missing CRLF or trailing data"))
        ));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_trailing_data() {
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1 8080 80\r\ntrailing data";
        let result = Header::decode(input);

        assert!(matches!(
            result,
            Err(DecodeError::MalformedData("missing CRLF or trailing data"))
        ));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_no_magic() {
        let input = b"NOTPROXY TCP4 192.168.1.1 10.0.0.1 8080 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Ok(Decoded::None)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_empty_input() {
        let input = b"";
        let result = Header::decode(input);

        // Empty input should result in missing CRLF or trailing data error because
        // str::from_utf8 succeeds, but split_once("\r\n") fails on empty string
        assert!(matches!(
            result,
            Err(DecodeError::MalformedData("missing CRLF or trailing data"))
        ));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_only_magic() {
        let input = b"PROXY\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::InvalidFamProto)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_invalid_protocol() {
        let input = b"PROXY INVALID 192.168.1.1 10.0.0.1 8080 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::InvalidFamProto)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_missing_src_ip() {
        let input = b"PROXY TCP4\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MissingData("SRC_IP"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_missing_dst_ip() {
        let input = b"PROXY TCP4 192.168.1.1\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MissingData("DST_IP"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_missing_src_port() {
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MissingData("SRC_PORT"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_missing_dst_port() {
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1 8080\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MissingData("DST_PORT"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_invalid_src_ip() {
        let input = b"PROXY TCP4 999.999.999.999 10.0.0.1 8080 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MalformedData("SRC_IP"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_invalid_dst_ip() {
        let input = b"PROXY TCP4 192.168.1.1 invalid_ip 8080 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MalformedData("DST_IP"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_invalid_src_port() {
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1 65536 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MalformedData("SRC_PORT"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp4_invalid_dst_port() {
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1 8080 invalid_port\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MalformedData("DST_PORT"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp6_missing_fields() {
        let input = b"PROXY TCP6 2001:db8::1\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MissingData("DST_IP"))));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_tcp6_invalid_ip() {
        let input = b"PROXY TCP6 invalid::ip fe80::1 8080 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::MalformedData("SRC_IP"))));
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn test_roundtrip_tcp4() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 50);
        let src_port = 12345;
        let dst_port = 443;

        let address_pair = AddressPair::Inet {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let original = Header::new(address_pair);

        let encoded = original.encode();
        let Decoded::Some(decoded) = Header::decode(encoded.as_bytes()).unwrap() else {
            unreachable!()
        };

        assert_eq!(original, decoded);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn test_roundtrip_tcp6() {
        let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);
        let dst_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50);
        let src_port = 12345;
        let dst_port = 443;

        let address_pair = AddressPair::Inet6 {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let original = Header::new(address_pair);

        let encoded = original.encode();
        let Decoded::Some(decoded) = Header::decode(encoded.as_bytes()).unwrap() else {
            unreachable!()
        };

        assert_eq!(original, decoded);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn test_roundtrip_unknown() {
        let original = Header::new(AddressPair::Unspecified);

        let encoded = original.encode();
        let Decoded::Some(decoded) = Header::decode(encoded.as_bytes()).unwrap() else {
            unreachable!()
        };

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_maximum_length_constant() {
        // Test that the MAXIMUM_LENGTH constant is reasonable
        // The longest possible v1 header would be something like:
        // "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        // ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"
        let longest_possible = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff \
                                ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        assert!(longest_possible.len() == MAXIMUM_LENGTH);
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_edge_case_whitespace() {
        // Test with multiple spaces (should work with split_whitespace())
        let input = b"PROXY  TCP4   192.168.1.1    10.0.0.1   8080   80\r\n";
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::TCP4);
        match header.address_pair {
            AddressPair::Inet {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => {
                assert_eq!(src_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(src_port, 8080);
                assert_eq!(dst_ip, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(dst_port, 80);
            }
            _ => panic!("Expected Inet address pair"),
        }
    }

    // Additional test cases for better coverage
    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_exact_maximum_length() {
        // Test a header that's exactly at the maximum length limit
        let input = b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        assert!(input.len() <= MAXIMUM_LENGTH);
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::TCP6);
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_minimal_tcp4() {
        let input = b"PROXY TCP4 0.0.0.0 0.0.0.0 0 0\r\n";
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::TCP4);
        match header.address_pair {
            AddressPair::Inet {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => {
                assert_eq!(src_ip, Ipv4Addr::new(0, 0, 0, 0));
                assert_eq!(src_port, 0);
                assert_eq!(dst_ip, Ipv4Addr::new(0, 0, 0, 0));
                assert_eq!(dst_port, 0);
            }
            _ => panic!("Expected Inet address pair"),
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_minimal_tcp6() {
        let input = b"PROXY TCP6 :: :: 0 0\r\n";
        let Decoded::Some(header) = Header::decode(input).unwrap() else {
            unreachable!()
        };

        assert_eq!(header.protocol, FamProto::TCP6);
        match header.address_pair {
            AddressPair::Inet6 {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            } => {
                assert_eq!(src_ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
                assert_eq!(src_port, 0);
                assert_eq!(dst_ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
                assert_eq!(dst_port, 0);
            }
            _ => panic!("Expected Inet6 address pair"),
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_mixed_case_protocol() {
        // Protocol should be case sensitive
        let input = b"PROXY tcp4 192.168.1.1 10.0.0.1 8080 80\r\n";
        let result = Header::decode(input);

        assert!(matches!(result, Err(DecodeError::InvalidFamProto)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn test_decode_different_line_ending() {
        // Should only accept \r\n, not just \n
        let input = b"PROXY TCP4 192.168.1.1 10.0.0.1 8080 80\n";
        let result = Header::decode(input);

        assert!(matches!(
            result,
            Err(DecodeError::MalformedData("missing CRLF or trailing data"))
        ));
    }
}
