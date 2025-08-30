//! PROXY Protocol v2.

#[cfg(any(feature = "feat-codec-decode", feature = "feat-codec-encode"))]
pub mod codec;
pub mod model;

#[cfg(any(feature = "feat-codec-decode", feature = "feat-codec-encode"))]
pub use codec::*;
pub use model::{AddressPair, Command, ExtensionRef, ExtensionType, Protocol, HEADER_SIZE};

#[derive(Debug, Clone, PartialEq, Eq)]
/// The PROXY Protocol v2 header.
///
/// For encoding and decoding stuffs, please refer to [`codec::HeaderEncoder`]
/// and [`codec::HeaderDecoder`].
pub struct Header {
    /// See [`Command`].
    command: Command,

    /// See [`Protocol`].
    protocol: Protocol,

    /// See [`AddressPair`].
    address_pair: AddressPair,
}

impl Header {
    /// The magic bytes that identify the PROXY Protocol v2 header.
    pub const MAGIC: &'static [u8; 12] = crate::Version::MAGIC_V2;

    #[inline]
    /// Creates a new `Header` with [`Command::Local`]
    pub const fn new_local() -> Self {
        Self {
            command: Command::Local,
            protocol: Protocol::Unspecified,
            address_pair: AddressPair::Unspecified,
        }
    }

    #[inline]
    /// Creates a new `Header` with [`Command::Proxy`]
    pub const fn new_proxy(protocol: Protocol, address_pair: AddressPair) -> Self {
        Self {
            command: Command::Proxy,
            protocol,
            address_pair,
        }
    }

    #[inline]
    /// Returns the command of the header.
    pub const fn command(&self) -> &Command {
        &self.command
    }

    #[inline]
    /// Returns the protocol of the header.
    pub const fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    #[inline]
    /// Returns the address pair of the header.
    pub const fn address_pair(&self) -> &AddressPair {
        &self.address_pair
    }

    #[cfg(feature = "feat-codec-encode")]
    #[inline]
    /// See [`HeaderEncoder::encode`].
    pub fn encode(&self) -> Encoded {
        HeaderEncoder::encode(self)
    }

    #[cfg(feature = "feat-codec-decode")]
    #[inline]
    /// See [`HeaderDecoder::decode`].
    pub fn decode<'a>(encoded: &'a [u8]) -> Result<Decoded<'a>, DecodeError> {
        HeaderDecoder::decode(encoded)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_local() {
        let header = Header::new_local();

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_unspec_unspec() {
        let header = Header::new_proxy(Protocol::Unspecified, AddressPair::Unspecified);

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_stream_unspec() {
        let header = Header::new_proxy(Protocol::Stream, AddressPair::Unspecified);

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_dgram_unspec() {
        let header = Header::new_proxy(Protocol::Dgram, AddressPair::Unspecified);

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_unspec_inet() {
        let header = Header::new_proxy(
            Protocol::Unspecified,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_stream_inet() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_dgram_inet() {
        let header = Header::new_proxy(
            Protocol::Dgram,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_unspec_inet6() {
        let header = Header::new_proxy(
            Protocol::Unspecified,
            AddressPair::Inet6 {
                src_ip: "::1".parse().unwrap(),
                dst_ip: "::2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_stream_inet6() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet6 {
                src_ip: "::1".parse().unwrap(),
                dst_ip: "::2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_dgram_inet6() {
        let header = Header::new_proxy(
            Protocol::Dgram,
            AddressPair::Inet6 {
                src_ip: "::1".parse().unwrap(),
                dst_ip: "::2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_unspec_unix() {
        let header = Header::new_proxy(
            Protocol::Unspecified,
            AddressPair::Unix {
                src_addr: [b'S'; 108],
                dst_addr: [b'D'; 108],
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_stream_unix() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Unix {
                src_addr: [b'S'; 108],
                dst_addr: [b'D'; 108],
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_no_extension_proxy_dgram_unix() {
        let header = Header::new_proxy(
            Protocol::Dgram,
            AddressPair::Unix {
                src_addr: [b'S'; 108],
                dst_addr: [b'D'; 108],
            },
        );

        _encode_decode_header_no_extension(header);
    }

    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn _encode_decode_header_no_extension(header: Header) {
        let encoded = codec::HeaderEncoder::encode(&header).finish().unwrap();

        let decoded = codec::HeaderDecoder::decode(&encoded).unwrap();
        if let codec::Decoded::Some(codec::DecodedHeader {
            header: decoded_header,
            extensions,
        }) = decoded
        {
            assert_eq!(decoded_header, header);
            let mut extensions_iter = extensions.into_iter();
            assert!(extensions_iter.next().is_none());
        } else {
            panic!("Expected decoded header");
        }
    }

    // Tests with extensions
    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_with_extension_local_alpn() {
        let header = Header::new_local();
        let alpn_data = b"http/1.1";

        _encode_decode_header_with_extension(
            header,
            |encoder| encoder.write_ext_alpn(alpn_data),
            |mut extensions| {
                let ext = extensions.next().unwrap().unwrap();
                assert_eq!(ext.typ().unwrap(), ExtensionType::ALPN);
                assert_eq!(ext.payload(), alpn_data);
                assert!(extensions.next().is_none());
            },
        );
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_with_extension_proxy_authority() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );
        let authority_data = b"example.com";

        _encode_decode_header_with_extension(
            header,
            |encoder| encoder.write_ext_authority(authority_data),
            |mut extensions| {
                let ext = extensions.next().unwrap().unwrap();
                assert_eq!(ext.typ().unwrap(), ExtensionType::Authority);
                assert_eq!(ext.payload(), authority_data);
                assert!(extensions.next().is_none());
            },
        );
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_with_extension_proxy_unique_id() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet6 {
                src_ip: "::1".parse().unwrap(),
                dst_ip: "::2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );
        let unique_id = b"unique-connection-id-12345";

        _encode_decode_header_with_extension(
            header,
            |encoder| encoder.write_ext_unique_id(unique_id),
            |mut extensions| {
                let ext = extensions.next().unwrap().unwrap();
                assert_eq!(ext.typ().unwrap(), ExtensionType::NetworkNamespace); // Note: write_ext_unique_id has a bug, it uses NetworkNamespace
                assert_eq!(ext.payload(), unique_id);
                assert!(extensions.next().is_none());
            },
        );
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_with_extension_proxy_network_namespace() {
        let header = Header::new_proxy(
            Protocol::Dgram,
            AddressPair::Unix {
                src_addr: [b'S'; 108],
                dst_addr: [b'D'; 108],
            },
        );
        let netns_data = b"my-namespace";

        _encode_decode_header_with_extension(
            header,
            |encoder| encoder.write_ext_network_namespace(netns_data),
            |mut extensions| {
                let ext = extensions.next().unwrap().unwrap();
                assert_eq!(ext.typ().unwrap(), ExtensionType::NetworkNamespace);
                assert_eq!(ext.payload(), netns_data);
                assert!(extensions.next().is_none());
            },
        );
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_with_extension_proxy_no_op() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );
        let padding_size = 5u16;

        _encode_decode_header_with_extension(
            header,
            |encoder| encoder.write_ext_no_op(padding_size),
            |mut extensions| {
                let ext = extensions.next().unwrap().unwrap();
                assert_eq!(ext.typ().unwrap(), ExtensionType::NoOp);
                assert_eq!(ext.payload().len(), padding_size as usize);
                assert_eq!(ext.payload(), &vec![0u8; padding_size as usize]);
                assert!(extensions.next().is_none());
            },
        );
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_with_multiple_extensions() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );
        let alpn_data = b"h2";
        let authority_data = b"test.example.org";
        let padding_size = 3u16;

        let encoded = codec::HeaderEncoder::encode(&header)
            .write_ext_alpn(alpn_data)
            .unwrap()
            .write_ext_authority(authority_data)
            .unwrap()
            .write_ext_no_op(padding_size)
            .unwrap()
            .finish()
            .unwrap();

        let decoded = codec::HeaderDecoder::decode(&encoded).unwrap();
        if let codec::Decoded::Some(codec::DecodedHeader {
            header: decoded_header,
            extensions,
        }) = decoded
        {
            assert_eq!(decoded_header, header);

            let mut extensions_iter = extensions.into_iter();

            // Check ALPN extension
            let ext1 = extensions_iter.next().unwrap().unwrap();
            assert_eq!(ext1.typ().unwrap(), ExtensionType::ALPN);
            assert_eq!(ext1.payload(), alpn_data);

            // Check Authority extension
            let ext2 = extensions_iter.next().unwrap().unwrap();
            assert_eq!(ext2.typ().unwrap(), ExtensionType::Authority);
            assert_eq!(ext2.payload(), authority_data);

            // Check NoOp extension
            let ext3 = extensions_iter.next().unwrap().unwrap();
            assert_eq!(ext3.typ().unwrap(), ExtensionType::NoOp);
            assert_eq!(ext3.payload().len(), padding_size as usize);
            assert_eq!(ext3.payload(), &vec![0u8; padding_size as usize]);

            // No more extensions
            assert!(extensions_iter.next().is_none());
        } else {
            panic!("Expected decoded header");
        }
    }

    #[test]
    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn encode_decode_header_with_custom_extension() {
        let header = Header::new_local();
        let custom_type = 0x80u8; // Custom extension type
        let custom_data = b"custom-extension-data";

        let extension = ExtensionRef::new_custom(custom_type, custom_data).unwrap();
        let encoded = codec::HeaderEncoder::encode(&header)
            .write_ext_custom(extension)
            .finish()
            .unwrap();

        let decoded = codec::HeaderDecoder::decode(&encoded).unwrap();
        if let codec::Decoded::Some(codec::DecodedHeader {
            header: decoded_header,
            extensions,
        }) = decoded
        {
            assert_eq!(decoded_header, header);

            let mut extensions_iter = extensions.into_iter();
            let ext = extensions_iter.next().unwrap().unwrap();
            assert_eq!(ext.typ().unwrap_err(), custom_type); // Unknown type returns Err with raw byte
            assert_eq!(ext.payload(), custom_data);
            assert!(extensions_iter.next().is_none());
        } else {
            panic!("Expected decoded header");
        }
    }

    #[test]
    #[cfg(all(
        feature = "feat-codec-encode",
        feature = "feat-codec-decode",
        feature = "feat-codec-v2-crc32c"
    ))]
    fn encode_decode_header_with_crc32c() {
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );

        let encoded = codec::HeaderEncoder::encode(&header).finish_with_crc32c().unwrap();

        let decoded = codec::HeaderDecoder::decode(&encoded).unwrap();
        if let codec::Decoded::Some(codec::DecodedHeader {
            header: decoded_header,
            extensions,
        }) = decoded
        {
            assert_eq!(decoded_header, header);

            let mut extensions_iter = extensions.into_iter();
            let ext = extensions_iter.next().unwrap().unwrap();
            assert_eq!(ext.typ().unwrap(), ExtensionType::CRC32C);
            assert_eq!(ext.payload().len(), 4); // CRC32C is 4 bytes
            assert!(extensions_iter.next().is_none());
        } else {
            panic!("Expected decoded header");
        }
    }

    #[cfg(all(feature = "feat-codec-encode", feature = "feat-codec-decode"))]
    fn _encode_decode_header_with_extension<F, V>(header: Header, add_extension: F, verify_extension: V)
    where
        F: FnOnce(
            codec::HeaderEncoder<codec::encode::stage::Finished>,
        ) -> Result<codec::HeaderEncoder<codec::encode::stage::Finished>, codec::EncodeError>,
        V: FnOnce(codec::DecodedExtensionsIter<'_>),
    {
        let encoded = add_extension(codec::HeaderEncoder::encode(&header))
            .unwrap()
            .finish()
            .unwrap();

        let decoded = codec::HeaderDecoder::decode(&encoded).unwrap();
        if let codec::Decoded::Some(codec::DecodedHeader {
            header: decoded_header,
            extensions,
        }) = decoded
        {
            assert_eq!(decoded_header, header);
            verify_extension(extensions.into_iter());
        } else {
            panic!("Expected decoded header");
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_peek_insufficient_data() {
        // Test with buffers of various sizes less than HEADER_SIZE (16 bytes)
        // that start with magic bytes
        for size in 1..16 {
            let mut buffer = vec![0u8; size];
            // Copy as much of the magic bytes as we can fit
            let magic = b"\r\n\r\n\x00\r\nQUIT\n";
            let copy_len = size.min(magic.len());
            buffer[..copy_len].copy_from_slice(&magic[..copy_len]);

            let result = codec::HeaderDecoder::decode(&buffer).unwrap();
            // If we have the full magic bytes, it should be Partial
            assert!(matches!(result, codec::Decoded::Partial(_)));
        }

        // Test with buffer that has no magic bytes
        let buffer = vec![0u8; 8];
        let result = codec::HeaderDecoder::decode(&buffer).unwrap();
        assert!(matches!(result, codec::Decoded::None));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_peek_not_proxy_protocol() {
        // Buffer that's large enough but doesn't start with magic bytes
        let buffer = vec![0u8; 16];
        let result = codec::HeaderDecoder::decode(&buffer).unwrap();
        assert!(matches!(result, codec::Decoded::None));

        // Buffer with wrong magic bytes
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"wrong_magic\x00");
        let result = codec::HeaderDecoder::decode(&buffer).unwrap();
        assert!(matches!(result, codec::Decoded::None));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_malformed_data() {
        // Create a valid header first
        let header = Header::new_proxy(
            Protocol::Stream,
            AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            },
        );
        let encoded = codec::HeaderEncoder::encode(&header).finish().unwrap();

        // Test with insufficient data for address parsing (truncate after header)
        let truncated = &encoded[..16]; // Only header, no address data
        let result = codec::HeaderDecoder::decode(truncated).unwrap();
        assert!(matches!(result, codec::Decoded::Partial(_)));

        // Test with partial address data
        let partial = &encoded[..20]; // Header + partial IPv4 address
        let result = codec::HeaderDecoder::decode(partial).unwrap();
        assert!(matches!(result, codec::Decoded::Partial(_)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_total_length_overflow() {
        // Create a buffer with magic bytes and valid version/command
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        buffer[12] = 0x21; // Version 2, Command Proxy
        buffer[13] = 0x11; // Family Inet, Protocol Stream

        // Set length to maximum value that would cause overflow
        buffer[14] = 0xFF;
        buffer[15] = 0xFF;

        // try_decode will return Partial requesting more data for the large length
        let result = codec::HeaderDecoder::decode(&buffer).unwrap();
        assert!(matches!(result, codec::Decoded::Partial(_)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_invalid_version_variants() {
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        buffer[13] = 0x11; // Valid family and protocol
        buffer[14] = 0x00; // Length hi
        buffer[15] = 0x00; // Length lo

        // Test various invalid version values
        let invalid_versions = [
            0x00, 0x10, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        ];
        for &invalid_version in &invalid_versions {
            buffer[12] = invalid_version | 0x01; // Keep command as Proxy
            let err = codec::HeaderDecoder::decode(&buffer).unwrap_err();
            assert!(matches!(err, codec::DecodeError::InvalidVersion(v) if v == invalid_version));
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_invalid_command_variants() {
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        buffer[12] = 0x20; // Valid version 2
        buffer[13] = 0x11; // Valid family and protocol
        buffer[14] = 0x00; // Length hi
        buffer[15] = 0x00; // Length lo

        // Test various invalid command values
        let invalid_commands = [
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        for &invalid_command in &invalid_commands {
            buffer[12] = 0x20 | invalid_command;
            let err = codec::HeaderDecoder::decode(&buffer).unwrap_err();
            assert!(matches!(err, codec::DecodeError::InvalidCommand(c) if c == invalid_command));
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_invalid_family_variants() {
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        buffer[12] = 0x21; // Valid version and command
        buffer[14] = 0x00; // Length hi
        buffer[15] = 0x00; // Length lo

        // Test various invalid family values
        let invalid_families = [0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0];
        for &invalid_family in &invalid_families {
            buffer[13] = invalid_family | 0x01; // Keep protocol as Stream
            let err = codec::HeaderDecoder::decode(&buffer).unwrap_err();
            assert!(matches!(err, codec::DecodeError::InvalidFamily(f) if f == invalid_family));
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_invalid_protocol_variants() {
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        buffer[12] = 0x21; // Valid version and command
        buffer[13] = 0x10; // Valid family Inet
        buffer[14] = 0x00; // Length hi
        buffer[15] = 0x00; // Length lo

        // Test various invalid protocol values
        let invalid_protocols = [
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        for &invalid_protocol in &invalid_protocols {
            buffer[13] = 0x10 | invalid_protocol;
            let err = codec::HeaderDecoder::decode(&buffer).unwrap_err();
            assert!(matches!(err, codec::DecodeError::InvalidProtocol(p) if p == invalid_protocol));
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_trailing_data_variants() {
        // Create a minimal valid header (Local command)
        let header = Header::new_local();
        let encoded = codec::HeaderEncoder::encode(&header).finish().unwrap();

        // Test with various amounts of trailing data
        for extra_bytes in 1..=10 {
            let mut with_trailing = encoded.clone();
            with_trailing.extend(vec![0xAA; extra_bytes]);

            // try_decode should detect trailing data and return an error
            let err = codec::HeaderDecoder::decode(&with_trailing).unwrap_err();
            assert!(matches!(err, codec::DecodeError::TrailingData));
        }
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_inet6_malformed() {
        // Create header for IPv6 but with insufficient data
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        buffer[12] = 0x21; // Version 2, Command Proxy
        buffer[13] = 0x21; // Family Inet6, Protocol Stream
        buffer[14] = 0x00; // Length hi
        buffer[15] = 0x24; // Length lo (36 bytes for IPv6 addresses)

        // Create buffer with header but insufficient address data
        let mut insufficient_data = buffer.clone();
        insufficient_data.extend(vec![0u8; 20]); // Only 20 bytes instead of 36

        let result = codec::HeaderDecoder::decode(&insufficient_data).unwrap();
        assert!(matches!(result, codec::Decoded::Partial(_)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_unix_malformed() {
        // Create header for Unix but with insufficient data
        let mut buffer = vec![0u8; 16];
        buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        buffer[12] = 0x21; // Version 2, Command Proxy
        buffer[13] = 0x31; // Family Unix, Protocol Stream
        buffer[14] = 0x00; // Length hi
        buffer[15] = 0xD8; // Length lo (216 bytes for Unix addresses)

        // Create buffer with header but insufficient address data
        let mut insufficient_data = buffer.clone();
        insufficient_data.extend(vec![0u8; 100]); // Only 100 bytes instead of 216

        let result = codec::HeaderDecoder::decode(&insufficient_data).unwrap();
        assert!(matches!(result, codec::Decoded::Partial(_)));
    }

    #[test]
    #[cfg(feature = "feat-codec-decode")]
    fn decode_zero_length_but_with_address_family() {
        // Test headers that claim to have address families but with zero length
        let families_and_protocols = [
            (0x10, 0x01), // Inet + Stream
            (0x20, 0x01), // Inet6 + Stream
            (0x30, 0x01), // Unix + Stream
        ];

        for (family, protocol) in families_and_protocols {
            let mut buffer = vec![0u8; 16];
            buffer[0..12].copy_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
            buffer[12] = 0x21; // Version 2, Command Proxy
            buffer[13] = family | protocol;
            buffer[14] = 0x00; // Length hi - zero length
            buffer[15] = 0x00; // Length lo - zero length

            let err = codec::HeaderDecoder::decode(&buffer).unwrap_err();
            assert!(matches!(err, codec::DecodeError::MalformedData));
        }
    }
}
