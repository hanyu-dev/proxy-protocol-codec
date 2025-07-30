# proxy-protocol-codec

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![Crates.io Version](https://img.shields.io/crates/v/proxy-protocol-codec.svg)](https://crates.io/crates/proxy-protocol-codec)
[![Docs.rs Version](https://docs.rs/proxy-protocol-codec/badge.svg)](https://docs.rs/proxy-protocol-codec)

PROXY Protocol codec implementation in Rust. See [HAProxy](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for the protocol specification.

## Usage

Add the following to your `Cargo.toml` as a dependency:

```toml
proxy-protocol-codec = "0.1"
```

### Encoding

```rust
// PROXY Protocol v1 (text format), TCP4
let address_pair = proxy_protocol_codec::v1::AddressPair::Inet {
    src_ip: "127.0.0.1".parse().unwrap(),
    dst_ip: "127.0.0.2".parse().unwrap(),
    src_port: 8080,
    dst_port: 80,
};
let header = proxy_protocol_codec::v1::Header::new(address_pair);

assert_eq!(header.encode(), "PROXY TCP4 127.0.0.1 127.0.0.2 8080 80\r\n");

// PROXY Protocol v1 (text format), TCP6
let address_pair = proxy_protocol_codec::v1::AddressPair::Inet6 {
    src_ip: "::1".parse().unwrap(),
    dst_ip: "::2".parse().unwrap(),
    src_port: 8080,
    dst_port: 80,
};
let header = proxy_protocol_codec::v1::Header::new(address_pair);

assert_eq!(header.encode(), "PROXY TCP6 ::1 ::2 8080 80\r\n");

// PROXY Protocol v1 (text format), UNKNOWN
let address_pair = proxy_protocol_codec::v1::AddressPair::Unspecified;
let header = proxy_protocol_codec::v1::Header::new(address_pair);

assert_eq!(header.encode(), "PROXY UNKNOWN\r\n");
```

```rust
// PROXY Protocol v1 (binary format)
let header = proxy_protocol_codec::v2::Header::new_proxy(
    proxy_protocol_codec::v2::Protocol::Stream,
    proxy_protocol_codec::v2::AddressPair::Inet {
        src_ip: "127.0.0.1".parse().unwrap(),
        dst_ip: "127.0.0.2".parse().unwrap(),
        src_port: 8080,
        dst_port: 80,
    },
);

let encoded = header
    .encode()
    .write_ext_authority(b"example.com")? // Optional, write extensions.
    .finish()?;
```

### Decoding

```rust
// PROXY Protocol v1 (text format)
let encoded = ...;

proxy_protocol_codec::v1::Header::decode(encoded))?
```

```rust
// PROXY Protocol v2 (binary format)
let tcp_stream = ...;

let mut buf = Vec::with_capacity(proxy_protocol_codec::v2::HEADER_SIZE);

unsafe {
    // Safe op filling with 0 is OK
    buf.set_len(proxy_protocol_codec::v2::HEADER_SIZE);
}

let peeked = tcp_stream.peek(&mut buf[..])?;

if peeked != 16 {
    // Not enough data to decode the header, the sender should not fragment the header.
    return Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "Not enough data to decode PROXY Protocol v2 header",
    ));
}

match proxy_protocol_codec::v2::Header::decode(&buf[..])? {
    proxy_protocol_codec::v2::Decoded::Partial(remaining) => {
        let total_length = proxy_protocol_codec::v2::HEADER_SIZE + remaining.get();

        unsafe {
            // Safe op filling with 0 is OK
            buf.set_len(total_length);
        }

        // Partial header, need more data.
        tcp_stream.read_exact(
            &mut buf[proxy_protocol_codec::v2::HEADER_SIZE..proxy_protocol_codec::v2::HEADER_SIZE + remaining.get()]
        )?;

        // Decode the full header with the remaining bytes.
        let proxy_protocol_codec::v2::Decoded::Some(header) = proxy_protocol_codec::v2::Header::decode(&buf[..])? else {
            panic!("must be Some here");
        };

        header
    }
    proxy_protocol_codec::v2::Decoded::Some(header) => {
        // Successfully decoded the header (without address pair or extensions).

        header
    }
    proxy_protocol_codec::v2::Decoded::None => {
        // Partial header, need more data.
        
        return ...;
    }
}
```
