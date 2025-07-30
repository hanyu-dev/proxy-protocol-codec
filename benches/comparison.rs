//! Benchmark comparing proxy-protocol-codec with ppp library for binary v2
//! protocol parsing.

#![allow(missing_docs)]

use core::hint::black_box;
use std::panic;

use criterion::{criterion_group, criterion_main, Criterion};
// #[cfg(unix)]
// use pprof::criterion::{Output, PProfProfiler};

fn benchmarks_v1(c: &mut Criterion) {
    // Decode
    {
        let mut group = c.benchmark_group("Decode/v1");

        // Inet
        {
            let encoded = proxy_protocol_codec::v1::Header::new(proxy_protocol_codec::v1::AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            })
            .encode();

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("ppp/inet", |b| {
                    b.iter(|| ppp::v1::Header::try_from(black_box(encoded.as_bytes())).unwrap());
                });
            }

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("proxy_protocol_codec/inet", |b| {
                    b.iter(|| proxy_protocol_codec::v1::Header::decode(black_box(encoded.as_bytes())).unwrap());
                });
            }
        }

        // Inet6
        {
            let encoded = proxy_protocol_codec::v1::Header::new(proxy_protocol_codec::v1::AddressPair::Inet6 {
                src_ip: "::1".parse().unwrap(),
                dst_ip: "::2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            })
            .encode();

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("ppp/inet6", |b| {
                    b.iter(|| ppp::v1::Header::try_from(black_box(encoded.as_bytes())).unwrap());
                });
            }

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("proxy_protocol_codec/inet6", |b| {
                    b.iter(|| proxy_protocol_codec::v1::Header::decode(black_box(encoded.as_bytes())).unwrap());
                });
            }
        }

        group.finish();
    }

    // Encode
    {
        let mut group = c.benchmark_group("Encode/v1");

        // Inet
        {
            let header = proxy_protocol_codec::v1::Header::new(proxy_protocol_codec::v1::AddressPair::Inet {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            });

            // ppp doesn't have a way to *encode* v1 header...

            {
                group.bench_function("proxy_protocol_codec/inet", |b| {
                    b.iter(|| black_box(&header).encode());
                });
            }
        }

        // Inet6
        {
            let header = proxy_protocol_codec::v1::Header::new(proxy_protocol_codec::v1::AddressPair::Inet6 {
                src_ip: "::1".parse().unwrap(),
                dst_ip: "::2".parse().unwrap(),
                src_port: 8080,
                dst_port: 80,
            });

            // ppp doesn't have a way to *encode* v1 header...

            {
                group.bench_function("proxy_protocol_codec/inet6", |b| {
                    b.iter(|| black_box(&header).encode());
                });
            }
        }

        group.finish();
    }
}

fn benchmarks_v2(c: &mut Criterion) {
    // Decode
    {
        let mut group = c.benchmark_group("Decode/v2");

        // Inet
        {
            let header = proxy_protocol_codec::v2::Header::new_proxy(
                proxy_protocol_codec::v2::Protocol::Stream,
                proxy_protocol_codec::v2::AddressPair::Inet {
                    src_ip: "127.0.0.1".parse().unwrap(),
                    dst_ip: "127.0.0.2".parse().unwrap(),
                    src_port: 8080,
                    dst_port: 80,
                },
            );

            let encoded = proxy_protocol_codec::v2::HeaderEncoder::encode(&header)
                .finish()
                .unwrap();

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("ppp/inet", |b| {
                    b.iter(|| {
                        let partial = ppp::v2::Header::try_from(&encoded[..16]);
                        if let Err(ppp::v2::ParseError::Partial(_, target)) = partial {
                            ppp::v2::Header::try_from(&encoded[..16 + target])
                        } else {
                            partial
                        }
                        .unwrap()
                    });
                });
            }

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("proxy_protocol_codec/inet", |b| {
                    b.iter(|| {
                        let proxy_protocol_codec::v2::Decoded::Partial(remaining) =
                            proxy_protocol_codec::v2::HeaderDecoder::decode(&encoded[..16]).unwrap()
                        else {
                            panic!("must be Partial here");
                        };

                        proxy_protocol_codec::v2::HeaderDecoder::decode(&encoded[..16 + remaining.get()]).unwrap()
                    });
                });
            }
        }

        // Inet6
        {
            let header = proxy_protocol_codec::v2::Header::new_proxy(
                proxy_protocol_codec::v2::Protocol::Stream,
                proxy_protocol_codec::v2::AddressPair::Inet6 {
                    src_ip: "::1".parse().unwrap(),
                    dst_ip: "::2".parse().unwrap(),
                    src_port: 8080,
                    dst_port: 80,
                },
            );

            let encoded = proxy_protocol_codec::v2::HeaderEncoder::encode(&header)
                .finish()
                .unwrap();

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("ppp/inet6", |b| {
                    b.iter(|| {
                        let partial = ppp::v2::Header::try_from(&encoded[..16]);
                        if let Err(ppp::v2::ParseError::Partial(_, target)) = partial {
                            ppp::v2::Header::try_from(&encoded[..16 + target])
                        } else {
                            partial
                        }
                        .unwrap()
                    });
                });
            }

            {
                let encoded = black_box(encoded.clone());

                group.bench_function("proxy_protocol_codec/inet6", |b| {
                    b.iter(|| {
                        let proxy_protocol_codec::v2::Decoded::Partial(remaining) =
                            proxy_protocol_codec::v2::HeaderDecoder::decode(&encoded[..16]).unwrap()
                        else {
                            panic!("must be Partial here");
                        };

                        proxy_protocol_codec::v2::HeaderDecoder::decode(&encoded[..16 + remaining.get()]).unwrap()
                    });
                });
            }
        }

        group.finish();
    }

    // Encode
    {
        let mut group = c.benchmark_group("Encode/v2");

        // Inet
        {
            let client_address = "127.0.0.1:80";
            let server_address = "127.0.0.2:8080";

            {
                let client_address = black_box(client_address.parse().unwrap());
                let server_address = black_box(server_address.parse().unwrap());

                group.bench_function("ppp/inet", |b| {
                    b.iter(|| {
                        ppp::v2::Builder::with_addresses(
                            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
                            ppp::v2::Protocol::Stream,
                            (client_address, server_address),
                        )
                        .build()
                        .unwrap()
                    });
                });
            }
            {
                let header = black_box(proxy_protocol_codec::v2::Header::new_proxy(
                    proxy_protocol_codec::v2::Protocol::Stream,
                    proxy_protocol_codec::v2::AddressPair::Inet {
                        src_ip: "127.0.0.1".parse().unwrap(),
                        dst_ip: "127.0.0.2".parse().unwrap(),
                        src_port: 8080,
                        dst_port: 80,
                    },
                ));

                group.bench_function("proxy_protocol_codec/inet", |b| {
                    b.iter(|| {
                        proxy_protocol_codec::v2::HeaderEncoder::encode(&header)
                            .finish()
                            .unwrap()
                    });
                });
            }
        }

        // Inet6
        {
            let client_address = "[::1]:80";
            let server_address = "[::2]:8080";

            {
                let client_address = black_box(client_address.parse().unwrap());
                let server_address = black_box(server_address.parse().unwrap());

                group.bench_function("ppp/inet6", |b| {
                    b.iter(|| {
                        ppp::v2::Builder::with_addresses(
                            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
                            ppp::v2::Protocol::Stream,
                            (client_address, server_address),
                        )
                        .build()
                        .unwrap()
                    });
                });
            }
            {
                let header = black_box(proxy_protocol_codec::v2::Header::new_proxy(
                    proxy_protocol_codec::v2::Protocol::Stream,
                    proxy_protocol_codec::v2::AddressPair::Inet6 {
                        src_ip: "::1".parse().unwrap(),
                        dst_ip: "::2".parse().unwrap(),
                        src_port: 8080,
                        dst_port: 80,
                    },
                ));

                group.bench_function("proxy_protocol_codec/inet6", |b| {
                    b.iter(|| {
                        proxy_protocol_codec::v2::HeaderEncoder::encode(&header)
                            .finish()
                            .unwrap()
                    });
                });
            }
        }

        group.finish();
    }
}

#[rustfmt::skip]
// #[cfg(unix)]
// criterion_group! {
//     name = benches;
//     config = {
//         Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
//     };
//     targets = benchmarks_v1, benchmarks_v2
// }

// #[cfg(not(unix))]
criterion_group!(benches, benchmarks_v1, benchmarks_v2);

criterion_main!(benches);
