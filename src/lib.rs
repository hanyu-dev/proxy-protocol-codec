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
