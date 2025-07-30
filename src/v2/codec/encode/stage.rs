//! Codec stage markers for encoding and decoding

#[allow(missing_debug_implementations)]
/// Marker: encoding / decoding MAGIC bytes (bytes 0 - 11).
pub struct Magic;

#[allow(missing_debug_implementations)]
/// Marker: encoding / decoding the version & command byte (byte 12).
pub struct VerCmd;

#[allow(missing_debug_implementations)]
/// Marker: encoding / decoding the address family & protocol (byte 13).
pub struct FamProto;

#[allow(missing_debug_implementations)]
/// Marker: encoding / decoding the address length (byte 14).
pub struct Len;

#[allow(missing_debug_implementations)]
/// Marker: encoding / decoding the src and dst address.
pub struct Addr;

#[allow(missing_debug_implementations)]
/// Marker: encoding / decoding the TLV (Type-Length-Value) data, or finished.
pub struct Finished;
