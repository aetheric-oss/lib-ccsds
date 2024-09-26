//! Error types associated with this library.

use crate::arrow::ArrowError;
use crate::ccsds::CcsdsError;
use crate::time::TimeCodeError;

/// Error types for this library.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// Errors pertaining to CCSDS packet formation.
    Ccsds(CcsdsError),

    /// Errors pertaining to time codes.
    TimeCode(TimeCodeError),

    /// Errors pertaining to the Arrow Packet.
    Arrow(ArrowError),
}
