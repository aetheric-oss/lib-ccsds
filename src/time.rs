//! Time Codes for CCSDS

use crate::error::Error;
use duplicate::duplicate_item;
use packed_struct::prelude::{packed_bits::Bits, Integer, PackedStruct, PrimitiveEnum_u8};
use snafu::prelude::Snafu;

/// The max value of the 'day' field in Cds packet if 24 bits
pub const CDS_DAY_MAX_VALUE_24_BIT: u32 = 0xFFFFFF;

/// The max value of the 'day' field in Cds packet if 16 bits
pub const CDS_DAY_MAX_VALUE_16_BIT: u16 = 0xFFFF;

/// Possible Ccsds Packet Construction/Deconstruction Errors
#[derive(Snafu, Copy, Clone, Debug, PartialEq)]
pub enum TimeCodeError {
    /// Failed to create secondary header given a uuid
    #[snafu(display("tried to provide a day value exceeding 24 bits"))]
    CdsDayExceedsMax,

    /// Failed to convert the packed "day" field to an unsigned value
    #[snafu(display("could not convert bitpacked 'day' field to an unsigned value"))]
    CdsUnableToConvertDay,
}

/// Indicates the presence of an extra preamble byte.
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum PreambleExtension {
    /// Indicates an extra preamble byte.
    Absent = 0,

    /// Indicates an extra preamble byte.
    Present = 1,
}

/// Indicates the time code type.
///
/// Possible time codes are:
/// - Unsegmented (CUC)
/// - Day Segmented (CDS)
/// - Calendar Segmented (CCS)
///
/// Unsegmented (CUC) time codes do not specify a time code type
///  in the preamble, unlike CDS and CCS.
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum PreambleTimeCodeType {
    /// Day Segmented
    Cds = 0b100,

    /// Calendar Segmented
    Ccs = 0b101,

    /// Agency-Defined Time Code
    Agency = 0b110,
}

/// Indicates the epoch from which the count began
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum PreambleEpoch {
    /// Agency defined epoch
    AgencyDefined = 0b0,

    /// January 1, 1958 epoch
    Jan1958 = 0b1,
}

/// Indicates the bit length of the "day" segment
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum PreambleDaySegmentLength {
    /// 16-bit day segment
    Sixteen = 0b0,

    /// 24-bit day segment
    TwentyFour = 0b1,
}

/// Indicates the resolution of fine (subsecond) measurement.
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum PreambleResolution {
    /// 16-bit day segment
    Milliseconds = 0b0,

    /// 24-bit day segment
    Microseconds = 0b1,
}

/// Also known as a P-Field, contains metadata indicating
///  how time is defined in the T-Field.
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct CdsPreamble {
    /// Indicates the presence of an extra preamble byte.
    #[packed_field(bits = "0..=0", ty = "enum")]
    extension: PreambleExtension,

    /// Indicates the time code format.
    #[packed_field(bits = "1..=3", ty = "enum")]
    time_code_type: PreambleTimeCodeType,

    /// Indicates the epoch from which the count began.
    #[packed_field(bits = "4..=4", ty = "enum")]
    epoch: PreambleEpoch,

    /// The number of bits representing the days since epoch.
    #[packed_field(bits = "5..=5", ty = "enum")]
    day_bitlen: PreambleDaySegmentLength,

    /// The resolution of the fine time measurement
    #[packed_field(bits = "6..=7", ty = "enum")]
    resolution: PreambleResolution,
}

impl CdsPreamble {
    pub(super) fn new(
        epoch: PreambleEpoch,
        day_bitlen: PreambleDaySegmentLength,
        resolution: PreambleResolution,
    ) -> Self {
        CdsPreamble {
            extension: PreambleExtension::Absent,
            time_code_type: PreambleTimeCodeType::Cds,
            epoch,
            day_bitlen,
            resolution,
        }
    }

    /// Return the 'extension' value of the P-Field
    pub fn extension(&self) -> PreambleExtension {
        self.extension
    }

    /// Return the 'time_code_type' value of the P-Field
    pub fn time_code_type(&self) -> PreambleTimeCodeType {
        self.time_code_type
    }

    /// Return the 'epoch' value of the P-Field
    pub fn epoch(&self) -> PreambleEpoch {
        self.epoch
    }

    /// Return the 'day_bitlen' value of the P-Field
    pub fn day_bitlen(&self) -> PreambleDaySegmentLength {
        self.day_bitlen
    }

    /// Return the 'resolution' value of the P-Field
    pub fn resolution(&self) -> PreambleResolution {
        self.resolution
    }
}

/// Also known as a T-Field, contains the time
///  data of the time code with a 24-bit day segment.
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct CdsTimeField24 {
    /// 24-bit day field
    #[packed_field(bits = "0..=23", endian = "msb")]
    day: Integer<u32, Bits<24>>,

    /// Either milliseconds or microseconds,
    ///  depending on preamble "resolution" field.
    #[packed_field(element_size_bits = "32", endian = "msb")]
    fine: u32,
}

/// Also known as a T-Field, contains the time
///  data of the time code with a 16-bit day segment.
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct CdsTimeField16 {
    /// 16-bit day field
    #[packed_field(bits = "0..=15", endian = "msb")]
    day: u16,

    /// Either milliseconds or microseconds,
    ///  depending on preamble "resolution" field.
    #[packed_field(element_size_bits = "32", endian = "msb")]
    fine: u32,
}

impl CdsTimeField24 {
    /// Creates a new T-Field for the time code
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::time::*;
    /// use crate::lib_ccsds::error::*;
    /// fn main() -> Result<(), Error> {
    ///
    ///    // obtain time from OS
    ///    let day = 20022; // arbitrary
    ///    let fine_ms = 1_234_567; // arbitrary
    ///
    ///    let tf = CdsTimeField24::new(
    ///        day,
    ///        fine_ms
    ///    );
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn new(day: u32, fine: u32) -> Result<Self, Error> {
        if day > CDS_DAY_MAX_VALUE_24_BIT {
            return Err(Error::TimeCode(TimeCodeError::CdsDayExceedsMax));
        }

        Ok(CdsTimeField24 {
            day: day.into(),
            fine,
        })
    }

    /// Return the 'day' value of the T-Field
    pub fn day(&self) -> Result<u32, Error> {
        let Ok(day) = self.day.try_into() else {
            return Err(Error::TimeCode(TimeCodeError::CdsUnableToConvertDay));
        };

        Ok(day)
    }
}

impl CdsTimeField16 {
    /// Creates a new T-Field for the time code
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::time::*;
    /// use crate::lib_ccsds::error::*;
    /// fn main() -> Result<(), Error> {
    ///
    ///    // obtain time from OS
    ///    let day = 20022; // arbitrary
    ///    let fine_ms = 1_234_567; // arbitrary
    ///
    ///    let tf = CdsTimeField16::new(
    ///        day,
    ///        fine_ms
    ///    );
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn new(day: u16, fine: u32) -> Result<Self, Error> {
        Ok(CdsTimeField16 { day, fine })
    }

    /// Return the 'day' value of the T-Field
    pub fn day(&self) -> Result<u16, Error> {
        Ok(self.day)
    }
}

#[duplicate_item(
    time_field      max_type   max_value;
[ CdsTimeField16 ]  [ u16 ]   [ CDS_DAY_MAX_VALUE_16_BIT ];
[ CdsTimeField24 ]  [ u32 ]   [ CDS_DAY_MAX_VALUE_24_BIT ];
)]
impl time_field {
    /// Return the 'fine' value of the T-Field
    pub fn fine(&self) -> u32 {
        self.fine
    }
}

/// A complete CDS time code with a 24-bit day segment.
///
/// This data type is 8 bytes in length.
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct CdsTimeCode24 {
    #[packed_field(element_size_bytes = "1")]
    preamble: CdsPreamble,

    #[packed_field(element_size_bytes = "7")]
    time: CdsTimeField24,
}

/// A complete CDS time code with a 16-bit day segment.
///
/// This data type is 7 bytes in length.
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct CdsTimeCode16 {
    #[packed_field(element_size_bytes = "1")]
    preamble: CdsPreamble,

    #[packed_field(element_size_bytes = "6")]
    time: CdsTimeField16,
}

#[duplicate_item(
    time_code         time_field         max_type  day_bitlen;
    [ CdsTimeCode16 ] [ CdsTimeField16 ] [ u16 ]   [ PreambleDaySegmentLength::Sixteen ];
    [ CdsTimeCode24 ] [ CdsTimeField24 ] [ u32 ]   [ PreambleDaySegmentLength::TwentyFour ];
)]
impl time_code {
    /// Creates a new time code.
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::time::*;
    /// use crate::lib_ccsds::error::*;
    /// fn main() -> Result<(), Error> {
    ///
    ///    // obtain time from OS
    ///    let day = 20022;         // arbitrary
    ///    let fine_ms = 1_234_567; // arbitrary
    ///
    ///    let tc = CdsTimeCode16::new( // or CdsTimeCode24
    ///        day,
    ///        fine_ms,
    ///        PreambleResolution::Milliseconds,
    ///        PreambleEpoch::Jan1958
    ///    );
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn new(
        day: max_type,
        fine: u32,
        fine_resolution: PreambleResolution,
        epoch: PreambleEpoch,
    ) -> Result<Self, Error> {
        let preamble = CdsPreamble::new(epoch, day_bitlen, fine_resolution);
        let time = time_field::new(day, fine)?;
        Ok(time_code { preamble, time })
    }

    /// Returns the P-Field (preamble) of the Time Code.
    pub fn preamble(&self) -> &CdsPreamble {
        &self.preamble
    }

    /// Returns the T-Field of the Time Code.
    pub fn time(&self) -> &time_field {
        &self.time
    }
}

#[cfg(test)]
mod time_tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn ut_cds_time_code_24_invalid_day() {
        let result = CdsTimeCode24::new(
            CDS_DAY_MAX_VALUE_24_BIT + 1,
            0,
            PreambleResolution::Milliseconds,
            PreambleEpoch::Jan1958,
        );
        assert_eq!(
            result.unwrap_err(),
            Error::TimeCode(TimeCodeError::CdsDayExceedsMax)
        );
    }

    #[test]
    fn ut_cds_time_code_16_nominal() -> Result<(), Error> {
        let mut rng = thread_rng();

        let resolution = PreambleResolution::Milliseconds;
        let epoch = PreambleEpoch::Jan1958;
        let day: u16 = CDS_DAY_MAX_VALUE_16_BIT;
        let fine = rng.gen();
        let tc = CdsTimeCode16::new(day, fine, resolution, epoch)?;

        assert_eq!(tc.time().day()?, day);
        assert_eq!(tc.time().fine(), fine);
        assert_eq!(
            tc.preamble().day_bitlen(),
            PreambleDaySegmentLength::Sixteen
        );
        assert_eq!(tc.preamble().epoch(), epoch);
        assert_eq!(tc.preamble().resolution(), resolution);
        assert_eq!(tc.preamble().time_code_type(), PreambleTimeCodeType::Cds);
        assert_eq!(tc.preamble().extension(), PreambleExtension::Absent);

        Ok(())
    }

    #[test]
    fn ut_cds_time_code_24_nominal() -> Result<(), Error> {
        let mut rng = thread_rng();

        let resolutions = [
            PreambleResolution::Microseconds,
            PreambleResolution::Milliseconds,
        ];

        let epochs = [PreambleEpoch::AgencyDefined, PreambleEpoch::Jan1958];

        for resolution in resolutions {
            for epoch in epochs {
                let day: u32 = rng.gen_range(0..=CDS_DAY_MAX_VALUE_24_BIT);
                let fine = rng.gen();
                let tc = CdsTimeCode24::new(day, fine, resolution, epoch)?;

                assert_eq!(tc.time().day()?, day);
                assert_eq!(tc.time().fine(), fine);
                assert_eq!(
                    tc.preamble().day_bitlen(),
                    PreambleDaySegmentLength::TwentyFour
                );
                assert_eq!(tc.preamble().epoch(), epoch);
                assert_eq!(tc.preamble().resolution(), resolution);
                assert_eq!(tc.preamble().time_code_type(), PreambleTimeCodeType::Cds);
                assert_eq!(tc.preamble().extension(), PreambleExtension::Absent);

                let bytes = tc.pack().unwrap();
                let tc2 = CdsTimeCode24::unpack(&bytes).unwrap();
                assert_eq!(tc, tc2);
            }
        }

        Ok(())
    }
}
