//! The default formats of Arrow packet constructs.

// use crate::ccsds::{CcsdsBuilder, CcsdsPacket};
use crate::ccsds::{CcsdsPacket, PacketType, PrimaryHeader, SecondaryHeaderFlag, SequenceFlag};
use crate::error::Error;
use crate::time::{CdsTimeCode24, PreambleEpoch, PreambleResolution};
use packed_struct::prelude::PackedStruct;
use snafu::prelude::Snafu;
use uuid::Uuid;

/// Defines the max length of the secondary header.
pub const ARROW_SECONDARY_HEADER_LEN: usize = 24;

/// Until const generic expressions are supported.
#[allow(dead_code)]
const ARROW_USER_DATA_LEN: usize = 24;

/// The length of the data segment in an Arrow packet
#[allow(dead_code)]
const ARROW_DATA_SEGMENT_SIZE: usize = ARROW_SECONDARY_HEADER_LEN + ARROW_USER_DATA_LEN;

/// Possible Ccsds Packet Construction/Deconstruction Errors
#[derive(Snafu, Copy, Clone, Debug, PartialEq)]
pub enum ArrowError {
    /// Failed to create secondary header given a uuid
    #[snafu(display("invalid uuid"))]
    FailedToParseUuid,

    /// Failed to create secondary header from a byte array
    #[snafu(display("failed to create a secondary header from bytes"))]
    SecondaryHeaderUnpackFailed,

    /// Failed to convert secondary header to a byte array
    #[snafu(display("failed to create a byte array from the secondary header"))]
    SecondaryHeaderPackFailed,
}

/// Secondary Header Field of Arrow Packets
///
/// Uses a CCSDS Day Segmented (CDS) time code.
///
/// Declares the UUID of the sender (128 bits).
///
///
/// ```text
/// +-------------+-----------+
/// |  Time Code  |   UUID    |
/// |             |           |
/// |  8 Bytes    |  16 Bytes |
/// +-------------------------+
/// |         24 Bytes        |
/// +-------------------------+
/// ```
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct ArrowSecondaryHeader {
    /// The time code of the message
    #[packed_field(element_size_bytes = "8", endian = "msb")]
    time_code: CdsTimeCode24,

    /// The upper 64 bits of the sender UUID
    #[packed_field(element_size_bytes = "8", endian = "msb")]
    uuid_major: u64,

    /// The lower 64 bits of the sender UUID
    #[packed_field(element_size_bytes = "8", endian = "msb")]
    uuid_minor: u64,
}

impl ArrowSecondaryHeader {
    /// Creates a new secondary header given a time code and uuid
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::arrow::*;
    /// use crate::lib_ccsds::time::*;
    /// use crate::lib_ccsds::error::*;
    /// use uuid::Uuid;
    /// fn main() -> Result<(), Error> {
    ///    let Ok(tc) = CdsTimeCode24::new(
    ///        20022,     // arbitrary day, obtain actual from OS
    ///        1_234_567, // arbitrary ms, obtain actual from OS
    ///        PreambleResolution::Milliseconds,
    ///        PreambleEpoch::Jan1958
    ///    ) else { panic!(); };
    ///
    ///    // arbitrary uuid, obtain actual from spacecraft
    ///    let uuid = Uuid::nil();
    ///
    ///    let second_header = ArrowSecondaryHeader::new(tc, uuid)?;
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn new(time_code: CdsTimeCode24, uuid: Uuid) -> Result<Self, Error> {
        let uuid = uuid.into_bytes();
        let Ok(uuid_major) = <[u8; 8]>::try_from(&uuid[0..8]) else {
            return Err(Error::Arrow(ArrowError::FailedToParseUuid));
        };

        let Ok(uuid_minor) = <[u8; 8]>::try_from(&uuid[8..16]) else {
            return Err(Error::Arrow(ArrowError::FailedToParseUuid));
        };

        Ok(ArrowSecondaryHeader {
            time_code,
            uuid_major: u64::from_be_bytes(uuid_major),
            uuid_minor: u64::from_be_bytes(uuid_minor),
        })
    }

    /// Unpack a secondary header from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let Ok(arr) = <&[u8; ARROW_SECONDARY_HEADER_LEN]>::try_from(bytes) else {
            return Err(Error::Arrow(ArrowError::SecondaryHeaderUnpackFailed));
        };

        let Ok(header) = ArrowSecondaryHeader::unpack(arr) else {
            return Err(Error::Arrow(ArrowError::SecondaryHeaderUnpackFailed));
        };

        Ok(header)
    }

    /// Writes an ArrowSecondaryHeader to a target buffer and return the
    ///  number of bytes written (should be [`ARROW_SECONDARY_HEADER_LEN`]).
    pub fn encode(&self, target: &mut [u8]) -> Result<usize, Error> {
        let Ok(packed_header) = self.pack() else {
            return Err(Error::Arrow(ArrowError::SecondaryHeaderPackFailed));
        };

        if packed_header.len() > target.len() {
            return Err(Error::Arrow(ArrowError::SecondaryHeaderPackFailed));
        }

        target[..packed_header.len()].copy_from_slice(&packed_header);
        Ok(packed_header.len())
    }

    /// Returns a reference to the time code field
    pub fn time_code(&self) -> &CdsTimeCode24 {
        &self.time_code
    }
}

/// An Arrow Packet is a CcsdsPacket with a standard
///  secondary header ([`ArrowSecondaryHeader`]).
///
/// The "user_data" argument will be used for the "user data" field
///  of the data segment. It should not include a header or
///  secondary header.
///
/// ```text
/// +----------------+-----------------------------------+
/// | HEADER SEGMENT |         DATA SEGMENT              |
/// +----------------+------------------+----------------+
/// | Primary Header | Secondary Header |   User Data    |
/// |                |                  |                |
/// | 48 Bits (6B)   |  224 Bits (28B)  | 224 Bits (28B) |
/// +----------------+------------------+----------------+
/// |                                                    |
/// +----------------------------------------------------+
/// ```
#[allow(clippy::too_many_arguments)]
pub fn arrow_packet(
    sender_uuid: &Uuid,
    packet_type: PacketType,
    apid: u16,
    sequence_count: u16,
    sequence_flag: SequenceFlag,
    day: u32,
    fine: u32,
    user_data: &[u8],
) -> Result<CcsdsPacket<ARROW_DATA_SEGMENT_SIZE>, Error> {
    // Create the primary header
    let header = PrimaryHeader::new(
        0b1, // version
        packet_type,
        SecondaryHeaderFlag::Present,
        apid, // apid
        sequence_flag,
        sequence_count, // sequence count
    )?;

    // Create the time code
    let tc = CdsTimeCode24::new(
        day,
        fine,
        PreambleResolution::Milliseconds,
        PreambleEpoch::Jan1958,
    )?;

    let secondary_header = ArrowSecondaryHeader::new(tc, *sender_uuid)?;

    // Create the secondary header
    let mut bytes = [0; ARROW_SECONDARY_HEADER_LEN];
    let _ = secondary_header.encode(&mut bytes)?;

    CcsdsPacket::<ARROW_DATA_SEGMENT_SIZE>::builder()
        .with_primary_header(header)?
        .with_secondary_header(&bytes)?
        .with_user_data(user_data)?
        .build()
}

#[cfg(test)]
mod arrow_secondary_header_tests {
    use super::*;
    use crate::time::*;
    use rand::prelude::*;
    use uuid::uuid;

    #[test]
    fn ut_to_decode_24() -> Result<(), Error> {
        let mut rng = thread_rng();

        let resolutions = [
            PreambleResolution::Microseconds,
            PreambleResolution::Milliseconds,
        ];

        let epochs = [PreambleEpoch::AgencyDefined, PreambleEpoch::Jan1958];

        for resolution in resolutions {
            for epoch in epochs {
                let tc = CdsTimeCode24::new(
                    rng.gen_range(0..CDS_DAY_MAX_VALUE_24_BIT), // arbitrary day, obtain actual from OS
                    rng.gen(), // arbitrary ms, obtain actual from OS
                    resolution,
                    epoch,
                )?;

                // arbitrary uuid, obtain actual from spacecraft
                let uuid = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8");

                // Got the header
                let header_1 = ArrowSecondaryHeader::new(tc, uuid)?;
                assert_eq!(header_1.time_code().preamble().epoch(), epoch);

                // Empty target buffer
                let mut bytes = [0; ARROW_SECONDARY_HEADER_LEN];

                // Confirm correct number of bytes are written
                assert_eq!(ARROW_SECONDARY_HEADER_LEN, header_1.encode(&mut bytes)?);

                // Confirm the two headers are the same
                assert_eq!(header_1, header_1);

                // Create a new header from the same bytes
                let header_2 = ArrowSecondaryHeader::decode(&bytes)?;
                assert_eq!(header_2.time_code().preamble().epoch(), epoch);

                // Confirm the two headers are the same
                assert_eq!(header_1, header_2);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod arrow_packet_tests {
    use super::*;
    use crate::time::*;
    use rand::prelude::*;
    use uuid::uuid;

    #[test]
    fn ut_new_packet() -> Result<(), Error> {
        const U: usize = ARROW_DATA_SEGMENT_SIZE; // todo const generics

        let mut rng = thread_rng();

        // Create expected values
        let uuid = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"); // arbitrary
        const USER_DATA_LEN: usize = U - ARROW_SECONDARY_HEADER_LEN;
        let day = rng.gen_range(0..CDS_DAY_MAX_VALUE_24_BIT); // arbitrary day
        let fine = rng.gen(); // arbitrary fine measurement
        let apid = 0xCD;
        let seq_count = 0xAB;
        let pkt_type = PacketType::Telemetry;
        let seq_flag = SequenceFlag::Unsegmented;
        let mut user_data = [0; USER_DATA_LEN];
        for i in 0..USER_DATA_LEN {
            user_data[i] = rng.gen();
        }

        // Build Packet
        let packet: CcsdsPacket<U> = arrow_packet(
            &uuid, pkt_type, apid,      // APID
            seq_count, // Sequence Count
            seq_flag, day,  // arbitrary day
            fine, // arbitrary fine measurement
            &user_data,
        )?;

        // Expected Secondary Header
        let expected_tc = CdsTimeCode24::new(
            day,
            fine,
            PreambleResolution::Milliseconds,
            PreambleEpoch::Jan1958,
        )?;
        let expected_secondary = ArrowSecondaryHeader::new(expected_tc, uuid)?;
        let mut expected_sh_bytes = [0; ARROW_SECONDARY_HEADER_LEN];
        let _ = expected_secondary.encode(&mut expected_sh_bytes)?;

        // Checks
        let ph: &PrimaryHeader = packet.primary_header();
        assert_eq!(ph.identification().apid(), apid);
        assert_eq!(
            ph.identification().secondary_header_flag(),
            SecondaryHeaderFlag::Present
        );
        assert_eq!(ph.identification().packet_type(), pkt_type);
        assert_eq!(ph.sequence_control().flag(), seq_flag);
        assert_eq!(ph.sequence_control().count(), seq_count);

        assert_eq!(
            packet.data()[..ARROW_SECONDARY_HEADER_LEN],
            expected_sh_bytes
        );

        assert_eq!(
            packet.data()[ARROW_SECONDARY_HEADER_LEN..ARROW_DATA_SEGMENT_SIZE],
            user_data
        );

        Ok(())
    }
}
