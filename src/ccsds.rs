//! Implementation of the CCSDS Packet Frame Specification
//! Source: <https://public.ccsds.org/Pubs/133x0b2e1.pdf>
//!
//! # Usage
//! The [`CcsdsBuilder`] object is the safest way to construct
//!  a [`CcsdsPacket`].

use packed_struct::prelude::{packed_bits::Bits, Integer, PackedStruct, PrimitiveEnum_u8};

use snafu::prelude::Snafu;

/// Possible Ccsds Packet Construction/Deconstruction Errors
#[derive(Snafu, Copy, Clone, Debug, PartialEq)]
pub enum CcsdsError {
    /// Failed to add a duplicate primary header
    #[snafu(display("cannot have multiple primary headers"))]
    DuplicatePrimaryHeader,

    /// Tried to construct a larger packet than allowed
    #[snafu(display("this action would add more bytes to the data segment than allowed"))]
    ExceedsMaxDataLength,

    /// Tried to add fields or construct the packet without a header
    #[snafu(display("the header must be added before data fields"))]
    MissingHeader,

    /// Tried to add a secondary header after user data
    #[snafu(display("the secondary header must precede user data"))]
    SecondaryHeaderAfterUserData,

    /// Tried to build a packet without any data fields
    #[snafu(display("a secondary header or user data field (or both) must be present"))]
    MissingSecondaryHeaderAndUserData,

    /// Tried to set a sequence number larger than [`SEQ_COUNT_MAX`]
    #[snafu(display("sequence count exceeds 14-bit value"))]
    ExceedsSequenceCountMax,

    /// Tried to set a version value larger than [`PVN_MAX`]
    #[snafu(display("version exceeds 3-bit value"))]
    ExceedsPrimaryVersionMax,

    /// Tried to set an APID value larger than [`APID_MAX`]
    #[snafu(display("apid exceeds 11-bit value"))]
    ExceedsApidMax,

    /// Tried to create a CCSDS packet from a buffer smaller than 7 (header length + 1)
    #[snafu(display("buffer must equal or exceed 7 bytes (minimum ccsds packet length)"))]
    InsufficientData,

    /// Tried to transform a [`CcsdsBuilder`] to a [`CcsdsPacket`] without adding enough data
    #[snafu(display("not enough data to build a packet of the given size"))]
    NotEnoughDataToBuildPacket,

    /// Tried to create a packet with zero data
    #[snafu(display("there must be at least one byte in the data segment"))]
    RequiresData,

    /// Unable to unpack the [`PrimaryHeader`] from a byte array
    #[snafu(display("failed to unpack the header section from a byte array"))]
    PrimaryHeaderUnpackFailed,

    /// Unable to unpack data from a byte array
    #[snafu(display("failed to unpack the data section from a byte array"))]
    DataUnpackFailed,

    /// Unable to pack the [`PrimaryHeader`] object into a byte array
    #[snafu(display("failed to pack the header section into a byte array"))]
    PrimaryHeaderPackFailed,

    /// Buffer too small for to write a [`CcsdsPacket`]
    #[snafu(display("failed to write the ccsds packet to the target buffer"))]
    TargetBufferTooSmall,
}

/// APID is an 11-bit field
pub const APID_MAX: u16 = 0x07FF;

/// Idle APID is all ones, max
pub const APID_IDLE: u16 = APID_MAX;

/// Sequence Count Field Max (14-bit field), 16383
pub const SEQ_COUNT_MAX: u16 = 0x3FFF;

/// Packet Version Number Maximum Value (3-bit field)
pub const PVN_MAX: u8 = 0b111;

/// Max number of bytes
/// 3.2.2.1 of CCSDS specification
pub const PACKET_LEN_MAX: usize = 65542;

/// Max size of header
const HEADER_LEN: usize = 6;

/// Packet Type (1-bit): 0 for Telemetry, 1 for Command
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum PacketType {
    /// The packet concerns telemetry
    Telemetry = 0,

    /// The packet concerns commanding
    Command = 1,
}

/// Secondary Header Presence (1-bit): 1 if present
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum SecondaryHeaderFlag {
    /// There is no secondary header present in the packet
    Absent = 0,

    /// There is a secondary header present in the packet
    Present = 1,
}

/// Type of Packet Relative to Sequence
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum SequenceFlag {
    /// A continuation of series of related packets
    Continued = 0b00,

    /// Marks the beginning of a series of related packets
    Start = 0b01,

    /// Marks the end of a series of related packets
    End = 0b10,

    /// Unassociated with other packets
    Unsegmented = 0b11,
}

/// The identification field segment of the primary header.
///
/// Unless specified, all fields are mandatory.
///
/// In this implementation, the 3-bit version field of the
/// primary header is included in the (normally) 13-bit
/// Identification section for a total of 16 bits.
/// ```text
/// +----------+---------------+-----------------+---------+
/// | Version  |  Packet Type  | 2nd Header Flag |   APID  |
/// |          |    TLM/CMD    | Absent/Present  |         |
/// |  3 Bits  |     1 Bit     |     1 Bit       | 11 Bits |
/// +----------+---------------+-----------------+---------+
/// |                  16 Bits (2 Bytes)                   |
/// +------------------------------------------------------+
/// ```
/// 4.1.3.3 of CCSDS specification
#[derive(PackedStruct, Debug, Clone, Copy, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct Identification {
    /// Packet Version Number (Mandatory)
    #[packed_field(bits = "0..=2")]
    version: Integer<u8, Bits<3>>,

    /// Telemetry or Command (Mandatory)
    #[packed_field(bits = "3..=3", ty = "enum")]
    packet_type: PacketType,

    /// Indicates the presence of a secondary header (Mandatory)
    #[packed_field(bits = "4..=4", ty = "enum")]
    secondary_header_flag: SecondaryHeaderFlag,

    /// Indicates the user or purpose of the packet
    /// These codes can be unique to the organization
    /// (Mandatory)
    #[packed_field(bits = "5..=15", endian = "msb")]
    apid: Integer<u16, Bits<11>>,
}

impl Identification {
    /// Creates the identification field of the primary header.
    pub fn new(
        version: u8,
        packet_type: PacketType,
        secondary_header_flag: SecondaryHeaderFlag,
        apid: u16,
    ) -> Result<Identification, CcsdsError> {
        if version > PVN_MAX {
            return Err(CcsdsError::ExceedsPrimaryVersionMax);
        }

        if apid > APID_MAX {
            return Err(CcsdsError::ExceedsApidMax);
        }

        Ok(Identification {
            version: version.into(),
            packet_type,
            secondary_header_flag,
            apid: apid.into(),
        })
    }

    /// Sets the secondary_header_flag to 1 (Present)
    pub(super) fn set_secondary_header_flag(&mut self) {
        self.secondary_header_flag = SecondaryHeaderFlag::Present;
    }
}

/// Sequence Control Section of CCSDS Primary [`PrimaryHeader`]
///
/// This section occupies 16 bits of the primary header.
/// Unless specified, all fields are mandatory.
/// ```text
/// +-----------------------+------------------------+
/// |     Sequence Flag     |     Sequence Count     |
/// |                       |                        |
/// |        2 Bits         |         14 Bits        |
/// +-----------------------+------------------------+
/// |                16 Bits (2 Bytes)               |
/// +------------------------------------------------+
/// ```
/// 4.1.3.4 of CCSDS specification
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct SequenceControl {
    #[packed_field(bits = "0..=1", ty = "enum")]
    flag: SequenceFlag,

    /// The packet number in the sequence
    #[packed_field(bits = "2..=15", endian = "msb")]
    count: Integer<u16, Bits<14>>,
}

impl SequenceControl {
    /// Creates the sequence control section of the primary header.
    pub fn new(flag: SequenceFlag, count: u16) -> Result<SequenceControl, CcsdsError> {
        if count > SEQ_COUNT_MAX {
            return Err(CcsdsError::ExceedsSequenceCountMax);
        }

        Ok(SequenceControl {
            flag,
            count: count.into(),
        })
    }
}

/// CCSDS Packet Primary Header.
///
/// The primary header occupies the first six bytes of the packet.
/// Unless specified, all fields are mandatory.
/// ```text
/// +---------+----------------+------------------+--------------+
/// | Version + Identification | Sequence Control |  Data Length |
/// |                          |                  |              |
/// | 3 Bits  |    13 Bits     |     16 Bits      |    16 Bits   |
/// +---------+----------------+------------------+--------------+
/// |                       48 Bits (6 Bytes)                    |
/// +------------------------------------------------------------+
/// ```
/// See 4.1.3 of CCSDS specification
#[derive(PackedStruct, Debug, Copy, Clone, PartialEq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct PrimaryHeader {
    /// Identification Section, 2 Octets
    #[packed_field(element_size_bytes = "2")]
    pub identification: Identification,

    /// Sequence Control Section, 2 Octets
    #[packed_field(element_size_bytes = "2")]
    pub sequence_control: SequenceControl,

    /// Length of coming data (in bytes) - 1
    #[packed_field(endian = "msb")]
    data_len_bytes: u16,
}

impl PrimaryHeader {
    /// Assemble a primary header from individual fields.
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    let header = PrimaryHeader::new(
    ///        0b111, // version
    ///        PacketType::Command,
    ///        SecondaryHeaderFlag::Present,
    ///        1, // apid
    ///        SequenceFlag::Unsegmented,
    ///        10, // sequence count
    ///    )?;
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn new(
        version: u8,
        packet_type: PacketType,
        secondary_header_flag: SecondaryHeaderFlag,
        apid: u16,
        sequence_flag: SequenceFlag,
        sequence_count: u16,
    ) -> Result<Self, CcsdsError> {
        let id_section = Identification::new(version, packet_type, secondary_header_flag, apid)?;

        let seq_section = SequenceControl::new(sequence_flag, sequence_count)?;

        Ok(Self::from_sections(id_section, seq_section))
    }

    /// Assemble a primary header from sections.
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    let id_section = Identification::new(
    ///        0b11, PacketType::Command, SecondaryHeaderFlag::Absent, 1)?;
    ///
    ///    let seq_section = SequenceControl::new(SequenceFlag::Start, 2)?;
    ///
    ///    let header = PrimaryHeader::from_sections(id_section, seq_section);
    ///    Ok(())
    /// }
    /// ```
    pub fn from_sections(
        id_section: Identification,
        sequence_control_section: SequenceControl,
    ) -> PrimaryHeader {
        PrimaryHeader {
            identification: id_section,
            sequence_control: sequence_control_section,
            data_len_bytes: 0,
        }
    }

    /// Assemble a primary header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PrimaryHeader, CcsdsError> {
        let Ok(arr) = <&[u8; HEADER_LEN]>::try_from(bytes) else {
            return Err(CcsdsError::PrimaryHeaderUnpackFailed);
        };

        let Ok(header) = PrimaryHeader::unpack(arr) else {
            return Err(CcsdsError::PrimaryHeaderUnpackFailed);
        };

        Ok(header)
    }

    /// Returns the value of the data_length field.
    pub fn data_len_bytes(&self) -> u16 {
        self.data_len_bytes
    }

    /// Clears the value of the data_length field.
    pub(super) fn clear_data(&mut self) {
        self.data_len_bytes = 0;
    }
}

/// A CCSDS packet frame.
///
/// ```text
/// +----------------+--------------------------------------------------+
/// |     HEADER     |                  DATA SEGMENT                    |
/// +----------------+--------------------------------+-----------------+
/// | Primary Header |        Secondary Header        |    User Data    |
/// |                | (Optional Unless No User Data) |    (Optional)   |
/// |     6 Bytes    |        Variable Length         | Variable Length |
/// +----------------+--------------------------------+-----------------+
/// ```
///
/// This type is implemented for [u8; N] types, where N is
///  the number of bytes in the data segment.
///
/// The safest way to build a CcsdsPacket from scratch is with
///  the [`CcsdsBuilder`] object.
#[derive(Debug)]
pub struct CcsdsPacket<const N: usize> {
    header: PrimaryHeader,
    data: [u8; N],
}

impl<const N: usize> CcsdsPacket<N> {
    /// Returns a Builder object for the CcsdsPacket with
    ///  N bytes in the data segment.
    pub fn builder() -> CcsdsBuilder<N> {
        CcsdsBuilder::<N>::default()
    }

    /// Returns the value of the secondary header flag field
    ///  in the header.
    pub fn secondary_header_flag(&self) -> SecondaryHeaderFlag {
        self.header.identification.secondary_header_flag
    }

    /// Returns the value of the data length field in the header.
    pub fn data_len_bytes(&self) -> u16 {
        self.header.data_len_bytes
    }

    /// Writes the packet to a buffer and returns the number of bytes written.
    ///
    /// The target buffer must be size `N` + 6 (size of a header)
    ///  to capture the entire packet, or this will return
    ///  [`CcsdsError::TargetBufferTooSmall`].
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    let header = PrimaryHeader::new(
    ///        0b111,
    ///        PacketType::Command,
    ///        SecondaryHeaderFlag::Present,
    ///        APID_MAX,
    ///        SequenceFlag::Unsegmented,
    ///        SEQ_COUNT_MAX,
    ///    )?;
    ///
    ///    const n_data: usize = 1024;
    ///
    ///    // The complete packet needs an extra 6 bytes for the header.
    ///    const n_total: usize = n_data + 6;
    ///
    ///    let mut target: [u8; n_total] = [0; n_total];
    ///
    ///    // Write to u8 array
    ///    let packet = CcsdsPacket::<n_data>::builder()
    ///        .with_primary_header(header)?
    ///        .with_secondary_header(&[0; n_data])?
    ///        .build()?
    ///        .to_bytes(&mut target);
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn to_bytes(&self, target: &mut [u8]) -> Result<usize, CcsdsError> {
        let Ok(packed_header) = self.header.pack() else {
            return Err(CcsdsError::PrimaryHeaderPackFailed);
        };

        let packet_length: usize = self.data.len() + packed_header.len();
        if packet_length > target.len() {
            return Err(CcsdsError::TargetBufferTooSmall);
        }

        target[..packed_header.len()].copy_from_slice(&packed_header);
        target[packed_header.len()..packet_length].copy_from_slice(&self.data);

        Ok(packet_length)
    }

    /// Consumes the buffer and produces a CcsdsPacket with N bytes in the data region
    ///
    /// Too few bytes or too many bytes in the buffer argument will result
    ///  in [`CcsdsError::InsufficientData`] or [`CcsdsError::ExceedsMaxDataLength`]
    ///  respectively.
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    const n_data: usize = 1;
    ///
    ///    // n_data + 6 header bytes for a complete packet
    ///    let buffer = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    ///
    ///    let packet = CcsdsPacket::<n_data>::from_bytes(&buffer)?;
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<CcsdsPacket<N>, CcsdsError> {
        if bytes.len() < (N + HEADER_LEN) {
            return Err(CcsdsError::InsufficientData);
        }

        if bytes.len() > (N + HEADER_LEN) {
            return Err(CcsdsError::ExceedsMaxDataLength);
        }

        let Ok(header) = PrimaryHeader::from_bytes(&bytes[..HEADER_LEN]) else {
            return Err(CcsdsError::PrimaryHeaderUnpackFailed);
        };

        let Ok(data) = <[u8; N]>::try_from(&bytes[HEADER_LEN..]) else {
            return Err(CcsdsError::DataUnpackFailed);
        };

        let packet = CcsdsPacket { header, data };

        Ok(packet)
    }
}

/// Safely construct a CCSDS Packet, consuming all arguments fed to it.
///
/// CcsdsBuilder is implemented for all [u8; const N: usize] types, where
///  `N` is the maximum allowable size for the data segment of the packet
///  (doesn't include the header).
///
/// Will prevent the following:
/// - Adding a "secondary header" AFTER a "user data" field has been added
/// - Setting larger values than a field would allow
/// - Adding multiple primary headers
/// - Adding more data than exceeds the predetermined size of the packet
/// - Building a packet with less than the expected amount of data provided
///
/// Will perform the following automatically:
/// - Toggle the header's secondary_header_flag to 1 if a secondary header is added
///
/// # Examples
/// ```
/// use crate::lib_ccsds::ccsds::*;
/// fn main() -> Result<(), CcsdsError> {
///    let header = PrimaryHeader::new(
///        0b111,
///        PacketType::Command,
///        SecondaryHeaderFlag::Present,
///        APID_MAX,
///        SequenceFlag::Unsegmented,
///        SEQ_COUNT_MAX,
///    )?;
///
///    // Declare that the number of bytes in the
///    //  data segment must be 10.
///    let packet = CcsdsPacket::<10>::builder()
///        .with_primary_header(header)?
///        .with_secondary_header(&[0; 6])?
///        .with_user_data(&[0; 4])?
///        .build()?;
///
///    Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct CcsdsBuilder<const N: usize> {
    header: Option<PrimaryHeader>,
    has_secondary_header: bool,
    has_user_data: bool,
    data: [u8; N],
    index: usize,
}

impl<const N: usize> Default for CcsdsBuilder<N> {
    /// Returns a fresh builder object.
    fn default() -> Self {
        CcsdsBuilder {
            header: None,
            has_secondary_header: false,
            has_user_data: false,
            data: [0; N],
            index: 0,
        }
    }
}

impl<const N: usize> CcsdsBuilder<N> {
    /// Add data to the packet.
    fn add_data(&mut self, data: &[u8]) -> Result<(), CcsdsError> {
        let total_data_bytes: usize = self.index + data.len();

        // Can't be larger than the data_length field can indicate (16-bits)
        if total_data_bytes > (u16::MAX as usize) {
            return Err(CcsdsError::ExceedsMaxDataLength);
        }

        // Can't exceed predefined packet size
        if total_data_bytes > N {
            return Err(CcsdsError::ExceedsMaxDataLength);
        }

        self.data[self.index..total_data_bytes].copy_from_slice(data);
        self.index = total_data_bytes;
        Ok(())
    }

    /// Adds a header to the Builder object.
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    let header = PrimaryHeader::new(
    ///        0b111,
    ///        PacketType::Command,
    ///        SecondaryHeaderFlag::Present,
    ///        APID_MAX,
    ///        SequenceFlag::Unsegmented,
    ///        SEQ_COUNT_MAX,
    ///    )?;
    ///
    ///    let packet = CcsdsPacket::<10>::builder()
    ///        .with_primary_header(header)?
    ///        .with_secondary_header(&[0; 10])?
    ///        .build()?;
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn with_primary_header(
        mut self,
        mut header: PrimaryHeader,
    ) -> Result<CcsdsBuilder<N>, CcsdsError> {
        if self.header.is_some() {
            return Err(CcsdsError::DuplicatePrimaryHeader);
        }

        header.clear_data();
        self.header = Some(header);

        Ok(self)
    }

    /// Adds a "Secondary Header" segment to the packet data segment.
    ///
    /// If the length of (the buffer argument + existing
    ///  data) would be greater than `N`, this will return
    /// a [`CcsdsError::ExceedsMaxDataLength`].
    ///
    /// A primary header must be present, or this
    ///  function will return [`CcsdsError::MissingHeader`].
    ///
    /// If a User Data field has already been added through
    ///  the builder, the function will return a
    ///  [`CcsdsError::SecondaryHeaderAfterUserData`].
    ///  A secondary header MUST precede any User Data field.
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    let header = PrimaryHeader::new(
    ///        0b111,
    ///        PacketType::Command,
    ///        SecondaryHeaderFlag::Present,
    ///        APID_MAX,
    ///        SequenceFlag::Unsegmented,
    ///        SEQ_COUNT_MAX,
    ///    )?;
    ///
    ///    let packet = CcsdsPacket::<10>::builder()
    ///        .with_primary_header(header)?
    ///        .with_secondary_header(&[0; 10])?
    ///        .build()?;
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn with_secondary_header(mut self, data: &[u8]) -> Result<CcsdsBuilder<N>, CcsdsError> {
        if self.has_user_data {
            return Err(CcsdsError::SecondaryHeaderAfterUserData);
        }

        let Some(mut header) = self.header else {
            return Err(CcsdsError::MissingHeader)
        };

        self.add_data(data)?;
        self.has_secondary_header = true;
        header.identification.set_secondary_header_flag();
        self.header = Some(header);
        Ok(self)
    }

    /// Adds a User Data field to the data segment.
    ///
    /// If the length of (the buffer argument + existing
    ///  data) would be greater than `N`, this will return
    /// a [`CcsdsError::ExceedsMaxDataLength`].
    ///
    /// A primary header must be present, or this
    ///  function will return [`CcsdsError::MissingHeader`].
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    let header = PrimaryHeader::new(
    ///        0b111,
    ///        PacketType::Command,
    ///        SecondaryHeaderFlag::Present,
    ///        APID_MAX,
    ///        SequenceFlag::Unsegmented,
    ///        SEQ_COUNT_MAX,
    ///    )?;
    ///
    ///    let packet = CcsdsPacket::<10>::builder()
    ///        .with_primary_header(header)?
    ///        .with_user_data(&[0; 10])?
    ///        .build()?;
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn with_user_data(mut self, data: &[u8]) -> Result<CcsdsBuilder<N>, CcsdsError> {
        self.add_data(data)?;
        self.has_user_data = true;
        Ok(self)
    }

    /// Builds a [`CcsdsPacket`] with N bytes in the data segment,
    ///  consuming the builder.
    ///
    /// If `N` is 0, will return [`CcsdsError::RequiresData`].
    ///  CCSDS requires at least one byte in the data segment.
    ///
    /// A primary header must be present, or this
    ///  function will return [`CcsdsError::MissingHeader`].
    ///
    /// [`CcsdsError::MissingSecondaryHeaderAndUserData`] will be returned
    ///  if no secondary header OR user data was provided.
    ///
    /// [`CcsdsError::NotEnoughDataToBuildPacket`] will be returned if
    ///  less than `N` data has been provided in the data segment.
    ///
    /// # Examples
    /// ```
    /// use crate::lib_ccsds::ccsds::*;
    /// fn main() -> Result<(), CcsdsError> {
    ///    let header = PrimaryHeader::new(
    ///        0b111,
    ///        PacketType::Command,
    ///        SecondaryHeaderFlag::Present,
    ///        APID_MAX,
    ///        SequenceFlag::Unsegmented,
    ///        SEQ_COUNT_MAX,
    ///    )?;
    ///
    ///    let packet = CcsdsPacket::<1024>::builder()
    ///        .with_primary_header(header)?
    ///        .with_secondary_header(&[0; 1000])?
    ///        .with_user_data(&[0; 24])?
    ///        .build()?;
    ///
    ///    Ok(())
    /// }
    /// ```
    pub fn build(self) -> Result<CcsdsPacket<N>, CcsdsError> {
        if N == 0 {
            return Err(CcsdsError::RequiresData);
        }

        let Some(mut header) = self.header else {
            return Err(CcsdsError::MissingHeader)
        };

        if !self.has_secondary_header && !self.has_user_data {
            return Err(CcsdsError::MissingSecondaryHeaderAndUserData);
        }

        if self.index < N {
            return Err(CcsdsError::NotEnoughDataToBuildPacket);
        }

        // 4.1.3.5.2 CCSDS specification
        // data length should be one octet/byte fewer than
        //  actual data length of packet data segment.
        header.data_len_bytes = (N - 1) as u16;

        Ok(CcsdsPacket {
            header,
            data: self.data,
        })
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn ut_header_valid_max() {
        PrimaryHeader::new(
            0b111, // version too high
            PacketType::Command,
            SecondaryHeaderFlag::Present,
            APID_MAX, // apid
            SequenceFlag::Unsegmented,
            SEQ_COUNT_MAX, // sequence count
        )
        .unwrap();
    }

    #[test]
    fn ut_header_valid_min() {
        PrimaryHeader::new(
            0b000, // version too high
            PacketType::Telemetry,
            SecondaryHeaderFlag::Absent,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )
        .unwrap();
    }

    #[test]
    fn ut_header_invalid_version() {
        let header = PrimaryHeader::new(
            0b111 + 1, // version too high
            PacketType::Telemetry,
            SecondaryHeaderFlag::Absent,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        );

        assert_eq!(header.unwrap_err(), CcsdsError::ExceedsPrimaryVersionMax);
    }

    #[test]
    fn ut_header_invalid_seq_count() {
        let header = PrimaryHeader::new(
            0b000,
            PacketType::Telemetry,
            SecondaryHeaderFlag::Absent,
            0, // apid
            SequenceFlag::Unsegmented,
            SEQ_COUNT_MAX + 1, // sequence count too high!
        );

        assert_eq!(header.unwrap_err(), CcsdsError::ExceedsSequenceCountMax);
    }

    #[test]
    fn ut_header_invalid_apid() {
        let header = PrimaryHeader::new(
            0, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Absent,
            APID_MAX + 1, // apid too high!
            SequenceFlag::Unsegmented,
            0, // sequence count
        );

        assert_eq!(header.unwrap_err(), CcsdsError::ExceedsApidMax);
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;

    #[test]
    fn ut_builder_not_enough_data() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;

        // Give no data
        let result = CcsdsPacket::<1024>::builder()
            .with_primary_header(header)?
            .with_secondary_header(&[])?
            .build();

        assert_eq!(result.unwrap_err(), CcsdsError::NotEnoughDataToBuildPacket);

        Ok(())
    }

    #[test]
    fn ut_builder_minimum_size() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;

        // Must have at least one byte in the data segment
        // 4.1.4.1.2 of CCSDS specification
        let packet = CcsdsPacket::<0>::builder()
            .with_primary_header(header)?
            .with_secondary_header(&[])?
            .build();
        assert_eq!(packet.unwrap_err(), CcsdsError::RequiresData);

        Ok(())
    }
}

#[cfg(test)]
#[duplicate::duplicate_item(
    buf_len;
    [ 1024 ];
    // [ 4096 ];
)]
mod builder_rep_tests {
    use super::*;

    #[test]
    /// secondary_header_flag should set to "Present"
    ///  if secondary_header is added through builder
    fn ut_builder_auto_toggle_secondary_header_flag() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Absent, // Set to ABSENT!
            0,                           // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;

        let second_header: [u8; buf_len] = [0x11; buf_len];

        // Add a secondary header despite absence
        let packet = CcsdsPacket::<buf_len>::builder()
            .with_primary_header(header)?
            .with_secondary_header(&second_header)?
            .build()?;

        assert_eq!(packet.secondary_header_flag(), SecondaryHeaderFlag::Present);

        Ok(())
    }

    #[test]
    /// The CCSDS Packet MUST have either
    ///  a secondary header or a user data field, or both.
    fn ut_builder_2hdr_or_user_data() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Absent,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;

        let packet = CcsdsPacket::<buf_len>::builder()
            .with_primary_header(header)?
            .build();

        assert_eq!(
            packet.unwrap_err(),
            CcsdsError::MissingSecondaryHeaderAndUserData
        );

        Ok(())
    }

    #[test]
    fn ut_builder_secondary_header_after_user_data() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;

        // Give no data
        let builder = CcsdsPacket::<buf_len>::builder()
            .with_primary_header(header)?
            .with_user_data(&[])?
            .with_secondary_header(&[]);

        // can't add secondary header after user_data
        assert_eq!(
            builder.unwrap_err(),
            CcsdsError::SecondaryHeaderAfterUserData
        );

        Ok(())
    }

    #[test]
    fn ut_builder_too_much_data() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;

        let data = [0; buf_len];
        let builder = CcsdsPacket::<buf_len>::builder()
            .with_primary_header(header)?
            .with_secondary_header(&data)? // succeeds
            .with_user_data(&[0x00]); // add one more than max, fails
        assert_eq!(builder.unwrap_err(), CcsdsError::ExceedsMaxDataLength);

        Ok(())
    }

    #[test]
    fn ut_builder_duplicate_header() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;
        let header_2 = header.clone();

        let builder = CcsdsPacket::<buf_len>::builder()
            .with_primary_header(header)?
            .with_primary_header(header_2);
        assert_eq!(builder.unwrap_err(), CcsdsError::DuplicatePrimaryHeader);

        Ok(())
    }

    #[test]
    fn ut_builder_to_from_bytes() -> Result<(), CcsdsError> {
        let header = PrimaryHeader::new(
            0b1, // version
            PacketType::Telemetry,
            SecondaryHeaderFlag::Present,
            0, // apid
            SequenceFlag::Unsegmented,
            0, // sequence count
        )?;
        let mut header_original = header.clone();

        let mut data: [u8; buf_len] = [0; buf_len];

        // Fill data buffer with ascending data
        for x in 0..data.len() {
            data[x] = x as u8;
        }

        let mut target: [u8; buf_len + HEADER_LEN] = [0; buf_len + HEADER_LEN];

        // To Bytes
        let n_written = CcsdsPacket::<buf_len>::builder()
            .with_primary_header(header)?
            .with_secondary_header(&data)? // succeeds
            .build()?
            .to_bytes(&mut target)?;

        assert_eq!(n_written, buf_len + HEADER_LEN);
        assert_eq!(target.len(), HEADER_LEN + data.len());

        // From Bytes
        let packet = CcsdsPacket::<buf_len>::from_bytes(&target)?;

        // header should update to add data.len() - 1 bytes to data_length field
        // data_len value should be one less than actual number of bytes in packet
        //  data segment
        // 4.1.3.5.2 CCSDS specification
        header_original.data_len_bytes = data.len() as u16 - 1;
        assert_eq!(packet.header, header_original);
        assert_eq!(packet.data, data);

        Ok(())
    }
}
