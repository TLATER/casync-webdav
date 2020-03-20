/// A module to read CaFormat files.
///
/// ## CaFormat files
///
/// CaFormat files are files written by
/// [casync](https://github.com/systemd/casync) - generally `.catar`
/// files, though they have cousins in `.caidx`, `.caibx` and `.cacnk`
/// files.
///
/// `.catar` files are essentially concatenated CAS chunks with
/// metadata that allows them to easily be pieced back together to
/// normal files on a Linux system.
///
/// The point is that the chunks can be extracted from the tarball,
/// stored separately, and instead be indexed. In such a scenario, we
/// call the resulting CaFormat file a `.caidx`, or a `.caibx` if it
/// only comprises a single file.
///
/// Individual chunks are stored as `.cacnk` files.
///
/// ## This module
///
/// This module parses CaFormat files as described above.
///
/// ### Implemented
/// - `.caidx` parsing
///
/// ### Todo
/// - More generic CaFormat parsing
/// - Better error handling
///
use std::convert::TryFrom;

use nom::bytes::complete::{tag, take};
use nom::multi::many_till;
use nom::number::complete::le_u64;
use nom::sequence::tuple;
use nom::IResult;
use snafu::Snafu;

/// Returned whenever we encounter an error while parsing a CaFormat
/// file.
#[derive(Debug, Snafu)]
pub enum CaParseError {
    /// This error is returned when we encounter a general error with
    /// the file format - this should only occur when the file is
    /// corrupted and we can't handle it properly.
    #[snafu(display("There was an issue with the file format"))]
    FileFormatError,
    /// This error is returned when the header specifies an
    /// unimplemented CaFormat type. Currently only the types
    /// necessary for CA_FORMAT_INDEX are implemented.
    #[snafu(display("Unimplemented CaFormat type"))]
    UnimplementedType,
    /// This error is returned when the header specifies an invalid
    /// CaFormat type. This should only occur on corrupted files or
    /// with extensions we don't recognize.
    #[snafu(display("Invalid CaFormat type"))]
    InvalidType,
    /// This error is returned when the header specifies an
    /// unimplemented feature flag. Currently, no feature flags are
    /// implemented.
    #[snafu(display("Unimplemented feature flag"))]
    UnimplementedFeatureFlag,
    /// This error is returned when the header specifies a feature
    /// flag that we do not recognize. This should only occur on
    /// corrupted files or with extensions we don't recognize.
    #[snafu(display("Invalid feature flag"))]
    InvalidFeatureFlag,
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for CaParseError {
    fn from(_error: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Self {
        // TODO: Better error handling.
        Self::FileFormatError
    }
}

/// A `.caidx` file.
#[derive(Debug)]
pub struct CaIndex {
    /// The header of the file
    header: CaFormatHeader,
    /// Feature flags set on the file
    flags: Vec<CaFeatureFlag>,
    /// The minimum chunk size
    chunk_size_min: u64,
    /// The average chunk size
    chunk_size_avg: u64,
    /// The maximum chunk size
    chunk_size_max: u64,
    /// The table that lists the chunk hashes
    table: CaFormatTable,
}

impl CaIndex {
    /// Parse a `.caidx` file.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::fs::read;
    ///
    /// let file = read(opt.index)?;
    /// let index = CaIndex::parse(&file)?;
    ///
    /// println!("{:?}", index);
    /// ```
    pub fn parse(input: &[u8]) -> Result<Self, CaParseError> {
        let (input, header) = CaFormatHeader::parse(input)?;
        let (input, (flags, chunk_size_min, chunk_size_avg, chunk_size_max)) =
            tuple((CaFeatureFlag::parse, le_u64, le_u64, le_u64))(input)?;
        let (_input, table) = CaFormatTable::parse(input)?;

        Ok(Self {
            header,
            flags,
            chunk_size_min,
            chunk_size_avg,
            chunk_size_max,
            table,
        })
    }

    /// # Examples
    /// ```
    /// let file = read("examples/minimal.caidx")?;
    /// let index = CaIndex::parse(&file)?;
    /// assert_eq!(index.list_chunks(), vec![]);
    /// ```
    ///
    pub fn list_chunks(&self) -> Vec<String> {
        self.table
            .items
            .iter()
            .map(CaFormatTableItem::get_sha)
            .collect()
    }
}

/// The set of valid CaFormat data types.
///
/// CaFormat files consist of many sub-components that are required to
/// build up the original file tree. In the simplest case, this is a
/// `.caidx` file, which contains a table of chunks, but chunks will
/// contain file information.
///
/// ### Todo
/// - Implement types required for non-`.caidx` files.
///
#[derive(Debug)]
enum CaFormat {
    /// An index file - contains an index of chunks
    Index,
    /// A table - lists chunk hashes
    Table,
    /// The end of a table
    TableTailMarker,
}

impl TryFrom<u64> for CaFormat {
    type Error = CaParseError;

    /// Determine a CaFormat type from its bit sequence.
    ///
    /// # Errors
    ///
    /// This will return:
    /// - CaParseError::UnimplementedType - if the type exists, but is not implemented.
    /// - CaParseError::InvalidType - If the type is not defined, or only in an unknown extension.
    ///
    fn try_from(field: u64) -> Result<Self, CaParseError> {
        match field {
            0x9682_4d9c_7b12_9ff9 => Ok(Self::Index),
            0xe75b_9e11_2f17_417d => Ok(Self::Table),
            0x4b4f_050e_5549_ecd1 => Ok(Self::TableTailMarker),
            0x1396_fabc_ea5b_bb51   // Entry
                | 0xf453_131a_aeea_ccb3 // User
                | 0x25eb_6ac9_6939_6a52 // Group
                | 0xb815_7091_f80b_c486 // xattr
                | 0x297d_c88b_2ef1_2faf // ACL user
                | 0x36f2_acb5_6cb3_dd0b // ACL group
                | 0x2304_7110_441f_38f3 // ACL group object
                | 0xfe3e_eda6_823c_8cd0 // ACL default
                | 0xbdf0_3df9_bd01_0a91 // ACL default user
                | 0xa0cb_1168_782d_1f51 // ACL default group
                | 0xf726_7db0_afed_0629 // fcaps
                | 0x161b_af2d_8772_a72b // Quota projid
                | 0x46fa_f060_2fd2_6c59 // selinux
                | 0x664a_6fb6_830e_0d6c // symlink
                | 0xac3d_ace3_69df_e643 // device
                | 0x8b9e_1d93_d6dc_ffc9 // payload
                | 0x6dbb_6ebc_b316_1f0b // filename
                | 0xdfd3_5c5e_8327_c403 // goodbye
                => Err(CaParseError::UnimplementedType),
            _ => Err(CaParseError::InvalidType),
        }
    }
}

/// CaFormat files have headers which specify what type of file they
/// are.
#[derive(Debug)]
struct CaFormatHeader {
    /// The size of the header, first 8 bytes of the file, little endian
    size: u64,
    /// The type of the file
    format: CaFormat,
}

impl CaFormatHeader {
    /// Parse a CaFormatHeader from a byte stream
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (size, format)) = tuple((le_u64, le_u64))(input)?;

        Ok((
            input,
            Self {
                size,
                format: CaFormat::try_from(format)
                    .expect("I would handle these errors, but nom doesn't let me"),
            },
        ))
    }
}

/// A feature flag - these are set at file creation time, and enable
/// certain features. Files with certain features set must be handled
/// differently.
#[derive(Debug)]
enum CaFeatureFlag {}

impl CaFeatureFlag {
    /// Parse a set of feature flags from their bit mask
    fn parse(input: &[u8]) -> IResult<&[u8], Vec<Self>> {
        let (input, _flag_bytes) = le_u64(input)?;
        Ok((input, vec![]))
    }
}

impl TryFrom<u64> for CaFeatureFlag {
    type Error = CaParseError;

    fn try_from(_field: u64) -> Result<Self, CaParseError> {
        Err(CaParseError::UnimplementedFeatureFlag)
    }
}

/// An index table entry - this contains the chunk hash.
#[derive(Debug)]
struct CaFormatTableItem {
    offset: u64,
    chunk: [u8; 32],
}

impl CaFormatTableItem {
    /// Parse a format table item from its byte stream.
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (offset, chunk_data)) = tuple((le_u64, take(32usize)))(input)?;

        // Copy over the slice to a sized array
        let mut chunk: [u8; 32] = Default::default();
        chunk.copy_from_slice(chunk_data);

        Ok((input, Self { offset, chunk }))
    }

    /// Get the hash of the chunk in string form.
    fn get_sha(&self) -> String {
        fn byte_to_hex(byte: u8) -> Vec<u8> {
            // Hex char lookup table
            let chars: [u8; 16] = [
                b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd',
                b'e', b'f',
            ];

            let upper = byte >> 4;
            let lower = byte & 0xF;
            vec![chars[upper as usize], chars[lower as usize]]
        }

        let chars: Vec<u8> = self
            .chunk
            .iter()
            .flat_map(|byte| byte_to_hex(*byte))
            .collect();

        String::from_utf8(chars).expect("We can only have valid utf-8 bytes in this string")
    }
}

/// An index table - contains a list of chunk hashes
#[derive(Debug)]
struct CaFormatTable {
    /// The header of the table
    header: CaFormatHeader,
    /// The list of chunks
    items: Vec<CaFormatTableItem>,
}

impl CaFormatTable {
    /// Parse a table from its byte stream
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = CaFormatHeader::parse(input)?;

        let (input, (items, _tail)) =
            many_till(CaFormatTableItem::parse, CaFormatTableTail::parse)(input)?;

        Ok((input, Self { header, items }))
    }
}

/// The end of an index table. This contains no information, but marks
/// the end of a table so that we know it has finished.
#[derive(Debug)]
struct CaFormatTableTail {
    index_offset: u64,
    size: u64,
}

impl CaFormatTableTail {
    /// Parse a tail from its byte stream
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        // We throw out the space where we would place the header and
        // flags so that the tail is the same size as the items.
        let (input, _) = tag(0u128.to_le_bytes())(input)?;

        let (input, (index_offset, size, _)) =
            tuple((le_u64, le_u64, tag(0x4b4f_050e_5549_ecd1u64.to_le_bytes())))(input)?;

        Ok((input, Self { index_offset, size }))
    }
}
