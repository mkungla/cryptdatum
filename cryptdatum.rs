// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

use std::ops::BitAnd;
use std::io::Read;
use std::convert::TryInto;

/// Current version of the Cryptdatum format
///
/// This constant defines the current version of the Cryptdatum format.
/// Implementations of the Cryptdatum library should set this value to 1
/// to indicate support for the current version of the format.
pub const VERSION: u16 = 1;


/// Minimum version of the Cryptdatum format
///
/// This constant defines the minimum version of the Cryptdatum format
/// what is supported by this library.
pub const MIN_VERSION: u16 = 1;

/// Size of a Cryptdatum header in bytes
///
/// This constant defines the size of a Cryptdatum header in bytes. It can be
/// used by implementations of the Cryptdatum library to allocate sufficient
/// memory for a Cryptdatum header, or to check the size of a Cryptdatum header
/// that has been read from a stream.
pub const HEADER_SIZE: usize = 64;

/// Magic number for Cryptdatum headers
///
/// This constant defines the magic number that is used to identify Cryptdatum
/// headers. If the magic number field in a Cryptdatum header does not match
/// this value, the header should be considered invalid.
pub const MAGIC: [u8; 4] = [0xA7, 0xF6, 0xE5, 0xD4];

/// Delimiter for Cryptdatum headers
///
/// This constant defines the delimiter that is used to mark the end of a
/// Cryptdatum header. If the delimiter field in a Cryptdatum header does not
/// match this value, the header should be considered invalid.
pub const DELIMITER: [u8; 2] = [0xA6, 0xE5];

const EMPTY: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

// MAGIC_DATE is the minimum possible value for Timestamp header field.
const MAGIC_DATE: u64 = 1652155382000000001;

/// Structure representing a Cryptdatum header
///
/// This structure represents a Cryptdatum header, which contains metadata about
/// the data payload of a Cryptdatum datum. It is used to identify the data as
/// a Cryptdatum datum, as well as to indicate the features that are used by
/// the datum.
#[repr(C)]
pub struct Header {
  pub version: u16, // Indicates the version of the Cryptdatu
  pub flags: u64, // Cryptdatum format features flags to indicate which Cryptdatum features are used.
  pub timestamp: u64, // Unix timestamp in nanoseconds
  pub opc: u32, // Unique operation ID
  pub chunk_size: u16, // Size of the chunks if data is chunked.
  pub network_id: u32, // Identifes the source network of the payload. When 0 no network is specified.
  pub size: u64, // Total size of the data payload.
  pub checksum: u64, // CRC64 checksum
  pub compression: u16, // compression algorithm
  pub encryption: u16, // encryption algorithm
  pub signature_type: u16, // signature type
  pub signature_size: u16, // signature size
  pub metadata_spec: u16, // metadata spec
  pub metadata_size: u32, // metadata size
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u64)]
pub enum DatumFlag {
  DatumInvalid = 1 << 0,
  DatumDraft = 1 << 1,
  DatumEmpty = 1 << 2,
  DatumChecksum = 1 << 3,
  DatumOPC = 1 << 4,
  DatumCompressed = 1 << 5,
  DatumEncrypted = 1 << 6,
  DatumExtractable = 1 << 7,
  DatumSigned = 1 << 8,
  DatumChunked = 1 << 9,
  DatumMetadata = 1 << 10,
  DatumCompromised = 1 << 11,
  DatumBigEndian = 1 << 12,
  DatumNetwork = 1 << 13,
}

impl BitAnd<DatumFlag> for u64 {
  type Output = bool;

  fn bitand(self, rhs: DatumFlag) -> bool {
    self & (rhs as u64) != 0
  }
}

impl BitAnd for DatumFlag {
  type Output = bool;

  fn bitand(self, rhs: DatumFlag) -> bool {
    self as u64 & (rhs as u64) != 0
  }
}


impl From<u64> for DatumFlag {
  fn from(value: u64) -> Self {
    match value {
      1 => DatumFlag::DatumInvalid,
      2 => DatumFlag::DatumDraft,
      4 => DatumFlag::DatumEmpty,
      8 => DatumFlag::DatumChecksum,
      16 => DatumFlag::DatumOPC,
      32 => DatumFlag::DatumCompressed,
      64 => DatumFlag::DatumEncrypted,
      128 => DatumFlag::DatumExtractable,
      256 => DatumFlag::DatumSigned,
      512 => DatumFlag::DatumChunked,
      1024 => DatumFlag::DatumMetadata,
      2048 => DatumFlag::DatumCompromised,
      4096 => DatumFlag::DatumBigEndian,
      8192 => DatumFlag::DatumNetwork,
      _ => todo!(),
    }
  }
}

#[derive(Debug)]
pub enum ErrorType {
  Io(std::io::Error),
  Regular(ErrorKind),
  Custom(String)
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
  IO,
  EOF,
  UnsupportedFormat,
  InvalidHeader,
}

impl ErrorKind {
  pub fn as_str(&self) -> &str {
    match *self {
      ErrorKind::IO => "cryptdatum I/O error",
      ErrorKind::EOF => "cryptdatum EOF",
      ErrorKind::UnsupportedFormat => "cryptdatum unsupported format",
      ErrorKind::InvalidHeader => "cryptdatum invalid header",
    }
  }
}

impl std::fmt::Display for ErrorType {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    match *self {
      ErrorType::Io(ref err) => err.fmt(f),
      ErrorType::Regular(ref err) => write!(f, "cryptdatum error: {:?}", err),
      ErrorType::Custom(ref err) => write!(f, "cryptdatum error: {:?}", err),
    }
  }
}

impl From<std::io::Error> for ErrorType {
  fn from(err: std::io::Error) -> ErrorType {
    ErrorType::Io(err)
  }
}
impl From<std::str::Utf8Error> for ErrorType {
  fn from(err: std::str::Utf8Error) -> ErrorType {
    ErrorType::Custom(err.to_string())
  }
}

pub type Result<T> = std::result::Result<T, ErrorType>;

/// Has Header
///
/// This function checks if the provided data contains a Cryptdatum header.
/// It looks for specific header fields and checks their alignment,
/// but does not perform any further validations. If the data is likely to be Cryptdatum,
/// the function returns true. Otherwise, it returns false. If you want to
/// verify the integrity of the header as well, use the has_valid_header function
/// or use decode_header and perform the validation yourself.
///
/// The data argument should contain the entire Cryptdatum data, as a byte slice.
/// The function will read the first HeaderSize bytes of the slice to
/// check for the presence of a header.
///
/// # Parameters
///
/// * `data`: A slice containing the Cryptdatum header to verify
///
/// # Returns
///
/// `true` if the header is valid, `false` if it is invalid
pub fn has_header(data: &[u8]) -> bool {
  // Verify that the data is at least the size of the header
  if data.len() < HEADER_SIZE {
    return false;
  }
  // check magic and delimiter
  return data[..4].eq(&MAGIC) && data[62..64].eq(&DELIMITER);
}

pub fn has_valid_header(data: &[u8]) -> bool {

  if !has_header(data) {
    return false;
  }

  // check version is >= 1
  let version = u16::from_le_bytes([data[4], data[5]]);
  if version < VERSION {
      return false;
  }


  let flags = u64::from_le_bytes([
    data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13],
  ]);

  // break here if DatumDraft or DatumCompromised is set
  if flags & DatumFlag::DatumCompromised  {
    return false;
  }
  if flags & DatumFlag::DatumDraft {
    return true;
  }

  // It it was not a draft it must have timestamp
  if u64::from_le_bytes([
    data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21],
  ]) < MAGIC_DATE {
      return false;
  }

  // DatumOPC is set then counter value must be gte 1
  let counter = u32::from_le_bytes([data[22], data[23], data[24], data[25]]);
  if flags & DatumFlag::DatumOPC && counter == 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumOPC) && counter > 0 {
    return false;
  }

  // DatumChunked is set then chunk size value must be gte 1
  let chunksize = u16::from_le_bytes([data[26], data[27]]);
  if flags & DatumFlag::DatumChunked && chunksize == 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumChunked) && chunksize > 0 {
    return false;
  }

  // DatumNetwork is set then network id value must be gte 1
  let networ_id = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
  if flags & DatumFlag::DatumNetwork && networ_id == 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumNetwork) && networ_id > 0 {
    return false;
  }

  // DatumEmpty is set then size value must be 0
	// DatumEmpty is not set then size value must be gte 1
  let size = u64::from_le_bytes([data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39]]);
  if flags & DatumFlag::DatumEmpty && size > 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumEmpty) && size == 0 {
    return false;
  }

  // DatumChecksum
  if flags & DatumFlag::DatumChecksum  && data[40..48].eq(&EMPTY) {
    return false;
  }
  if !(flags & DatumFlag::DatumChecksum) && !data[40..48].eq(&EMPTY) {
    return false;
  }

  // DatumCompressed
  let comprssion = u16::from_le_bytes([data[48], data[49]]);
  if flags & DatumFlag::DatumCompressed && comprssion == 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumCompressed) && comprssion > 0 {
    return false;
  }
  // DatumEncrypted
  let comprssion = u16::from_le_bytes([data[50], data[51]]);
  if flags & DatumFlag::DatumEncrypted && comprssion == 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumEncrypted) && comprssion > 0 {
    return false;
  }
  // DatumSigned
  let signature_type = u16::from_le_bytes([data[52], data[53]]);
  let signature_size = u16::from_le_bytes([data[54], data[55]]);
  if flags & DatumFlag::DatumSigned && signature_type == 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumSigned) && (signature_type > 0 || signature_size > 0) {
    return false;
  }

  // DatumMetadata
  let metadata_spec = u16::from_le_bytes([data[56], data[57]]);
  let metadata_size = u32::from_le_bytes([data[58], data[59], data[60], data[61]]);
  if flags & DatumFlag::DatumMetadata && metadata_spec == 0 {
    return false;
  }
  if !(flags & DatumFlag::DatumMetadata) && (metadata_spec > 0 || metadata_size > 0) {
    return false;
  }

  // If all checks pass, return true
  true
}

pub fn decode_header<R: Read>(reader: &mut R) -> Result<Header> {
  let mut header_buf = [0u8; HEADER_SIZE];
  let bytes_read = reader.read(&mut header_buf)?;
  if bytes_read < HEADER_SIZE {
    return Err(ErrorType::Regular(ErrorKind::IO))
  }

  if !has_header(&header_buf) {
    return Err(ErrorType::Regular(ErrorKind::UnsupportedFormat));
  }
  if !has_valid_header(&header_buf) {
    return Err(ErrorType::Regular(ErrorKind::InvalidHeader));
  }



  let header: Header = Header{
    version: u16::from_le_bytes(header_buf[4..6].try_into().unwrap()),
    flags: u64::from_le_bytes(header_buf[6..14].try_into().unwrap()),
    timestamp: u64::from_le_bytes(header_buf[14..22].try_into().unwrap()),
    opc: u32::from_le_bytes(header_buf[22..26].try_into().unwrap()),
    chunk_size: u16::from_le_bytes(header_buf[26..28].try_into().unwrap()),
    network_id: u32::from_le_bytes(header_buf[28..32].try_into().unwrap()),
    size: u64::from_le_bytes(header_buf[32..40].try_into().unwrap()),
    checksum: u64::from_le_bytes(header_buf[40..48].try_into().unwrap()),
    compression: u16::from_le_bytes(header_buf[48..50].try_into().unwrap()),
    encryption: u16::from_le_bytes(header_buf[50..52].try_into().unwrap()),
    signature_type: u16::from_le_bytes(header_buf[52..54].try_into().unwrap()),
    signature_size: u16::from_le_bytes(header_buf[54..56].try_into().unwrap()),
    metadata_spec: u16::from_le_bytes(header_buf[56..58].try_into().unwrap()),
    metadata_size: u32::from_le_bytes(header_buf[58..62].try_into().unwrap()),
  };

  Ok(header)
}

pub mod timestamp {
  //! The `timestamp` module provides functions for formatting and parsing
  //! UTC nanoseconds timestamps as strings.

  const MAX_BUF_SIZE: usize = 32;

  /// Formats a UTC nanoseconds timestamp as a string using the given format string.
  ///
  /// The format string can include the following formatting codes:
  ///
  /// - `%Y`: the year as a 4-digit integer (e.g. 2023)
  /// - `%m`: the month as a 2-digit integer (e.g. 01, 12)
  /// - `%d`: the day as a 2-digit integer (e.g. 01, 31)
  /// - `%H`: the hour as a 2-digit integer (e.g. 00, 23)
  /// - `%M`: the minute as a 2-digit integer (e.g. 00, 59)
  /// - `%S`: the second as a 2-digit integer (e.g. 00, 59)
  /// - `%n`: the nanoseconds as a 9-digit integer (e.g. 000000001, 999999999)
  ///
  /// Any other characters in the format string are written to the output string as-is.
  ///
  /// # Examples
  ///
  /// ```
  /// use cryptdatum::timestamp::format;
  ///
  /// let ts = 1234567890;
  /// let fmt = "%Y-%m-%dT%H:%M:%S%nZ";
  /// let s = format(fmt, ts);
  /// assert_eq!(s, "1970-01-01T00:00:01.234567890Z");
  /// ```
  pub fn format(fmt: &str, ts: u64) -> String {
    let (secs, nsec) = div_rem(ts, 1_000_000_000);
    let days: u64 = secs / 86400;
    let (year, month, day) = get_date(days);
    
    let sec: u8 = (secs % 60) as u8;
    let min: u8 = ((secs / 60) % 60) as u8;
    let hour: u8 = ((secs / 3600) % 24) as u8;

    let mut buf = [0; MAX_BUF_SIZE];
    let mut i = 0; // layout cursor
    let mut j = 0; // buf cursor
    let mut f: bool = false;

    for c in fmt.chars() {
      if j >= MAX_BUF_SIZE {
        break;
      }
      match c {
        '%' => {
          i += 1;
          let n = fmt[i..].chars().next().unwrap();
          f = true;
          match n {
            'Y' => { j = write_str(j, &mut buf, format!("{:04}", year)); },
            'm' => { j = write_str(j, &mut buf, format!("{:02}", month)); },
            'd' => { j = write_str(j, &mut buf, format!("{:02}", day)); },
            'H' => { j = write_str(j, &mut buf, format!("{:02}", hour)); },
            'M' => { j = write_str(j, &mut buf, format!("{:02}", min)); },
            'S' => { j = write_str(j, &mut buf, format!("{:02}", sec)); },
            'n' => { j = write_str(j, &mut buf, format!(".{:09}", nsec)); },
            _ => {
              buf[j] = n as u8;
              j += 1;
            }
          }
        },
        _ => {
          i += 1;
          if !f {
            buf[j] = c as u8;
            j += 1;
          }
          f = false;
        },
      }
    }

    let res = unsafe {
      String::from_utf8_unchecked((&buf[..j]).to_vec())
    };
    res
  }

  /// Writes the given string to the given byte array starting at the given index.
  ///
  /// # Returns
  ///
  /// The index after the last written character.
  ///
  /// # Panics
  ///
  /// This function panics if the string is too long to fit in the byte array.
  fn write_str(bufc: usize, buf: &mut [u8], s: String) -> usize {
    // silently ignore
    if bufc >= MAX_BUF_SIZE {
      return bufc;
    }
    let mut j = bufc;
    for c in s.chars() {
      buf[j] = c as u8;
      j += 1;
    }
    j
  }

  /// Calculates the quotient and remainder of the given number when divided by the given divisor.
  fn div_rem(x: u64, y: u64) -> (u64, u64) {
    (x / y, x % y)
  }

  /// Returns whether the given year is a leap year.
  fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
  }

  /// Calculates the year, month, and day from the given number of days since the Unix epoch.
  fn get_date(days: u64) -> (u64, u8, u8) {
    let mut year: u64 = 1970;
    let mut month: u8 = 1;
    let mut day: u8 = 1;
    let mut ds: u64 = days;
    while ds >= 365 {
      if is_leap_year(year) {
        if ds >= 366 {
          ds -= 366;
          year += 1;
        } else {
          break
        }
      } else {
        ds -= 365;
        year += 1;
      }
    }
    while ds >= 28 {
      let dim = days_in_month(year, month);
      if ds >= dim {
        ds -= dim;
        month += 1;
      } else {
        break;
      }
    }
    day += ds as u8;
    (year, month, day)
  }

  /// Calculates the number of days in a given month and year.
  ///
  /// # Panics
  ///
  /// This function panics if an invalid month value is passed to it.
  fn days_in_month(year: u64, month: u8) -> u64 {
    match month {
      1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
      4 | 6 | 9 | 11 => 30,
      2 => if is_leap_year(year) { 29 } else { 28 },
      _ => panic!("Invalid month: {}", month),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn set_header_version(slice: &mut [u8], version: u16) {
    if slice.len() < 10 {
      return;
    }
    slice[4] = version as u8;
    slice[5] = (version >> 8) as u8;
  }

  fn set_header_date(slice: &mut [u8], nsec: u64) {
    if slice.len() < 25 {
      return;
    }
    slice[14] = nsec as u8;
    slice[15] = (nsec >> 8) as u8;
    slice[16] = (nsec >> 16) as u8;
    slice[17] = (nsec >> 24) as u8;
    slice[18] = (nsec >> 32) as u8;
    slice[19] = (nsec >> 40) as u8;
    slice[20] = (nsec >> 48) as u8;
    slice[21] = (nsec >> 56) as u8;
  }

  fn set_header_flag(slice: &mut [u8], flag: u64) {
    if slice.len() < 14 {
      return;
    }
    slice[6] = flag as u8;
    slice[7] = (flag >> 8) as u8;
    slice[8] = (flag >> 16) as u8;
    slice[9] = (flag >> 24) as u8;
    slice[10] = (flag >> 32) as u8;
    slice[11] = (flag >> 40) as u8;
    slice[12] = (flag >> 48) as u8;
    slice[13] = (flag >> 56) as u8;
  }

  #[test]
  // Test too small data
  fn has_valid_header_too_small_data() {
    let data = [0; HEADER_SIZE - 1];
    assert!(!has_valid_header(&data));
  }

  #[test]
  fn has_valid_header_magic() {
    // Test valid magic
    let mut data = [0; HEADER_SIZE];
    data[0..4].copy_from_slice(&MAGIC);
    set_header_version(&mut data, VERSION);
    set_header_date(&mut data, MAGIC_DATE);
    set_header_flag(&mut data, 4);


    data[62..64].copy_from_slice(&DELIMITER);
    assert!(has_valid_header(&data));

    // Test invalid magic
    let mut data = [0; HEADER_SIZE];
    data[0] = 0x00;
    set_header_version(&mut data, VERSION);
    data[62..64].copy_from_slice(&DELIMITER);
    assert!(!has_valid_header(&data));
  }

  #[test]
  // Test invalid delimiter
  fn has_valid_header_delimiter() {
    let mut data = [0; HEADER_SIZE];
    data[0..4].copy_from_slice(&MAGIC);
    set_header_version(&mut data, VERSION);
    data[62] = 0x00;
    assert!(!has_valid_header(&data));
  }
}
