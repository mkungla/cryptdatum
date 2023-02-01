// Copyright 2023 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

const std = @import("std");

// Version is the current version of the Cryptdatum format.
// Implementations of the Cryptdatum library should set the version field in
// Cryptdatum headers to this value.
pub const Version: u16 = 1;

// MinVersion is the minimum supported version of the Cryptdatum format.
// If the version field in a Cryptdatum header is lower than this value, the
// header should be considered invalid.
pub const MinVersion: u16 = 1;

// HeaderSize is the size of a Cryptdatum header in bytes. It can be used by
// implementations of the Cryptdatum library to allocate sufficient memory for
// a Cryptdatum header, or to check the size of a Cryptdatum header that has
// been read from a stream.
pub const HeaderSize: usize = 64;

// MagicDate is date which datum can not be older. Therefore it is the minimum
// value possible for Header.Timestamp
pub const MagicDate: u64 = 1652155382000000001;


// Magic is the magic number used to identify Cryptdatum headers. If the magic
// number field in a Cryptdatum header does not match this value, the header
// should be considered invalid.
pub const Magic = [4]u8{0xA7, 0xF6, 0xE5, 0xD4};

// Delimiter is the delimiter used to mark the end of a Cryptdatum header. If
// the delimiter field in a Cryptdatum header does not match this value, the
// header should be considered invalid.
pub const Delimiter = [2]u8{0xA6, 0xE5};

pub const DatumFlag = enum(u64) {
  Invalid = 1 << 0,
  Draft = 1 << 1,
  Empty = 1 << 2,
  Checksum = 1 << 3,
  OPC = 1 << 4,
  Compressed = 1 << 5,
  Encrypted = 1 << 6,
  Extractable = 1 << 7,
  Signed = 1 << 8,
  Chunked = 1 << 9,
  Metadata = 1 << 10,
  Compromised = 1 << 11,
  BigEndian = 1 << 12,
  Network = 1 << 13,

  pub fn isSet(self: DatumFlag, flags: u64) bool {
    return (flags & @enumToInt(self) != 0);
  } 
};

const empty = [8]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const empty2 = [2]u8{0x00, 0x00};
const empty4 = [4]u8{0x00, 0x00, 0x00, 0x00};

const Error = error{
    IO, // i/o
    EOF, // EOF
    UnsupportedFormat, // unsupported format
    InvalidHeader, // invalid header
};

pub const Header = struct {
  // version indicates the version of the Cryptdatum format.
  version: u16 = 0,

  // Cryptdatum format features flags to indicate which Cryptdatum features are
  // used by that datum e.g whether the data is encrypted, compressed, or has
  // a checksum. has operation counter set is signed etc.
  flags: u64 = 0,

  // timestamp is Unix timestamp in nanoseconds, indicating the time when the data was created.
  timestamp: u64 = 0,

  // opc Operation Counter - Unique operation ID for the data.
  opc: u32 = 0,

  // chunk_size in kilobytes if DatumChunked is enabled
  chunk_size: u16 = 0,

  // network_id identifes the source network of the payload. When 0 no network is specified.
  network_id: u32 = 0,

  // Total size of the data, including the header and optional signature.
  size: u64 = 0,

  // CRC64 checksum for verifying the integrity of the data.
  checksum: u64 = 0,

  // Compression indicates the compression algorithm used, if any.
  compression: u16 = 0,

  // Encryption indicates the encryption algorithm used, if any.
  encryption: u16 = 0,

  // SignatureType indicates the signature type helping implementations to
  // identify how the signature should be verified.
  signature_type: u16 = 0,

  // SignatureSize indicates the size of the signature, if any.
  signature_size: u16 = 0,

  // MetadataSpec is identifer which indentifies metadata format used if any is used.
  metadata_spec: u16 = 0,

  // MetadataSize
  metadata_size: u32 = 0,
};

// hasHeader checks if the provided data contains a Cryptdatum header. It looks for specific header
// fields and checks their alignment, but does not perform any further validations. If the data
// is likely to be Cryptdatum, the function returns true. Otherwise, it returns false.
// If you want to verify the integrity of the header as well, use the hasValidHeader function
// or use DecodeHeader and perform the validation yourself.
//
// The data argument should contain the entire Cryptdatum data, as a byte slice. The function will
// read the first HeaderSize bytes of the slice to check for the presence of a header.
pub fn hasHeader(data: []const u8) bool {
  if (data.len < HeaderSize) {
    return false;
  }
  return std.mem.eql(u8, data[0..4], Magic[0..4]) and std.mem.eql(u8, data[62..HeaderSize], Delimiter[0..2]);
}

// hasValidHeader checks if the provided data contains a valid Cryptdatum header. It verifies the
// integrity of the header by checking the magic number, delimiter, and other fields. If the header
// is valid, the function returns true. Otherwise, it returns false.
//
// The data argument can contain any data as a byte slice, but should be at least HeaderSize in length
// and start with the header. The function will read the first HeaderSize bytes of the slice to
// validate the header. If the data slice is smaller than HeaderSize bytes, the function will
// return false, as the header is considered incomplete.
//
// It is important to note that this function only validates header usage it does not peek the payload.
// E.g HasValidHeader does not check is signature or metadata present when these flag bits are set.
// However it may perform additional header validations depending the flag bits is corresonding
// header field set which is required by flag bit. See Cryptdatum Specification for more details.
pub fn hasValidHeader(data: []const u8) bool {
  if (!hasHeader(data)) {
    return false;
  }
 
  // check version is >= 1
  if (std.mem.readIntLittle(u16, data[4..6]) < 1) {
    return false;
  }

  const flags: u64 = std.mem.readIntLittle(u64, data[6..14]);

  // retuirn fast if data is compromized or draft
  if (DatumFlag.Compromised.isSet(flags)) {
    return false;
  }
  if (DatumFlag.Draft.isSet(flags)) {
    return false;
  }

  // If it was not a draft it must have timestamp
  if (std.mem.readIntLittle(u64, data[14..22]) < MagicDate) {
    return false;
  }

  // DatumFlag.OPC is set then counter value must be gte 1
  if ((DatumFlag.OPC.isSet(flags) and std.mem.eql(u8, data[22..26], empty4[0..4])) or (!DatumFlag.OPC.isSet(flags) and !std.mem.eql(u8, data[22..26], empty4[0..4]))) {
    return false;
  }

  // DatumFlag.Chunked is set then chunk size value must be gte 1
  if ((DatumFlag.Chunked.isSet(flags) and std.mem.eql(u8, data[26..28], empty2[0..2])) or 
    (!DatumFlag.Chunked.isSet(flags) and !std.mem.eql(u8, data[26..28], empty2[0..2]))) {
    return false;
  }

  // DatumFlag.Network is set then network id value must be gte 1
  if ((DatumFlag.Network.isSet(flags) and std.mem.eql(u8, data[28..32], empty4[0..4])) or (!DatumFlag.Network.isSet(flags) and !std.mem.eql(u8, data[28..32], empty4[0..4]))) {
    return false;
  }

  // DatumFlag.Empty is set then size value must be 0
  // DatumFlag.Empty is not set then size value must be gte 1
  if ((DatumFlag.Empty.isSet(flags) and !std.mem.eql(u8, data[32..40], empty[0..8])) or 
      (!DatumFlag.Empty.isSet(flags) and std.mem.eql(u8, data[32..40], empty[0..8]))) {
    return false;
  }

  // DatumFlag.Checksum must be set when checsum is used and not set if Checksum field is not empty
  if (DatumFlag.Checksum.isSet(flags) and std.mem.eql(u8, data[40..48], empty[0..8])) {
    return false;
  }

  // DatumFlag.Compressed compression algorithm must be set
  if (DatumFlag.Compressed.isSet(flags) and std.mem.eql(u8, data[48..50], empty2[0..2])) {
    return false;
  }

  // DatumFlag.Encrypted encryption algorithm must be set
  if (DatumFlag.Encrypted.isSet(flags) and std.mem.eql(u8, data[50..52], empty2[0..2])) {
    return false;
  }

  // SIGNATURE TYPE and SIGNATURE SIZE
  if (DatumFlag.Signed.isSet(flags) and std.mem.eql(u8, data[52..54], empty2[0..2])) {
    return false;
  }
  
  if (!DatumFlag.Signed.isSet(flags) and (!std.mem.eql(u8, data[52..54], empty2[0..2]) or !std.mem.eql(u8, data[54..56], empty2[0..2]))) {
    return false;
  }

  // MEATADATA SPEC  and MEATADATA SIZE
  if (DatumFlag.Metadata.isSet(flags) and std.mem.eql(u8, data[56..58], empty2[0..2])) {
    return false;
  }
  if (!DatumFlag.Metadata.isSet(flags) and (!std.mem.eql(u8, data[56..58], empty2[0..2]) or !std.mem.eql(u8, data[58..62], empty4[0..4]))) {
    return false;
  }
  
  return true;
}

// decodeHeader returns the header information of a Cryptdatum data without decoding the entire data.
// The header information is read from the provided reader, which should contain the Cryptdatum data.
// If the header is invalid or an error occurs while reading, an error is returned.
//
// Caller is responsible to close the source e.g FILE
pub fn decodeHeader(data: []const u8) Error!Header {

  if (data.len < HeaderSize) return Error.EOF;
  if (!hasHeader(data)) return Error.UnsupportedFormat;
  if (!hasValidHeader(data)) return Error.InvalidHeader;

  const header = Header{
    .version = std.mem.readIntLittle(u16, data[4..6]),
    .flags = std.mem.readIntLittle(u64, data[6..14]),
    .timestamp = std.mem.readIntLittle(u64, data[14..22]),
    .opc = std.mem.readIntLittle(u32, data[22..26]),
    .chunk_size = std.mem.readIntLittle(u16, data[26..28]),
    .network_id = std.mem.readIntLittle(u32, data[28..32]),
    .size = std.mem.readIntLittle(u64, data[32..40]),
    .checksum = std.mem.readIntLittle(u64, data[40..48]),
    .compression = std.mem.readIntLittle(u16, data[48..50]),
    .encryption = std.mem.readIntLittle(u16, data[50..52]),
    .signature_type = std.mem.readIntLittle(u16, data[52..54]),
    .signature_size = std.mem.readIntLittle(u16, data[54..56]),
    .metadata_spec = std.mem.readIntLittle(u16, data[56..58]),
    .metadata_size = std.mem.readIntLittle(u32, data[58..62]),
  };
  return header;
}

pub const TimeFormatter = struct {
  buf: []u8,
  allocator: std.mem.Allocator,
  timestamp: u64 = 0,
  
  const MaxBufSize: u16 = 1280;

  pub const FormatError = error{
    OutOfMemory,
    InvalidRange,
  };

  pub fn init(allocator: std.mem.Allocator, ts: u64) !TimeFormatter {
    return .{
      .buf = allocator.alloc(u8, MaxBufSize) catch {
        return FormatError.OutOfMemory;
      },
      .allocator = allocator,
      .timestamp = ts,
    };
  }

  pub fn format(self: *TimeFormatter, fmt: []const u8) ![]const u8 {
    const dr = divRem(self.timestamp, 1_000_000_000);
    const days: u64 = dr.sec / 86400;
    const date = get_date(days);

    const sec: u64 = (dr.sec % 60);
    const min: u64 = ((dr.sec / 60) % 60);
    const hour: u64 = ((dr.sec / 3600) % 24);

    var fmt_str = std.ArrayList(u8).init(self.allocator);
    defer fmt_str.deinit();
    var writer = fmt_str.writer();
    var j: usize = 0;
    var f: bool = false;
    for (fmt) |c, i| {
      if (j >= MaxBufSize) {
        break;
      }
      switch (c) {
        '%' => {
          var n = fmt[i+1];
          f = true;
          switch (n) {
            'Y' => try writer.print("{d:0>4}", .{date.year}),
            'm' => try writer.print("{d:0>2}", .{date.month}),
            'd' => try writer.print("{d:0>2}", .{date.day}),
            'H' => try writer.print("{d:0>2}", .{hour}),
            'M' => try writer.print("{d:0>2}", .{min}),
            'S' => try writer.print("{d:0>2}", .{sec}),
            'n' => try writer.print(".{d:0>9}", .{dr.nsec}),
            else => fmt_str.append(n) catch unreachable,
          }
        },
        else => {
          if (!f) {
            fmt_str.append(c) catch unreachable;
          }
          f = false;
        },
      }
    }
    
    const slice = try std.fmt.bufPrint(self.buf, "{s}", .{fmt_str.items});
    return slice;
  }

  pub fn deinit(self: *TimeFormatter) void {
    self.allocator.free(self.buf);
  }

    // Calculates the quotient and remainder of the given number when divided by the given divisor.
  fn divRem(x: u64, y: u64) struct { sec: u64, nsec: u64 } {
    return .{ .sec = x / y, .nsec = x % y };
  }

  fn get_date(days: u64) struct { year: u64, month: u8, day: u8 } {
    var year: u64 = 1970;
    var month: u8 = 1;
    var day: u8 = 1;

    var ds: u64 = days;
    while (ds >= 365) {
      if (is_leap_year(year)) {
        if (ds >= 366) {
          ds -= 366;
          year += 1;
        } else {
          break;
        }
      } else {
        ds -= 365;
        year += 1;
      }
    }
    while (ds >= 28) {
      var dim = days_in_month(year, month);
      if (ds >= dim) {
        ds -= dim;
        month += 1;
      } else {
        break;
      }
    }
    day += @truncate(u8, ds);
    return .{
      .year = year,
      .month = month,
      .day = day,
    };
  }

  fn is_leap_year(year: u64) bool {
    return (year % 4 == 0 and year % 100 != 0) or year % 400 == 0;
  }

  fn days_in_month(year: u64, month: u8) u8 {
    switch (month) {
      1, 3, 5, 7, 8, 10, 12 => return 31,
      4, 6, 9, 11 => return 30,
      2 => if (is_leap_year(year)) { return 29; } else { return 28; },
      else => {},
    }
    return 0;
  }
};

const expect = std.testing.expect;

fn minimal_valid_header() [64]u8 {
  return [64]u8{
    0xa7, 0xf6, 0xe5, 0xd4, // magic
    0x1, 0x0, // version: u16
    0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // flags: u64
    0x1, 0x1c, 0xdc, 0x1, 0x91, 0xa2, 0xed, 0x16, // timestamp: u64
    0x0, 0x0, 0x0, 0x0, // opc: u32
    0x0, 0x0, // chunk_size: u16
    0x0, 0x0, 0x0, 0x0, // network_id: u32,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // size: u64,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // checksum: u64,
    0x0, 0x0, // compression: u16,
    0x0, 0x0, // encryption: u16,
    0x0, 0x0, // signature_type: u16,
    0x0, 0x0, // signature_size: u16,
    0x0, 0x0, // metadata_spec: u16,
    0x0, 0x0, 0x0, 0x0, // metadata_size: u32,
    0xa6, 0xe5 // delimiter
  };
}

fn header_full_featured() [64]u8 {
  return [64]u8{
    0xa7, 0xf6, 0xe5, 0xd4, // magic
    0x1, 0x0, // version: u16
    0x78, 0x27, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // flags: u64
    0x1, 0x1c, 0xdc, 0x1, 0x91, 0xa2, 0xed, 0x16, // timestamp: u64
    0x2, 0x0, 0x0, 0x0, // opc: u32
    0x3, 0x0, // chunk_size: u16
    0x4, 0x0, 0x0, 0x0, // network_id: u32,
    0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // size: u64,
    0xd2, 0x2, 0x96, 0x49, 0x0, 0x0, 0x0, 0x0, // checksum: u64,
    0x6, 0x0, // compression: u16,
    0x7, 0x0, // encryption: u16,
    0x8, 0x0, // signature_type: u16,
    0x9, 0x0, // signature_size: u16,
    0xa, 0x0, // metadata_spec: u16,
    0xb, 0x0, 0x0, 0x0, // metadata_size: u32,
    0xa6, 0xe5, // delimiter
  };
}

test "has header" {
  try expect(hasHeader(minimal_valid_header()[0..]));
}

test "has valid header" {
  try expect(hasValidHeader(header_full_featured()[0..]));
}