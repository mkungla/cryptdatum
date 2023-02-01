// Copyright 2023 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

const std = @import("std");
const cryptdatum = @import("cryptdatum/cryptdatum.zig");

const print = std.debug.print;

pub fn main() !void {
  var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
  defer _ = gpa.deinit();
  var args = try std.process.argsWithAllocator(gpa.allocator());
  defer args.deinit();
  _ = args.skip(); // arg 0
  
  const cmd = args.next() orelse {
    std.io.getStdErr().writeAll("error: no subcommand provided.\n") catch {};
    return;
  };
  const arg1 = args.next() orelse {
    std.io.getStdErr().writeAll("error: missing arg.\n") catch {};
    return;
  };


  if (std.mem.eql(u8, "file-has-header", cmd)) {
    if (cmdFileHasHeader(arg1)) {
      std.os.exit(0);
    } else {
      std.os.exit(1);
    }
  } else if  (std.mem.eql(u8, "file-has-valid-header", cmd)) {
    if (cmdFileHasValidHeader(arg1)) {
      std.os.exit(0);
    } else {
      std.os.exit(1);
    }
  } else if  (std.mem.eql(u8, "file-has-invalid-header", cmd)) {
    if (cmdFileHasValidHeader(arg1)) {
      std.os.exit(1);
    } else {
      std.os.exit(0);
    }
  } else if  (std.mem.eql(u8, "file-info", cmd)) {
    if (cmdFileInfo(gpa.allocator(), arg1)) |ok| {
      if (ok) {
        std.os.exit(0);
      } else {
        std.os.exit(1);
      }
    } else |err| {
      std.io.getStdErr().writer().print("failed to read file info {s}: {s}\n", .{ arg1, @errorName(err) }) catch {};
      std.os.exit(1);
    }
  } else {
    std.io.getStdErr().writeAll("error: invalid command.\n") catch {};
    std.os.exit(1);
  }
}

fn cmdFileHasHeader(filepath: []const u8) bool {
  var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
  defer _ = gpa.deinit();
  const buf = std.fs.cwd().readFileAlloc(gpa.allocator(), filepath, 64) catch |err| switch (err) {
    error.OutOfMemory => {
      std.io.getStdErr().writeAll("allocation failure\n") catch {};
      return false;
    },
    else => { // this should catch any possible error opening the file
      std.io.getStdErr().writer().print("failed to open file {s}: {s}\n", .{ filepath, @errorName(err) }) catch {};
      return false;
    },
  };
  defer gpa.allocator().free(buf);

  return cryptdatum.hasHeader(buf);
}

fn cmdFileHasValidHeader(filepath: []const u8) bool {
  var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
  defer _ = gpa.deinit();
  const buf = std.fs.cwd().readFileAlloc(gpa.allocator(), filepath, 64) catch |err| switch (err) {
    error.OutOfMemory => {
      std.io.getStdErr().writeAll("allocation failure\n") catch {};
      return false;
    },
    else => { // this should catch any possible error opening the file
      std.io.getStdErr().writer().print("failed to open file {s}: {s}\n", .{ filepath, @errorName(err) }) catch {};
      return false;
    },
  };
  defer gpa.allocator().free(buf);

  return cryptdatum.hasValidHeader(buf);
}

fn cmdFileInfo(allocator: std.mem.Allocator, filepath: []const u8) !bool {
  const buf = std.fs.cwd().readFileAlloc(allocator, filepath, 64) catch |err| switch (err) {
    error.OutOfMemory => {
      std.io.getStdErr().writeAll("allocation failure\n") catch {};
      return false;
    },
    else => { // this should catch any possible error opening the file
      std.io.getStdErr().writer().print("failed to open file {s}: {s}\n", .{ filepath, @errorName(err) }) catch {};
      return false;
    },
  };
  defer allocator.free(buf);

  const header = try cryptdatum.decodeHeader(buf);

  try print_header(allocator, header);

  return true;
}

const string = []const u8;

const units = &[_]string{ "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

fn print_header(allocator: std.mem.Allocator, header: cryptdatum.Header) !void {
  const stdout_file = std.io.getStdOut().writer();
  var bw = std.io.bufferedWriter(stdout_file);
  const stdout = bw.writer();
  
  var size_buf: [32]u8 = undefined;
  var i: u8 = 0;
  var size = header.size;
  while (size >= 1024 and i < 8) {
    size /= 1024;
    i += 1;
  }

  // const created = try timestampFormat("%Y-%m-%dT%H:%M:%S%nZ", header.timestamp);
  var tsformat = try cryptdatum.TimeFormatter.init(allocator, header.timestamp);
  defer tsformat.deinit();

  const created = try tsformat.format("%Y-%m-%dT%H:%M:%S%nZ");
  const datumsize = try std.fmt.bufPrint(&size_buf, "{d} {s}", .{size, units[i]});

  try stdout.print("+-------------------+-----------------------------------------+------------------------------------+\n", .{});
  try stdout.print("| CRYPTDATUM        | SIZE: {s:>23} | CREATED: {s:>35} | \n", .{datumsize, created});
  try stdout.print("+-------------------+----------+------------------------------+-------------+----------------------+\n", .{});
  try stdout.print("| Field             | Size (B) | Description                  | Type        | Value                |\n", .{});
  try stdout.print("+-------------------+----------+------------------------------+-------------+----------------------+\n", .{});
  try stdout.print("| VERSION ID        | 2        | Version number               | 16-bit uint | {?:<20} |\n", .{header.version});
  try stdout.print("| FLAGS             | 8        | Flags                        | 64-bit uint | {?:<20} |\n", .{header.flags});
  try stdout.print("| TIMESTAMP         | 8        | Timestamp                    | 64-bit uint | {?:<20} |\n", .{header.timestamp});
  try stdout.print("| OPERATION COUNTER | 4        | Operation Counter            | 32-bit uint | {?:<20} |\n", .{header.opc});
  try stdout.print("| CHUNK SIZE        | 8        | Data chunk size              | 16-bit uint | {?:<20} |\n", .{header.chunk_size});
  try stdout.print("| NETWORK ID        | 8        | Network ID                   | 32-bit uint | {?:<20} |\n", .{header.network_id});
  try stdout.print("| SIZE              | 8        | Total payload size           | 64-bit uint | {?:<20} |\n", .{header.size});
  try stdout.print("| CHECKSUM          | 8        | Datum checksum               | 64-bit uint | {?:<20} |\n", .{header.checksum});
  try stdout.print("| COMPRESSION ALGO. | 2        | Compression algorithm        | 16-bit uint | {?:<20} |\n", .{header.compression});
  try stdout.print("| ENCRYPTION ALGO.  | 2        | Encryption algorithm         | 16-bit uint | {?:<20} |\n", .{header.encryption});
  try stdout.print("| SIGNATURE TYPE    | 2        | Signature type               | 16-bit uint | {?:<20} |\n", .{header.signature_type});
  try stdout.print("| SIGNATURE SIZE    | 2        | Signature size               | 16-bit uint | {?:<20} |\n", .{header.signature_size});
  try stdout.print("| METADATA SPEC     | 2        | Metadata specification       | 16-bit uint | {?:<20} |\n", .{header.metadata_spec});
  try stdout.print("| MEATADATA SIZE    | 4        | Metadata size                | 32-bit uint | {?:<20} |\n", .{header.metadata_size});
  try stdout.print("+-------------------+----------+------------------------------+-------------+----------------------+\n", .{});
  try stdout.print("| DATUM FLAGS                  | Bits                         | Flag bit is set                    |\n", .{});
  try stdout.print("+------------------------------+-------------------------------------------------------------------+\n", .{});
  try stdout.print("| DATUM INVALID                | 1                            | {:<5}                              |\n", .{cryptdatum.DatumFlag.Invalid.isSet(header.flags)});
  try stdout.print("| DATUM DRAFT                  | 2                            | {:<5}                              |\n", .{cryptdatum.DatumFlag.Draft.isSet(header.flags)});
  try stdout.print("| DATUM EMPTY                  | 4                            | {:<5}                              |\n", .{cryptdatum.DatumFlag.Empty.isSet(header.flags)});
  try stdout.print("| DATUM CHECKSUM               | 8                            | {:<5}                              |\n", .{cryptdatum.DatumFlag.Checksum.isSet(header.flags)});
  try stdout.print("| DATUM OPC                    | 16                           | {:<5}                              |\n", .{cryptdatum.DatumFlag.OPC.isSet(header.flags)});
  try stdout.print("| DATUM COMPRESSED             | 32                           | {:<5}                              |\n", .{cryptdatum.DatumFlag.Compressed.isSet(header.flags)});
  try stdout.print("| DATUM ENCRYPTED              | 64                           | {:<5}                              |\n", .{cryptdatum.DatumFlag.Encrypted.isSet(header.flags)});
  try stdout.print("| DATUM EXTRACTABLE            | 128                          | {:<5}                              |\n", .{cryptdatum.DatumFlag.Extractable.isSet(header.flags)});
  try stdout.print("| DATUM SIGNED                 | 256                          | {:<5}                              |\n", .{cryptdatum.DatumFlag.Signed.isSet(header.flags)});
  try stdout.print("| DATUM CHUNKED                | 512                          | {:<5}                              |\n", .{cryptdatum.DatumFlag.Chunked.isSet(header.flags)});
  try stdout.print("| DATUM METADATA               | 1024                         | {:<5}                              |\n", .{cryptdatum.DatumFlag.Metadata.isSet(header.flags)});
  try stdout.print("| DATUM COMPROMISED            | 2048                         | {:<5}                              |\n", .{cryptdatum.DatumFlag.Compromised.isSet(header.flags)});
  try stdout.print("| DATUM BIG ENDIAN             | 4096                         | {:<5}                              |\n", .{cryptdatum.DatumFlag.BigEndian.isSet(header.flags)});
  try stdout.print("| DATUM DATUM NETWORK          | 8192                         | {:<5}                              |\n", .{cryptdatum.DatumFlag.Network.isSet(header.flags)});
  try stdout.print("+------------------------------+-------------------------------------------------------------------+\n", .{});
  try bw.flush();
}
