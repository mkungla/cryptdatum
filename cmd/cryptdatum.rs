// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.
use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;
use cryptdatum::*;

fn main() -> Result<()> {
  let args: Vec<String> = env::args().collect();

  if args.len() < 2 {
      println!("error: no subcommand provided.");
      exit(1);
  }

  let command = &args[1];
  let filepath = &args[2];

  match command.as_str() {
      "file-has-header" => cmd_file_has_header(filepath)?,
      "file-has-valid-header" => cmd_file_has_valid_header(filepath)?,
      "file-has-invalid-header" => cmd_file_has_invalid_header(filepath)?,
      "file-info" => cmd_file_info(filepath)?,
      // "file-info" => cmd_file_info(filepath)?,
      _ => {
          println!("invalid command");
          exit(1);
      }
  }

  Ok(())
}

fn cmd_file_has_header(filepath: &str) -> Result<()> {
  let mut ctd = File::open(filepath)?;
  let mut headb = [0; cryptdatum::HEADER_SIZE];

  ctd.read_exact(&mut headb)?;

  if !has_header(&headb) {
      exit(1);
  }

  Ok(())
}

fn cmd_file_has_valid_header(filepath: &str) -> Result<()> {
  let mut ctd = File::open(filepath)?;
  let mut headb = [0; cryptdatum::HEADER_SIZE];

  ctd.read_exact(&mut headb)?;

  if !has_valid_header(&headb) {
      exit(1);
  }

  Ok(())
}

fn cmd_file_has_invalid_header(filepath: &str) -> Result<()> {
  let mut ctd = File::open(filepath)?;
  let mut headb = [0; cryptdatum::HEADER_SIZE];

  ctd.read_exact(&mut headb)?;

  if has_valid_header(&headb) {
    exit(1);
  }
  Ok(())
}

fn cmd_file_info(filepath: &str) -> Result<()> {
  let mut ctd = File::open(filepath)?;
  let header = decode_header(&mut ctd)?;
  print_header(header);
  Ok(())
}

fn pretty_size(size: u64) -> String {
  let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
  let mut i = 0;
  let mut ss = size;
  while ss >= 1024 && i < 8 {
      ss /= 1024;
      i += 1;
  }
  format!("{} {}", ss, units[i])
}

fn bool_str(value: bool) -> &'static str {
  if value {
      "true"
  } else {
      "false"
  }
}

fn print_header(header: Header) {

  let created = timestamp::format("%Y-%m-%dT%H:%M:%S%nZ", header.timestamp);
  let datumsize = pretty_size(header.size);

  print!("+-------------------+-----------------------------------------+------------------------------------+\n");
  print!("| CRYPTDATUM        | SIZE: {:>23} | CREATED: {:>35} | \n", datumsize, created);
	print!("+-------------------+----------+------------------------------+-------------+----------------------+\n");
	print!("| Field             | Size (B) | Description                  | Type        | Value                |\n");
	print!("+-------------------+----------+------------------------------+-------------+----------------------+\n");
	print!("| VERSION ID        | 2        | Version number               | 16-bit uint | {:<20} |\n", header.version);
	print!("| FLAGS             | 8        | Flags                        | 64-bit uint | {:<20} |\n", 0);
	print!("| TIMESTAMP         | 8        | Timestamp                    | 64-bit uint | {:<20} |\n", header.timestamp);
	print!("| OPERATION COUNTER | 4        | Operation Counter            | 32-bit uint | {:<20} |\n", header.opc);
	print!("| CHUNK SIZE        | 8        | Data chunk size              | 16-bit uint | {:<20} |\n", header.chunk_size);
	print!("| NETWORK ID        | 8        | Network ID                   | 32-bit uint | {:<20} |\n", header.network_id);
	print!("| SIZE              | 8        | Total payload size           | 64-bit uint | {:<20} |\n", header.size);
	print!("| CHECKSUM          | 8        | Datum checksum               | 64-bit uint | {:<20} |\n", header.checksum);
	print!("| COMPRESSION ALGO. | 2        | Compression algorithm        | 16-bit uint | {:<20} |\n", header.compression);
	print!("| ENCRYPTION ALGO.  | 2        | Encryption algorithm         | 16-bit uint | {:<20} |\n", header.encryption);
	print!("| SIGNATURE TYPE    | 2        | Signature type               | 16-bit uint | {:<20} |\n", header.signature_type);
	print!("| SIGNATURE SIZE    | 2        | Signature size               | 16-bit uint | {:<20} |\n", header.signature_size);
	print!("| METADATA SPEC     | 2        | Metadata specification       | 16-bit uint | {:<20} |\n", header.metadata_spec);
	print!("| MEATADATA SIZE    | 4        | Metadata size                | 32-bit uint | {:<20} |\n", header.metadata_size);
	print!("+-------------------+----------+------------------------------+-------------+----------------------+\n");
	print!("| DATUM FLAGS                  | Bits                         | Flag bit is set                    |\n");
	print!("+------------------------------+-------------------------------------------------------------------+\n");
	print!("| DATUM INVALID                | 1                            | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumInvalid));
	print!("| DATUM DRAFT                  | 2                            | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumDraft));
	print!("| DATUM EMPTY                  | 4                            | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumEmpty));
	print!("| DATUM CHECKSUM               | 8                            | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumChecksum));
	print!("| DATUM OPC                    | 16                           | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumOPC));
	print!("| DATUM COMPRESSED             | 32                           | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumCompressed));
	print!("| DATUM ENCRYPTED              | 64                           | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumEncrypted));
	print!("| DATUM EXTRACTABLE            | 128                          | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumExtractable));
	print!("| DATUM SIGNED                 | 256                          | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumSigned));
	print!("| DATUM CHUNKED                | 512                          | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumChunked));
	print!("| DATUM METADATA               | 1024                         | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumMetadata));
	print!("| DATUM COMPROMISED            | 2048                         | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumCompromised));
	print!("| DATUM BIG ENDIAN             | 4096                         | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumBigEndian));
	print!("| DATUM DATUM NETWORK          | 8192                         | {:<5}                              |\n", bool_str(header.flags & DatumFlag::DatumNetwork));
	print!("+------------------------------+-------------------------------------------------------------------+\n");
}
