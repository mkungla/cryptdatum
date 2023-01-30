// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package main

import (
	"encoding/binary"
	"os"
	"time"

	"golang.org/x/exp/slog"
)

var (
	magic = [4]byte{0xA7, 0xF6, 0xE5, 0xD4}

	delimiter = [2]byte{0xA6, 0xE5}
)

func main() {
	var generators = []func() (string, error){
		createValidMinimalHeader,
		createValidFullFeaturedHeader,
	}
	for _, gen := range generators {
		if name, err := gen(); err != nil {
			slog.Error("failed to create", err, slog.String("file", name))
			os.Exit(1)
		}
	}
}

// createValidMinimalHeader craetes valid header which is valid
func createValidMinimalHeader() (string, error) {
	const name = "valid-minimal-header.cdt"
	var header [64]byte

	// Set Magic
	copy(header[0:4], magic[:])
	// Set version, must be 1
	binary.LittleEndian.PutUint16(header[4:6], 1)
	// DatumEmpty
	binary.LittleEndian.PutUint64(header[6:14], 4)

	ts := time.Date(2022, 5, 10, 4, 3, 2, 1, time.UTC).UnixNano()
	binary.LittleEndian.PutUint64(header[14:22], uint64(ts))

	// Delimiter
	copy(header[62:64], delimiter[:])

	return name, os.WriteFile(name, header[:], 0640)
}

func createValidFullFeaturedHeader() (string, error) {
	const name = "valid-full-featured-header-with-empty-chunk.cdt"
	var header [64]byte
	// Set Magic
	copy(header[0:4], magic[:])
	// Set version, must be 1
	binary.LittleEndian.PutUint16(header[4:6], 1)
	// DatumChecksum 8
	// DatumOPC 16
	// DatumCompressed 32
	// DatumEncrypted 64
	// DatumSigned 256
	// DatumChunked 512
	// DatumMetadata 1024
	// DatumNetwork 8192
	binary.LittleEndian.PutUint64(header[6:14], 8|16|32|64|256|512|1024|8192)

	// Timestamp is Unix timestamp in nanoseconds spec v1 min date.
	ts := time.Date(2022, 5, 10, 4, 3, 2, 1, time.UTC).UnixNano()

	binary.LittleEndian.PutUint64(header[14:22], uint64(ts))

	// OPC Operation Counter
	binary.LittleEndian.PutUint32(header[22:26], 2)

	// ChunkSize
	binary.LittleEndian.PutUint16(header[26:28], 3)

	// NetworkID
	binary.LittleEndian.PutUint32(header[28:32], 4)

	// Size
	binary.LittleEndian.PutUint64(header[32:40], 5)

	// CRC64 checksum
	binary.LittleEndian.PutUint64(header[40:48], 1234567890)

	// Compression
	binary.LittleEndian.PutUint16(header[48:50], 6)

	// Encryption
	binary.LittleEndian.PutUint16(header[50:52], 7)

	// SignatureType
	binary.LittleEndian.PutUint16(header[52:54], 8)

	// SignatureSize
	binary.LittleEndian.PutUint16(header[54:56], 9)

	// MetadataSpec
	binary.LittleEndian.PutUint16(header[56:58], 10)

	// MetadataSize
	binary.LittleEndian.PutUint32(header[58:62], 11)

	// Delimiter
	copy(header[62:64], delimiter[:])
	return name, os.WriteFile(name, header[:], 0640)
}
