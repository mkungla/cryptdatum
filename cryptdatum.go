// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cryptdatum

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// Version is the current version of the Cryptdatum format.
	// Implementations of the Cryptdatum library should set the version field in
	// Cryptdatum headers to this value.
	Version uint16 = 1

	// MinVersion is the minimum supported version of the Cryptdatum format.
	// If the version field in a Cryptdatum header is lower than this value, the
	// header should be considered invalid.
	MinVersion uint16 = 1

	// HeaderSize is the size of a Cryptdatum header in bytes. It can be used by
	// implementations of the Cryptdatum library to allocate sufficient memory for
	// a Cryptdatum header, or to check the size of a Cryptdatum header that has
	// been read from a stream.
	HeaderSize int = 64

	// MagicDate is date which datum can not be older. Therefore it is the minimum
	// value possible for Header.Timestamp
	MagicDate uint64 = 1652155382000000001
)

type DatumFlag uint64

const (
	DatumInvalid DatumFlag = 1 << iota
	DatumDraft
	DatumEmpty
	DatumChecksum
	DatumOPC
	DatumCompressed
	DatumEncrypted
	DatumExtractable
	DatumSigned
	DatumChunked
	DatumMetadata
	DatumCompromised
	DatumBigEndian
	DatumNetwork
)

var (
	// Magic is the magic number used to identify Cryptdatum headers. If the magic
	// number field in a Cryptdatum header does not match this value, the header
	// should be considered invalid.
	Magic = [4]byte{0xA7, 0xF6, 0xE5, 0xD4}

	// Delimiter is the delimiter used to mark the end of a Cryptdatum header. If
	// the delimiter field in a Cryptdatum header does not match this value, the
	// header should be considered invalid.
	Delimiter = [2]byte{0xA6, 0xE5}

	// empty
	empty  = [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	empty2 = [2]byte{0x00, 0x00}
)

var (
	Err                  = errors.New("cryptdatum")
	ErrIO                = fmt.Errorf("%w i/o", Err)
	ErrEOF               = fmt.Errorf("%w EOF", Err)
	ErrUnsupportedFormat = fmt.Errorf("%w unsupported format", Err)
	ErrInvalidHeader     = fmt.Errorf("%w invalid header", Err)
)

// Header represents a Cryptdatum header. It contains metadata about the data
// payload, such as the version of the Cryptdatum format, the time when the
// data was created, and the features used by the datum.
type Header struct {
	// Version indicates the version of the Cryptdatum format.
	Version uint16

	// Cryptdatum format features flags to indicate which Cryptdatum features are
	// used by that datum e.g whether the data is encrypted, compressed, or has
	// a checksum. has operation counter set is signed etc.
	Flags DatumFlag

	// Timestamp is Unix timestamp in nanoseconds, indicating the time when the data was created.
	Timestamp uint64

	// OPC Operation Counter - Unique operation ID for the data.
	OPC uint32

	// ChunkSize in kilobytes if DatumChunked is enabled
	ChunkSize uint16

	// NetworkID identifes the source network of the payload. When 0 no network is specified.
	NetworkID uint32

	// Total size of the data, including the header and optional signature.
	Size uint64

	// CRC64 checksum for verifying the integrity of the data.
	Checksum uint64

	// Compression indicates the compression algorithm used, if any.
	Compression uint16

	// Encryption indicates the encryption algorithm used, if any.
	Encryption uint16

	// SignatureType indicates the signature type helping implementations to
	// identify how the signature should be verified.
	SignatureType uint16

	// SignatureSize indicates the size of the signature, if any.
	SignatureSize uint16

	// MetadataSpec is identifer which indentifies metadata format used if any is used.
	MetadataSpec uint16

	// MetadataSize
	MetadataSize uint32
}

// HasHeader checks if the provided data contains a Cryptdatum header. It looks for specific header
// fields and checks their alignment, but does not perform any further validations. If the data
// is likely to be Cryptdatum, the function returns true. Otherwise, it returns false.
// If you want to verify the integrity of the header as well, use the HasValidHeader function
// or use DecodeHeader and perform the validation yourself.
//
// The data argument should contain the entire Cryptdatum data, as a byte slice. The function will
// read the first HeaderSize bytes of the slice to check for the presence of a header.
func HasHeader(data []byte) bool {
	if len(data) < HeaderSize {
		return false
	}

	// check magic and delimiter
	return Magic == [4]byte(data[:4]) && Delimiter == [2]byte(data[62:HeaderSize])
}

// HasValidHeader checks if the provided data contains a valid Cryptdatum header. It verifies the
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
func HasValidHeader(data []byte) bool {
	if !HasHeader(data) {
		return false
	}
	// check version is >= 1
	if binary.LittleEndian.Uint16(data[4:6]) < 1 {
		return false
	}

	flags := DatumFlag(binary.LittleEndian.Uint64(data[6:14]))

	// retuirn fast if data is compromized or DatumDraft
	if flags&DatumCompromised != 0 {
		return false
	}

	if flags&DatumDraft != 0 {
		return true
	}

	// If it was not a draft it must have timestamp
	if binary.LittleEndian.Uint64(data[14:22]) < MagicDate {
		return false
	}

	// DatumOPC is set then counter value must be gte 1
	if opc := binary.LittleEndian.Uint32(data[22:26]); (flags&DatumOPC != 0 && opc == 0) || (flags&DatumOPC == 0 && opc > 0) {
		return false

	}
	// DatumChunked is set then chunk size value must be gte 1
	if cs := binary.LittleEndian.Uint16(data[26:28]); (flags&DatumChunked != 0 && cs == 0) || (flags&DatumChunked == 0 && cs > 0) {
		return false
	}

	// DatumNetwork is set then network id value must be gte 1
	if net := binary.LittleEndian.Uint32(data[28:32]); (flags&DatumNetwork != 0 && net < 1) || (flags&DatumNetwork == 0 && net > 0) {
		return false
	}

	// DatumEmpty is set then size value must be 0
	// DatumEmpty is not set then size value must be gte 1
	if size := binary.LittleEndian.Uint64(data[32:40]); (flags&DatumEmpty != 0 && size > 0) || flags&DatumEmpty == 0 && size == 0 {
		return false
	}

	// DatumChecksum must be set when checsum is used and not set if Checksum field is not empty
	if flags&DatumChecksum != 0 && [8]byte(data[40:48]) == empty || flags&DatumChecksum == 0 && [8]byte(data[40:48]) != empty {
		return false
	}

	// DatumCompressed compression algorithm must be set
	if flags&DatumCompressed != 0 && [2]byte(data[48:50]) == empty2 {
		return false
	}

	// DatumEncrypted encryption algorithm must be set
	if flags&DatumEncrypted != 0 && [2]byte(data[50:52]) == empty2 {
		return false
	}

	// SIGNATURE TYPE and SIGNATURE SIZE
	if flags&DatumSigned != 0 && [2]byte(data[52:54]) == empty2 {
		return false
	}
	if flags&DatumSigned == 0 && ([2]byte(data[52:54]) != empty2 || [2]byte(data[54:56]) != empty2) {
		return false
	}

	// MEATADATA SPEC  and MEATADATA SIZE
	if flags&DatumMetadata != 0 && [2]byte(data[56:58]) == empty2 {
		return false
	}
	if flags&DatumMetadata == 0 && ([2]byte(data[56:58]) != empty2 || [2]byte(data[58:62]) != empty2) {
		return false
	}

	return true
}

// DecodeHeader returns the header information of a Cryptdatum data without decoding the entire data.
// The header information is read from the provided reader, which should contain the Cryptdatum data.
// If the header is invalid or an error occurs while reading, an error is returned.
//
// Caller is responsible to close the source e.g FILE
func DecodeHeader(r io.Reader) (header Header, err error) {
	headb := make([]byte, HeaderSize)

	n, err := r.Read(headb)
	if err != nil {
		return header, err
	}
	if n < HeaderSize {
		return header, io.ErrUnexpectedEOF
	}
	if !HasHeader(headb) {
		return Header{}, ErrUnsupportedFormat
	}
	if !HasValidHeader(headb) {
		return Header{}, ErrInvalidHeader
	}

	header.Version = binary.LittleEndian.Uint16(headb[4:6])
	header.Flags = DatumFlag(binary.LittleEndian.Uint64(headb[6:14]))
	header.Timestamp = binary.LittleEndian.Uint64(headb[14:22])
	header.OPC = binary.LittleEndian.Uint32(headb[22:26])
	header.ChunkSize = binary.LittleEndian.Uint16(headb[26:28])
	header.NetworkID = binary.LittleEndian.Uint32(headb[28:32])
	header.Size = binary.LittleEndian.Uint64(headb[32:40])
	header.Checksum = binary.LittleEndian.Uint64(headb[40:48])
	header.Compression = binary.LittleEndian.Uint16(headb[48:50])
	header.Encryption = binary.LittleEndian.Uint16(headb[50:52])
	header.SignatureType = binary.LittleEndian.Uint16(headb[52:54])
	header.SignatureSize = binary.LittleEndian.Uint16(headb[54:56])
	header.MetadataSpec = binary.LittleEndian.Uint16(headb[56:58])
	header.MetadataSize = binary.LittleEndian.Uint32(headb[58:62])
	return header, nil
}

func Time(ns uint64) time.Time {
	return time.Unix(int64(ns/1e9), int64(ns%1e9))
}
