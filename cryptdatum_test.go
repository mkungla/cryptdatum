// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cryptdatum

import (
	"encoding/binary"
	"io"
	"os"
	"testing"
)

func headerSetMagicAndVersion(data []byte) {
	copy(data[:4], Magic[:])
	binary.LittleEndian.PutUint16(data[4:6], Version) // version
}

func headerSetFlag(data []byte, flag DatumFlag) uint64 {
	bits := binary.LittleEndian.Uint64(data[6:14])
	if bits&uint64(flag) != 0 {
		return bits // already has a flag
	}
	bits |= uint64(flag)
	binary.LittleEndian.PutUint64(data[6:14], bits)
	return bits
}

func headerHasFlag(data []byte, flag DatumFlag) bool {
	bits := binary.LittleEndian.Uint64(data[6:14])
	return bits&uint64(flag) != 0
}

func headerRemoveFlag(data []byte, flag DatumFlag) uint64 {
	bits := binary.LittleEndian.Uint64(data[6:14])
	if bits&uint64(flag) == 0 {
		return bits // does not have a flag
	}
	flags := bits &^ uint64(flag)
	binary.LittleEndian.PutUint64(data[6:14], flags)
	return flags
}

func headerSetDelimiter(data []byte) {
	copy(data[HeaderSize-len(Delimiter):HeaderSize], Delimiter[:])
}

func headerSetTimestamp(data []byte, ts uint64) {
	binary.LittleEndian.PutUint64(data[14:22], ts)
}

func headerSetOPC(data []byte, opc uint32) {
	binary.LittleEndian.PutUint32(data[22:26], opc)
}

func headerSetChunkSize(data []byte, size uint16) {
	binary.LittleEndian.PutUint16(data[26:28], size)
}

func headerSetNetworkID(data []byte, net uint32) {
	binary.LittleEndian.PutUint32(data[28:32], net)
}

func headerSetSize(data []byte, size uint64) {
	binary.LittleEndian.PutUint64(data[32:40], size)
}

func headerGetSize(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data[32:40])
}

func headerSetChecksum(data []byte, checksum uint64) {
	binary.LittleEndian.PutUint64(data[40:48], checksum)
}

func headerSetCompression(data []byte, compalg uint16) {
	binary.LittleEndian.PutUint16(data[48:50], compalg)
}

func headerSetEncryption(data []byte, encalg uint16) {
	binary.LittleEndian.PutUint16(data[50:52], encalg)
}

func headerSetSignatureType(data []byte, styp uint16) {
	binary.LittleEndian.PutUint16(data[52:54], styp)
}

func headerSetSignatureSize(data []byte, size uint16) {
	binary.LittleEndian.PutUint16(data[54:56], size)
}

func headerSetMetadataSpec(data []byte, size uint16) {
	binary.LittleEndian.PutUint16(data[56:58], size)
}

func headerSetMetadataSize(data []byte, size uint32) {
	binary.LittleEndian.PutUint32(data[58:62], size)
}

func newMinimalValidHeader(t *testing.T) []byte {
	header := make([]byte, HeaderSize, HeaderSize)
	headerSetMagicAndVersion(header)
	headerSetFlag(header, DatumEmpty)
	headerSetTimestamp(header, MagicDate)

	headerSetDelimiter(header)

	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when spec requirements are met.")
	}
	return header
}

func TestHasHeader(t *testing.T) {
	header := make([]byte, HeaderSize, HeaderSize)
	headerSetMagicAndVersion(header)
	headerSetFlag(header, DatumDraft)
	headerSetDelimiter(header)

	small := make([]byte, HeaderSize-1, HeaderSize-1)
	headerSetMagicAndVersion(small)
	binary.LittleEndian.PutUint64(small[10:18], uint64(DatumDraft)) // draft flag
	copy(small[HeaderSize-len(Delimiter)-1:HeaderSize-1], Delimiter[:])
	if HasHeader(small) {
		t.Errorf("Header MUST be invalid when provided data is less than 64 bytes")
	}
}

func TestHeaderFieldMagic(t *testing.T) {
	header := newMinimalValidHeader(t)
	// Invalid magic
	copy(header[0:2], []byte{0x00, 0x00})
	if HasValidHeader(header) {
		t.Errorf("first four magic bytes MUST equal to `0xA7, 0xF6, 0xE5, 0xD4`")
	}
	if HasHeader(header) {
		t.Errorf("expected HasHeader to return false")
	}
}

func TestHeaderFieldVersion(t *testing.T) {
	header := newMinimalValidHeader(t)
	binary.LittleEndian.PutUint16(header[4:6], 0)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when Version is 0")
	}
	if !HasHeader(header) {
		t.Errorf("expected HasHeader to return true, even when version is invalid")
	}
}

func TestHeaderFieldFlags(t *testing.T) {
	var tests = []struct {
		Name string
		Flag DatumFlag
	}{
		{"datum invalid", DatumInvalid},
		{"datum draft", DatumDraft},
		{"datum empty", DatumEmpty},
		{"datum checksum", DatumChecksum},
		{"datum opc", DatumOPC},
		{"datum compressed", DatumCompressed},
		{"datum encrypted", DatumEncrypted},
		{"datum extractable", DatumExtractable},
		{"datum signed", DatumSigned},
		{"datum chucked", DatumChunked},
		{"datum metadata", DatumMetadata},
		{"datum compromized", DatumCompromised},
		{"datum big endian", DatumBigEndian},
		{"datum network", DatumNetwork},
	}

	header := newMinimalValidHeader(t)

	for _, test := range tests {
		headerRemoveFlag(header, test.Flag)
		if headerHasFlag(header, test.Flag) {
			t.Errorf("expected header not to have %q flag bit after it was removed", test.Name)
		}
		headerSetFlag(header, test.Flag)
		if !headerHasFlag(header, test.Flag) {
			t.Errorf("expected header to have %q flag bit after it was set", test.Name)
		}
	}
}

func TestHeaderFieldTimestamp(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetTimestamp(header, MagicDate-1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid, when TIMESTAMP value is less than magic date")
	}
}

func TestHeaderFieldOPC(t *testing.T) {
	header := newMinimalValidHeader(t)

	headerSetFlag(header, DatumOPC)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when OPC flag bit is set and OPC counter value is 0")
	}
	headerSetOPC(header, 100)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid only when other conditions are met and when OPC flag bit is set and OPC counter value is greater than 0")
	}

	header2 := newMinimalValidHeader(t)
	headerSetOPC(header2, 100)
	if HasValidHeader(header2) {
		t.Errorf("Header MUST be invalid, when OPC counter value is creater than 0 and OPC flag bit is not set")
	}
	headerSetFlag(header2, DatumOPC)
	if !HasValidHeader(header2) {
		t.Errorf("Header MUST be valid only when other conditions are met and when OPC flag bit is set and OPC counter value is greater than 0")
	}
}

func TestHeaderFieldChunkSize(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumChunked)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChunked flag bit is set and CHUNK SIZE field value is 0")
	}
	headerSetChunkSize(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumChunked flag bit is set and CHUNK SIZE field value is 1")
	}
	headerSetChunkSize(header, 65535)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumChunked flag bit is set and CHUNK SIZE field value is 65535")
	}
	headerRemoveFlag(header, DatumChunked)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChunked flag bit is not set and CHUNK SIZE field value is gt 0")
	}
}

func TestHeaderFieldNetworkID(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumNetwork)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumNetwork flag bit is set and NETWORK ID field value is 0")
	}
	headerSetNetworkID(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumNetwork flag bit is set and NETWORK ID field value is 1")
	}
	headerRemoveFlag(header, DatumNetwork)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumNetwork flag bit is not set and NETWORK ID field value is gt 0")
	}
}

func TestHeaderFieldSize(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumEmpty)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumEmpty flag bit is set and SIZE field value is 0")
	}
	headerSetSize(header, 1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumEmpty flag bit is set and SIZE field value is gt 0")
	}
	headerRemoveFlag(header, DatumEmpty)
	if headerHasFlag(header, DatumEmpty) {
		t.Error("expected to have DatumEmpty flag bit not set")
	}
	if size := headerGetSize(header); size == 0 {
		t.Error("expected size to be grater than 0")
	}

	headerSetSize(header, 0)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumEmpty flag bit is not set and SIZE field value is 0")
	}
}

func TestHeaderFieldChecksum(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumChecksum)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChecksum flag bit is set and CHECKSUM field value is empty")
	}
	headerSetChecksum(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumChecksum flag bit is set and CHECKSUM field value is not empty")
	}
	headerRemoveFlag(header, DatumChecksum)
	if headerHasFlag(header, DatumChecksum) {
		t.Error("expected to have DatumChecksum flag bit not set")
	}

	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChecksum flag bit is not set and CHECKSUM field value is not empty")
	}
}

func TestHeaderFieldCompressionAlgorithm(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumCompressed)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumCompressed flag bit is set and COMPRESSION ALGORITHM field value is empty")
	}
	headerSetCompression(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumCompressed flag bit is set and COMPRESSION ALGORITHM field value is not empty")
	}
	headerRemoveFlag(header, DatumCompressed)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumCompressed flag bit is not set and COMPRESSION ALGORITHM field value is not empty")
	}
}

func TestHeaderFieldEncryptionAlgorithm(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumEncrypted)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumEncrypted flag bit is set and ENCRYPTION ALGORITHM field value is empty")
	}
	headerSetEncryption(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumEncrypted flag bit is set and ENCRYPTION ALGORITHM field value is not empty")
	}
	headerRemoveFlag(header, DatumEncrypted)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumEncrypted flag bit is not set and ENCRYPTION ALGORITHM field value is not empty")
	}
}

func TestHeaderFieldSignatureType(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumSigned)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is set and SIGNATURE TYPE field value is empty")
	}
	headerSetSignatureType(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumSigned flag bit is set and SIGNATURE TYPE field value is set")
	}

	headerRemoveFlag(header, DatumSigned)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is not set and SIGNATURE TYPE field value is set")
	}
}

func TestHeaderFieldSignatureSize(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetSignatureSize(header, 1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is not set and SIGNATURE SIZE field value is not empty")
	}

	headerSetFlag(header, DatumSigned)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is set and SIGNATURE SIZE field value is set, but SIGNATURE TYPE is not set")
	}
	headerSetSignatureType(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumSigned flag bit is set and both SIGNATURE TYPE and SIGNATURE SIZE field values are set")
	}
}

func TestHeaderFieldMetadataType(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetFlag(header, DatumMetadata)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is set and METADATA SPEC field value is empty")
	}
	headerSetMetadataSpec(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumMetadata flag bit is set and METADATA SPEC field value is set")
	}

	headerRemoveFlag(header, DatumMetadata)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is not set and METADATA SPEC field value is set")
	}
}

func TestHeaderFieldMetadataSize(t *testing.T) {
	header := newMinimalValidHeader(t)
	headerSetMetadataSize(header, 1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is not set and METADATA SIZE field value is not empty")
	}

	headerSetFlag(header, DatumMetadata)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is set and METADATA SIZE field value is set, but METADATA SPEC is not set")
	}
	headerSetMetadataSpec(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumMetadata flag bit is set and both METADATA SPEC and METADATA SIZE field values are set")
	}
}

func TestHeaderFieldDelimiter(t *testing.T) {
	header := newMinimalValidHeader(t)
	header[62] = 0x00
	header[63] = 0x00
	var hits int
	for i := range [256]byte{} {
		header[62] = byte(i) ^ 0x00
		for j := 0; j < 256; j++ {
			header[63] = byte(j) ^ 0xFF
			if HasValidHeader(header) {
				hits++
			}
		}
	}
	if hits != 1 {
		t.Errorf("expected header to be valid for exactly one delimiter value, hits: %d", hits)
	}
}

func TestHasValidHeader(t *testing.T) {
	var (
		header []byte
		l      int
	)
	for range [HeaderSize * 2]byte{} {
		l = len(header)
		switch l {
		case 6:
			headerSetMagicAndVersion(header)
		case 14:
			headerSetFlag(header, DatumDraft)
		case HeaderSize:
			headerSetDelimiter(header)
		}
		if l >= HeaderSize && !HasValidHeader(header) {
			t.Errorf("expected header to be valid, len: %d header: %v", l, header)
		} else if l < HeaderSize && HasValidHeader(header) {
			t.Errorf("expected header to be invalid, len: %d header: %v", l, header)
		}
		header = append(header, 0x00)
	}

	// just to ensure, but we can be sure it is valid
	if !HasValidHeader(header) {
		t.Errorf("expected header to be valid, len: %d header: %v", l, header)
	}
	// invalidate the version
	binary.LittleEndian.PutUint16(header[4:6], 0)
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid, len: %d header: %v", l, header)
	}

	// restore version
	headerSetMagicAndVersion(header)

	var flags uint64
	flags = headerRemoveFlag(header, DatumDraft)
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid when no flags are set, flags: %d header: %v", flags, header)
	}
	flags = headerSetFlag(header, DatumEmpty)
	headerSetTimestamp(header, MagicDate-1) // invalid date
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid setting DatumEmpty and Timestamp(MagicDate-1), flags: %d header: %v", flags, header)
	}

	// set minimum valid timestamp
	headerSetTimestamp(header, MagicDate) // valid date
	if !HasValidHeader(header) {
		t.Errorf("expected header to be valid setting DatumEmpty and Timestamp(MagicDate), flags: %d header: %v", flags, header)
	}
	// Fully featured header
	fullHeader := newMinimalValidHeader(t)
	if !HasValidHeader(fullHeader) {
		t.Errorf("expected header to be valid setting from test.newFullValidHeader header: %v", fullHeader)
	}
}

func TestCompromizedData(t *testing.T) {
	header := make([]byte, HeaderSize, HeaderSize)
	headerSetMagicAndVersion(header)
	headerSetFlag(header, DatumDraft)
	headerSetDelimiter(header)

	if !HasValidHeader(header) {
		t.Errorf("expected header to be valid %v", header)
	}

	headerSetFlag(header, DatumCompromised)
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid after setting flag bit 2048, header: %v", header)
	}
}

func TestSpecV1_HasValidHeader_ValidMinimalHeader(t *testing.T) {
	head, err := os.Open("testdata/v1/valid-minimal-header.cdt")
	if err != nil {
		t.Error(err)
	}
	defer head.Close()

	header, err := io.ReadAll(head)
	if err != nil {
		t.Error(err)
	}
	if !HasValidHeader(header) {
		t.Errorf("expected header to be invalid")
	}
}

func TestSpecV1_DecodeHeader_ValidMinimalHeader(t *testing.T) {
	head, err := os.Open("testdata/v1/valid-minimal-header.cdt")
	if err != nil {
		t.Error(err)
	}
	defer head.Close()
	h, err := DecodeHeader(head)
	if err != nil {
		t.Error(err)
	}
	if h.Version != Version {
		t.Errorf("expected Version to be %d got %d", Version, h.Version)
	}
	if h.Flags&DatumEmpty == 0 {
		t.Error("expected DatumEmpty flag bit to be set")
	}
}

func TestSpecV1_DecodeHeader_ValidFullFeaturedHeader(t *testing.T) {
	head, err := os.Open("testdata/v1/valid-full-featured-header.cdt")
	if err != nil {
		t.Error(err)
	}
	defer head.Close()
	h, err := DecodeHeader(head)
	if err != nil {
		t.Error(err)
	}
	if h.Version != Version {
		t.Errorf("expected Version to be %d got %d", Version, h.Version)
	}

	var flags = []DatumFlag{
		DatumChecksum,
		DatumOPC,
		DatumCompressed,
		DatumEncrypted,
		DatumSigned,
		DatumChunked,
		DatumMetadata,
		DatumNetwork,
	}

	for _, flag := range flags {
		if h.Flags&flag == 0 {
			t.Errorf("expected flag %d to be set", flag)
		}
	}

	if h.Timestamp != 1652155382000000001 {
		t.Errorf("expected Timestamp 1652155382000000001 got %d", h.Timestamp)
	}
	if h.Time().IsZero() {
		t.Errorf("expected time not to be zero")
	}
	if h.OPC != 2 {
		t.Errorf("expected OPC 2 got %d", h.OPC)
	}
	if h.ChunkSize != 3 {
		t.Errorf("expected ChunkSize 3 got %d", h.ChunkSize)
	}
	if h.NetworkID != 4 {
		t.Errorf("expected NetworkID 4 got %d", h.NetworkID)
	}
	if h.Size != 5 {
		t.Errorf("expected Size 5 got %d", h.Size)
	}
	if h.Checksum != 1234567890 {
		t.Errorf("expected Checksum 1234567890 got %d", h.Checksum)
	}
	if h.Compression != 6 {
		t.Errorf("expected Compression 6 got %d", h.Compression)
	}
	if h.Encryption != 7 {
		t.Errorf("expected Encryption 7 got %d", h.Encryption)
	}
	if h.SignatureType != 8 {
		t.Errorf("expected SignatureType 8 got %d", h.SignatureType)
	}
	if h.SignatureSize != 9 {
		t.Errorf("expected SignatureSize 9 got %d", h.SignatureSize)
	}
	if h.MetadataSpec != 10 {
		t.Errorf("expected MetadataSpec 10 got %d", h.MetadataSpec)
	}
	if h.MetadataSize != 11 {
		t.Errorf("expected MetadataSize 11 got %d", h.MetadataSize)
	}
}
