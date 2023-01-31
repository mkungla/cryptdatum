// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cryptdatum

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/howijd/cryptdatum/tests/spec"
)

func newMinimalValidHeader(t *testing.T) []byte {
	header := spec.Latest.NewMinimalValidHeader()
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when minimum spec v1 requirements are met.")
	}
	return header
}

func TestHasHeader(t *testing.T) {
	header := make([]byte, HeaderSize-1, HeaderSize-1)
	spec.Latest.HeaderSetMagicAndVersion(header)
	spec.Latest.HeaderSetFlag(header, uint64(DatumDraft))
	copy(header[HeaderSize-len(Delimiter)-1:HeaderSize-1], Delimiter[:])
	if HasHeader(header) {
		t.Errorf("Header MUST be invalid when provided data is less than 64 bytes")
	}
}

func TestHeaderFieldMagic(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
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
	header := spec.Latest.NewMinimalValidHeader()
	binary.LittleEndian.PutUint16(header[4:6], 0)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when Version is 0")
	}
	if !HasHeader(header) {
		t.Errorf("expected HasHeader to return true, even when version is invalid")
	}
}

func TestHeaderFieldFlags(t *testing.T) {
	var flagTests = []struct {
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

	header := spec.Latest.NewMinimalValidHeader()

	for _, test := range flagTests {
		spec.Latest.HeaderRemoveFlag(header, uint64(test.Flag))
		if spec.Latest.HeaderHasFlag(header, uint64(test.Flag)) {
			t.Errorf("expected header not to have %q flag bit after it was removed", test.Name)
		}
		spec.Latest.HeaderSetFlag(header, uint64(test.Flag))
		if !spec.Latest.HeaderHasFlag(header, uint64(test.Flag)) {
			t.Errorf("expected header to have %q flag bit after it was set", test.Name)
		}
	}
}

func TestHeaderFieldTimestamp(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetTimestamp(header, MagicDate-1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid, when TIMESTAMP value is less than magic date")
	}
}

func TestHeaderFieldOPC(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()

	spec.Latest.HeaderSetFlag(header, uint64(DatumOPC))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when OPC flag bit is set and OPC counter value is 0")
	}
	spec.Latest.HeaderSetOPC(header, 100)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid only when other conditions are met and when OPC flag bit is set and OPC counter value is greater than 0")
	}

	header2 := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetOPC(header2, 100)
	if HasValidHeader(header2) {
		t.Errorf("Header MUST be invalid, when OPC counter value is creater than 0 and OPC flag bit is not set")
	}
	spec.Latest.HeaderSetFlag(header2, uint64(DatumOPC))
	if !HasValidHeader(header2) {
		t.Errorf("Header MUST be valid only when other conditions are met and when OPC flag bit is set and OPC counter value is greater than 0")
	}
}

func TestHeaderFieldChunkSize(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumChunked))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChunked flag bit is set and CHUNK SIZE field value is 0")
	}
	spec.Latest.HeaderSetChunkSize(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumChunked flag bit is set and CHUNK SIZE field value is 1")
	}
	spec.Latest.HeaderSetChunkSize(header, 65535)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumChunked flag bit is set and CHUNK SIZE field value is 65535")
	}
	spec.Latest.HeaderRemoveFlag(header, uint64(DatumChunked))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChunked flag bit is not set and CHUNK SIZE field value is gt 0")
	}
}

func TestHeaderFieldNetworkID(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumNetwork))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumNetwork flag bit is set and NETWORK ID field value is 0")
	}
	spec.Latest.HeaderSetNetworkID(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumNetwork flag bit is set and NETWORK ID field value is 1")
	}
	spec.Latest.HeaderRemoveFlag(header, uint64(DatumNetwork))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumNetwork flag bit is not set and NETWORK ID field value is gt 0")
	}
}

func TestHeaderFieldSize(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumEmpty))
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumEmpty flag bit is set and SIZE field value is 0")
	}
	spec.Latest.HeaderSetSize(header, 1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumEmpty flag bit is set and SIZE field value is gt 0")
	}
	spec.Latest.HeaderRemoveFlag(header, uint64(DatumEmpty))
	if spec.Latest.HeaderHasFlag(header, uint64(DatumEmpty)) {
		t.Error("expected to have DatumEmpty flag bit not set")
	}
	if size := spec.Latest.HeaderGetSize(header); size == 0 {
		t.Error("expected size to be grater than 0")
	}

	spec.Latest.HeaderSetSize(header, 0)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumEmpty flag bit is not set and SIZE field value is 0")
	}
}

func TestHeaderFieldChecksum(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumChecksum))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChecksum flag bit is set and CHECKSUM field value is empty")
	}
	spec.Latest.HeaderSetChecksum(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumChecksum flag bit is set and CHECKSUM field value is not empty")
	}
	spec.Latest.HeaderRemoveFlag(header, uint64(DatumChecksum))
	if spec.Latest.HeaderHasFlag(header, uint64(DatumChecksum)) {
		t.Error("expected to have DatumChecksum flag bit not set")
	}

	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumChecksum flag bit is not set and CHECKSUM field value is not empty")
	}
}

func TestHeaderFieldCompressionAlgorithm(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumCompressed))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumCompressed flag bit is set and COMPRESSION ALGORITHM field value is empty")
	}
	spec.Latest.HeaderSetCompression(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumCompressed flag bit is set and COMPRESSION ALGORITHM field value is not empty")
	}
	spec.Latest.HeaderRemoveFlag(header, uint64(DatumCompressed))
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumCompressed flag bit is not set and COMPRESSION ALGORITHM field value is not empty")
	}
}

func TestHeaderFieldEncryptionAlgorithm(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumEncrypted))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumEncrypted flag bit is set and ENCRYPTION ALGORITHM field value is empty")
	}
	spec.Latest.HeaderSetEncryption(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumEncrypted flag bit is set and ENCRYPTION ALGORITHM field value is not empty")
	}
	spec.Latest.HeaderRemoveFlag(header, uint64(DatumEncrypted))
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumEncrypted flag bit is not set and ENCRYPTION ALGORITHM field value is not empty")
	}
}

func TestHeaderFieldSignatureType(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumSigned))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is set and SIGNATURE TYPE field value is empty")
	}
	spec.Latest.HeaderSetSignatureType(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumSigned flag bit is set and SIGNATURE TYPE field value is set")
	}

	spec.Latest.HeaderRemoveFlag(header, uint64(DatumSigned))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is not set and SIGNATURE TYPE field value is set")
	}
}

func TestHeaderFieldSignatureSize(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetSignatureSize(header, 1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is not set and SIGNATURE SIZE field value is not empty")
	}

	spec.Latest.HeaderSetFlag(header, uint64(DatumSigned))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumSigned flag bit is set and SIGNATURE SIZE field value is set, but SIGNATURE TYPE is not set")
	}
	spec.Latest.HeaderSetSignatureType(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumSigned flag bit is set and both SIGNATURE TYPE and SIGNATURE SIZE field values are set")
	}
}

func TestHeaderFieldMetadataType(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetFlag(header, uint64(DatumMetadata))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is set and METADATA SPEC field value is empty")
	}
	spec.Latest.HeaderSetMetadataSpec(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumMetadata flag bit is set and METADATA SPEC field value is set")
	}

	spec.Latest.HeaderRemoveFlag(header, uint64(DatumMetadata))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is not set and METADATA SPEC field value is set")
	}
}

func TestHeaderFieldMetadataSize(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
	spec.Latest.HeaderSetMetadataSize(header, 1)
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is not set and METADATA SIZE field value is not empty")
	}

	spec.Latest.HeaderSetFlag(header, uint64(DatumMetadata))
	if HasValidHeader(header) {
		t.Errorf("Header MUST be invalid when DatumMetadata flag bit is set and METADATA SIZE field value is set, but METADATA SPEC is not set")
	}
	spec.Latest.HeaderSetMetadataSpec(header, 1)
	if !HasValidHeader(header) {
		t.Errorf("Header MUST be valid when DatumMetadata flag bit is set and both METADATA SPEC and METADATA SIZE field values are set")
	}
}

func TestHeaderFieldDelimiter(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()
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
			spec.Latest.HeaderSetMagicAndVersion(header)
		case 14:
			spec.Latest.HeaderSetFlag(header, uint64(DatumDraft))
		case HeaderSize:
			spec.Latest.HeaderSetDelimiter(header)
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
	spec.Latest.HeaderSetMagicAndVersion(header)

	var flags uint64
	flags = spec.Latest.HeaderRemoveFlag(header, uint64(DatumDraft))
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid when no flags are set, flags: %d header: %v", flags, header)
	}
	flags = spec.Latest.HeaderSetFlag(header, uint64(DatumEmpty))
	spec.Latest.HeaderSetTimestamp(header, MagicDate-1) // invalid date
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid setting DatumEmpty and Timestamp(MagicDate-1), flags: %d header: %v", flags, header)
	}

	// set minimum valid timestamp
	spec.Latest.HeaderSetTimestamp(header, MagicDate) // valid date
	if !HasValidHeader(header) {
		t.Errorf("expected header to be valid setting DatumEmpty and Timestamp(MagicDate), flags: %d header: %v", flags, header)
	}
	// Fully featured header
	fullHeader := spec.Latest.NewMinimalValidHeader()
	if !HasValidHeader(fullHeader) {
		t.Errorf("expected header to be valid setting from test.newFullValidHeader header: %v", fullHeader)
	}
}

func TestCompromizedData(t *testing.T) {
	header := spec.Latest.NewMinimalValidHeader()

	if !HasValidHeader(header) {
		t.Errorf("expected header to be valid %v", header)
	}

	spec.Latest.HeaderSetFlag(header, uint64(DatumCompromised))
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid after setting flag bit 2048, header: %v", header)
	}
}

func TestSpecV1_TestdataHeaders(t *testing.T) {
	for name, isValid := range spec.Latest.TestFiles {
		testdata := filepath.Join("tests/spec/testdata/v1", name)
		if _, err := os.Stat(testdata); err != nil {
			t.Errorf("testdata: %s %s", name, err.Error())
			continue
		}
		file, err := os.Open(testdata)
		if err != nil {
			t.Error(err)
		}
		defer file.Close()

		headerb := make([]byte, spec.Latest.HeaderSize, spec.Latest.HeaderSize)
		if _, err := file.Read(headerb); err != nil {
			t.Error(err)
		}
		if HasValidHeader(headerb) != isValid {
			t.Errorf("expected HasValidHeader to return %t when validating %s", isValid, testdata)
		}
	}
}

func TestSpecV1_DecodeHeader_ValidMinimalHeader(t *testing.T) {
	head, err := os.Open("tests/spec/testdata/v1/valid-header-minimal.cdt")
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
	head, err := os.Open("tests/spec/testdata/v1/valid-header-full-featured.cdt")
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
	if Time(h.Timestamp).IsZero() {
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

func TestTimestamp(t *testing.T) {
	var in uint64 = 1234567890
	got := Time(in).UTC().Format(time.RFC3339Nano)
	want := "1970-01-01T00:00:01.23456789Z"
	if got != want {
		t.Errorf("expected Time(%d) return time.Time %s got %s", in, want, got)
	}
}
