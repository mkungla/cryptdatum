// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package spec

import (
	"encoding/binary"
)

//go:generate go run spec-v1-gen.go

var V1 = Specification{
	HeaderSize:     64,
	Version:        1,
	MinimumVersion: 1,
	Magic:          [4]byte{0xA7, 0xF6, 0xE5, 0xD4},
	Delimiter:      [2]byte{0xA6, 0xE5},
	MagicDate:      1652155382000000001,
	TestFiles:      make(map[string]bool),
}

func init() {
	V1.TestFiles["valid-header-minimal.cdt"] = true
	V1.TestFiles["valid-header-full-featured.cdt"] = true
	V1.TestFiles["invalid-header-full-featured.cdt"] = false
}

func (s Specification) NewMinimalValidHeader() []byte {
	header := make([]byte, s.HeaderSize, s.HeaderSize)
	s.HeaderSetMagicAndVersion(header)
	s.HeaderSetFlag(header, uint64(4)) // DatumEmpty
	s.HeaderSetTimestamp(header, uint64(s.MagicDate))
	s.HeaderSetDelimiter(header)

	return header
}

func (s Specification) HeaderSetMagicAndVersion(data []byte) {
	copy(data[:4], s.Magic[:])
	binary.LittleEndian.PutUint16(data[4:6], s.Version) // version
}

func (s Specification) HeaderSetDelimiter(data []byte) {
	copy(data[s.HeaderSize-len(s.Delimiter):s.HeaderSize], s.Delimiter[:])
}

func (s Specification) HeaderSetFlag(data []byte, flag uint64) uint64 {
	bits := binary.LittleEndian.Uint64(data[6:14])
	if bits&uint64(flag) != 0 {
		return bits // already has a flag
	}
	bits |= uint64(flag)
	binary.LittleEndian.PutUint64(data[6:14], bits)
	return bits
}

func (s Specification) HeaderHasFlag(data []byte, flag uint64) bool {
	bits := binary.LittleEndian.Uint64(data[6:14])
	return bits&uint64(flag) != 0
}

func (s Specification) HeaderRemoveFlag(data []byte, flag uint64) uint64 {
	bits := binary.LittleEndian.Uint64(data[6:14])
	if bits&uint64(flag) == 0 {
		return bits // does not have a flag
	}
	flags := bits &^ uint64(flag)
	binary.LittleEndian.PutUint64(data[6:14], flags)
	return flags
}

func (s Specification) HeaderSetTimestamp(data []byte, ts uint64) {
	binary.LittleEndian.PutUint64(data[14:22], ts)
}

func (s Specification) HeaderSetOPC(data []byte, opc uint32) {
	binary.LittleEndian.PutUint32(data[22:26], opc)
}

func (s Specification) HeaderSetChunkSize(data []byte, size uint16) {
	binary.LittleEndian.PutUint16(data[26:28], size)
}

func (s Specification) HeaderSetNetworkID(data []byte, net uint32) {
	binary.LittleEndian.PutUint32(data[28:32], net)
}

func (s Specification) HeaderSetSize(data []byte, size uint64) {
	binary.LittleEndian.PutUint64(data[32:40], size)
}

func (s Specification) HeaderGetSize(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data[32:40])
}

func (s Specification) HeaderSetChecksum(data []byte, checksum uint64) {
	binary.LittleEndian.PutUint64(data[40:48], checksum)
}

func (s Specification) HeaderSetCompression(data []byte, compalg uint16) {
	binary.LittleEndian.PutUint16(data[48:50], compalg)
}

func (s Specification) HeaderSetEncryption(data []byte, encalg uint16) {
	binary.LittleEndian.PutUint16(data[50:52], encalg)
}

func (s Specification) HeaderSetSignatureType(data []byte, styp uint16) {
	binary.LittleEndian.PutUint16(data[52:54], styp)
}

func (s Specification) HeaderSetSignatureSize(data []byte, size uint16) {
	binary.LittleEndian.PutUint16(data[54:56], size)
}

func (s Specification) HeaderSetMetadataSpec(data []byte, size uint16) {
	binary.LittleEndian.PutUint16(data[56:58], size)
}

func (s Specification) HeaderSetMetadataSize(data []byte, size uint32) {
	binary.LittleEndian.PutUint32(data[58:62], size)
}
