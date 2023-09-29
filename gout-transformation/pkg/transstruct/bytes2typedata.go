package transstruct

import (
	"bytes"
	"encoding/binary"
	"math"
)

/****************************************/
func bytesToBool(buf []byte) bool {
	return buf[0] != 0
}

func bytesToUint8(buf []byte) uint8 {
	var tmp uint8
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}

func bytesToUint16(buf []byte) uint16 {
	var tmp uint16
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}

func bytesToUint32(buf []byte) uint32 {
	var tmp uint32
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}
func bytesToUint64(buf []byte) uint64 {
	var tmp uint64
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}

func bytesToInt8(buf []byte) int8 {
	var tmp int8
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}
func bytesToInt16(buf []byte) int16 {
	var tmp int16
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}

func bytesToInt32(buf []byte) int32 {
	var tmp int32
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}

func bytesToInt64(buf []byte) int64 {
	var tmp int64
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return tmp
}

func bytesToInt(buf []byte) int {
	var tmp int64
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return int(tmp)
}

func bytesToUint(buf []byte) uint {
	var tmp uint64
	binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, &tmp)
	return uint(tmp)
}

func bytesToFloat32(bytes []byte) float32 {
	bits := binary.LittleEndian.Uint32(bytes)
	return math.Float32frombits(bits)
}
func bytesToFloat64(bytes []byte) float64 {
	bits := binary.LittleEndian.Uint64(bytes)
	return math.Float64frombits(bits)
}

func bytesToString(buf []byte, len int) string {
	return string(buf[0:len])
}
