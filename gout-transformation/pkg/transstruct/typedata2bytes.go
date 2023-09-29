package transstruct

import (
	"bytes"
	"encoding/binary"
)

/****************************Data2Byte***************************************/

func getBoolByte(val bool) byte {
	if val {
		return byte(1)
	}
	return byte(0)
}

func getUint8Byte(val uint8) byte {
	return byte(val)
}

func getUint16Byte(val uint16) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getUint32Byte(val uint32) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getUint64Byte(val uint64) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getUintByte(val uint) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getInt8Byte(val int8) byte {
	return byte(val)
}

func getInt16Byte(val int16) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getInt32Byte(val int32) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getInt64Byte(val int64) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getIntByte(val int) []byte {
	var buf = make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(val))
	return buf
}

func getFloat32Byte(val float32) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getFloat64Byte(val float64) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, val)
	return bytesBuffer.Bytes()
}

func getStringByte(val string) []byte {
	return []byte(val)
}
