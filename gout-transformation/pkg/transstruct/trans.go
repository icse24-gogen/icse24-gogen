package transstruct

import (
	"reflect"
	"unsafe"
)

// getFuzzData is the top api for fuzz entries.
// Initobj is the init input for the Fuzz func, and data is the byte stream get from backend of Fuzz
// This Func returns an object translated from data with the same type as the initobj
func getFuzzData(initobj interface{}, data []byte) interface{} {

	switch obj := initobj.(type) {
	case string:
		input := struct {
			s string
		}{
			s: initobj.(string),
		}
		byte2Struct(unsafe.Pointer(&input), reflect.TypeOf(input), data)
		return input.s
	case []byte:
		input := struct {
			s []byte
		}{
			s: initobj.([]byte),
		}
		byte2Struct(unsafe.Pointer(&input), reflect.TypeOf(input), data)
		return input.s
	default:
		//TODO(jx): distinguish pointer and struct
		//fmt.Println(reflect.TypeOf(obj))
		byte2Struct(unsafe.Pointer((uintptr(*(*int)(unsafe.Pointer(uintptr(int(uintptr(unsafe.Pointer(&initobj))) + 8)))))),
			reflect.TypeOf(obj), data)
		return initobj
	}
}

func getBool(data []byte) (bool, []byte) {
	lenindex++
	return bytesToBool(data), data[1:]
}

func getUint8(data []byte) (uint8, []byte) {
	lenindex++
	// keeping lenindex responding with items in lenconfig is necessary
	// to split strings correctly.
	return bytesToUint8(data), data[1:]
}

func getUint16(data []byte) (uint16, []byte) {
	lenindex++
	return bytesToUint16(data), data[2:]
}

func getUint32(data []byte) (uint32, []byte) {
	lenindex++
	return bytesToUint32(data), data[4:]
}

func getUint64(data []byte) (uint64, []byte) {
	lenindex++
	return bytesToUint64(data), data[8:]
}

func getInt8(data []byte) (int8, []byte) {
	lenindex++ // lenindex++ seems useless in typedata to byte
	return bytesToInt8(data), data[1:]
}

func getInt16(data []byte) (int16, []byte) {
	lenindex++
	return bytesToInt16(data), data[2:]
}

func getInt32(data []byte) (int32, []byte) {
	lenindex++
	return bytesToInt32(data), data[4:]
}

func getInt64(data []byte) (int64, []byte) {
	lenindex++
	return bytesToInt64(data), data[8:]
}

func getInt(data []byte) (int, []byte) {
	lenindex++
	return bytesToInt(data), data[8:]

}

func getUint(data []byte) (uint, []byte) {
	lenindex++
	return bytesToUint(data), data[8:]
}

func getFloat32(data []byte) (float32, []byte) {
	lenindex++
	return bytesToFloat32(data), data[4:]
}

func getFloat64(data []byte) (float64, []byte) {
	lenindex++
	return bytesToFloat64(data), data[8:]
}

func getString(data []byte) (string, []byte) {
	var length int
	length, _ = getLenFromConfig()

	return bytesToString(data, length), data[length:]
}

func getBytes(data []byte) ([]byte, []byte) {
	var length int
	length, _ = getLenFromConfig()
	return data[:length], data[length:]
}

func getDefaultString() string {
	var res string = ""
	for i := 0; i < defaultStringLen; i++ {
		res += "a"
	}
	return res
}

func getSlice(tp reflect.Type, data []byte) (reflect.Value, []byte) {
	// now i have a strategy that:
	//I use the fixed lenth of byte corresponding to the type to gen its value
	//and repeat it for a random times, the random time is decided by the first byte now
	var slicelen int

	//slicelen = int(data[0])
	slicelen, _ = getLenFromConfig()
	if slicelen == -1 {
		return reflect.ValueOf(nil), data
	}

	tmplist := reflect.MakeSlice(reflect.SliceOf(tp), 0, 0)
	var val interface{}

	for i := 0; i < slicelen; i++ {
		switch tp.Kind() {
		case reflect.Uint8:
			val, data = getUint8(data)
			tmplist = reflect.Append(tmplist, reflect.ValueOf(val))
		case reflect.Int:
			val, data = getInt(data)
			tmplist = reflect.Append(tmplist, reflect.ValueOf(val))
		//case reflect.Float64:
		//	val, data = GetFloat64(data)
		//	tmplist = reflect.Append(tmplist, reflect.ValueOf(val))
		case reflect.String:
			val, data = getString(data)
			tmplist = reflect.Append(tmplist, reflect.ValueOf(val))
		case reflect.Struct:
			tmpptr := reflect.New(tp)
			data = byte2Struct(unsafe.Pointer(tmpptr.Pointer()), tp, data)
			tmplist = reflect.Append(tmplist, tmpptr.Elem())
		}
	}
	//fmt.Println("tmplist: ", tmplist)
	return tmplist, data
}
func getFixSlice(tp reflect.Type, slicelen int, data []byte) (reflect.Value, []byte) {
	tmplist := reflect.MakeSlice(reflect.SliceOf(tp), 0, 0)
	var val interface{}

	tmpptr := reflect.New(tp)
	switch tp.Kind() {
	case reflect.Int:
		val, data = getInt(data)
	case reflect.Float64:
		val, data = getFloat64(data)
	case reflect.String:
		val, data = getString(data)
	case reflect.Struct:
		data = byte2Struct(unsafe.Pointer(tmpptr.Pointer()), tp, data)
	}
	for i := 0; i < slicelen; i++ {
		if tp.Kind() == reflect.Struct {
			tmplist = reflect.Append(tmplist, tmpptr.Elem())
		} else {
			tmplist = reflect.Append(tmplist, reflect.ValueOf(val))
		}
	}
	return tmplist, data
}

func getPtr(ptr uintptr, tp reflect.Type, data []byte) []byte {
	// asign a value for ptr according to type
	switch tp.Kind() {
	case reflect.Int:
		intptr := (*int)(unsafe.Pointer(ptr))
		*intptr, data = getInt(data)
	case reflect.String:
		strptr := (*string)(unsafe.Pointer(ptr))
		*strptr, data = getString(data)
	case reflect.Struct:
		//TODO(jx): not supported in this version
		//tmpptr := reflect.New(tp)
		//data = RewriteFieldsByPtr(unsafe.Pointer(tmpptr.Pointer()), tp, data)

	}
	return data
}
