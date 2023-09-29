package transstruct

// import "hwprojects/tools/byte2struct"
import (
	"fmt"
	"reflect"
	"unsafe"
)

func byte2Struct(ptr unsafe.Pointer, tp reflect.Type, data []byte) []byte {
	if len(data) < 1000 {
		data = bytesCombine1000(data)
	}
	// DEBUG
	//env := os.Getenv("AFL_LENCONFIG")
	//fmt.Println(env)
	//
	//if env != "" {
	//	fmt.Println("env not empty")
	//	argid, err := strconv.Atoi(env)
	//	fmt.Println(argid)
	//	fmt.Println(os.Args)
	//	if err == nil {
	//		fmt.Println(os.Args[argid])
	//	} else {
	//		fmt.Println(err)
	//	}
	//}
	// END DEBUG

	//listlen := 5 // define the lenth of assigned list
	fnum := tp.NumField()
	for i := 0; i < fnum; i++ {
		tpSubfield := tp.Field(i)
		if tpSubfield.Type.Kind() == reflect.Struct {
			data = byte2Struct(unsafe.Pointer(uintptr(ptr)+tpSubfield.Offset), tpSubfield.Type, data)
			continue
		}

		switch tpSubfield.Type.Kind() {
		case reflect.Bool:
			valptr := (*bool)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			//*valptr = false
			*valptr = int(data[0])%2 != 0
			data = data[1:]
			lenindex++

		//not implement in struct2byte yet
		case reflect.Uint8:
			valptr := (*uint8)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getUint8(data)
		case reflect.Uint16:
			valptr := (*uint16)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getUint16(data)
		case reflect.Uint32:
			valptr := (*uint32)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getUint32(data)
		case reflect.Uint64:
			valptr := (*uint64)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getUint64(data)
		case reflect.Uint:
			valptr := (*uint)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getUint(data)

		case reflect.Int8:
			valptr := (*int8)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getInt8(data)
		case reflect.Int16:
			valptr := (*int16)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getInt16(data)
		case reflect.Int32:
			valptr := (*int32)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getInt32(data)
		case reflect.Int64:
			valptr := (*int64)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getInt64(data)
		case reflect.Int:
			valptr := (*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getInt(data)

		case reflect.Float32:
			valptr := (*float32)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getFloat32(data)
		case reflect.Float64:
			valptr := (*float64)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getFloat64(data)

		case reflect.String:
			valptr := (*string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr, data = getString(data)

		case reflect.Slice:
			// DONE :get its lenth
			//sliceLen := *(*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset + 8))
			//fmt.Println("slice len is ", sliceLen)

			//tmplist := reflect.MakeSlice(reflect.SliceOf(tpSubfield.Type.Elem()), 0, 0)
			var tmplist reflect.Value
			tmplist, data = getSlice(tpSubfield.Type.Elem(), data)

			valptr := (*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			lenptr := (*int)(unsafe.Pointer(uintptr(unsafe.Pointer(valptr)) + 8))
			capptr := (*int)(unsafe.Pointer(uintptr(unsafe.Pointer(valptr)) + 16))

			if tmplist == reflect.ValueOf(nil) {
				*valptr = 0 // set a nil slice
				*lenptr = 0
				*capptr = 0

			} else {
				tmpptr := *(*int)(unsafe.Pointer(uintptr(unsafe.Pointer(&tmplist)) + 8))

				*valptr = *(*int)(unsafe.Pointer(uintptr(tmpptr)))

				*lenptr = *(*int)(unsafe.Pointer(uintptr(tmpptr) + 8))

				*capptr = *(*int)(unsafe.Pointer(uintptr(tmpptr) + 16))
			}

		case reflect.Map:
			switch tpSubfield.Type.Key().Kind() { // type of key
			case reflect.Int:
				var key int
				switch tpSubfield.Type.Elem().Kind() { //type of value
				case reflect.Int:
					mapsize, _ := getLenFromConfig()
					var val int
					valptr := (*map[int]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					*valptr = map[int]int{}
					for i := 0; i < mapsize; i++ {
						key, data = getInt(data)
						val, data = getInt(data)
						(*valptr)[key] = val
					}

				case reflect.String:
					mapsize, _ := getLenFromConfig()
					var val string
					valptr := (*map[int]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					*valptr = map[int]string{}
					for i := 0; i < mapsize; i++ {
						key, data = getInt(data)
						val, data = getString(data)
						(*valptr)[key] = val
					}
				default:
					fmt.Println("unknow value type", tpSubfield.Type.Elem().Kind())
				}

			case reflect.String:
				var key string
				//key, data = GetString(data)
				switch tpSubfield.Type.Elem().Kind() { //type of value
				case reflect.Int:
					mapsize, _ := getLenFromConfig()
					var val int
					valptr := (*map[string]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					*valptr = map[string]int{}
					for i := 0; i < mapsize; i++ {
						key, data = getString(data)
						val, data = getInt(data)
						(*valptr)[key] = val
					}
				case reflect.String:
					mapsize, _ := getLenFromConfig()
					var val string
					valptr := (*map[string]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					*valptr = map[string]string{}
					for i := 0; i < mapsize; i++ {
						key, data = getString(data)
						val, data = getString(data)
						(*valptr)[key] = val
					}
				default:
					fmt.Println("unknow value type", tpSubfield.Type.Elem().Kind())
				}

			default:
				fmt.Println("unknow key type", tpSubfield.Type.Key())
			}
		case reflect.Ptr:
			ptrtype := tpSubfield.Type.Elem()
			newptr := reflect.New(ptrtype).Pointer()
			data = getPtr(newptr, ptrtype, data)
			valptr := (*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			*valptr = int(newptr)

		//	ptrtype :=
		default:
			fmt.Println("unknow fields type:", tpSubfield.Type.Kind())
		}
	}

	return data
}
