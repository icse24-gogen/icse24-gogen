package transstruct

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

func struct2Byte(ptr unsafe.Pointer, tp reflect.Type) ([]byte, int) {
	numOfTerm := 0 //number of terms in lenconfig belonging to this struct

	data := make([]byte, 0)
	fnum := tp.NumField()
	for i := 0; i < fnum; i++ {
		tpSubfield := tp.Field(i)
		if tpSubfield.Type.Kind() == reflect.Struct {
			tmpbyte, tmpint := struct2Byte(unsafe.Pointer(uintptr(ptr)+tpSubfield.Offset), tpSubfield.Type)
			data = append(data, tmpbyte...)
			numOfTerm += tmpint
			continue
		}
		switch tpSubfield.Type.Kind() {
		case reflect.Bool:
			valptr := (*bool)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getBoolByte(*valptr))
			config[lenindex] = append(config[lenindex], "bool", "1")
			lenindex++
			numOfTerm++
		case reflect.Uint8:
			valptr := (*uint8)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getUint8Byte(*valptr))
			config[lenindex] = append(config[lenindex], "uint8", "1")
			lenindex++
			numOfTerm++
		case reflect.Uint16:
			valptr := (*uint16)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getUint16Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "uint16", "2")
			lenindex++
			numOfTerm++
		case reflect.Uint32:
			valptr := (*uint32)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getUint32Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "uint32", "4")
			lenindex++
			numOfTerm++
		case reflect.Uint64:
			valptr := (*uint64)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getUint64Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "uint64", "8")
			lenindex++
			numOfTerm++
		case reflect.Uint:
			valptr := (*uint)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getUintByte(*valptr)...)
			config[lenindex] = append(config[lenindex], "uint", "8")
			lenindex++
			numOfTerm++
		case reflect.Int8:
			valptr := (*int8)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getInt8Byte(*valptr))
			config[lenindex] = append(config[lenindex], "int8", "1")
			lenindex++
			numOfTerm++
		case reflect.Int16:
			valptr := (*int16)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getInt16Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "int16", "2")
			lenindex++
			numOfTerm++
		case reflect.Int32:
			valptr := (*int32)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getInt32Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "int32", "4")
			lenindex++
			numOfTerm++
		case reflect.Int64:
			valptr := (*int64)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getInt64Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "int64", "8")
			lenindex++
			numOfTerm++
		case reflect.Int:
			valptr := (*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getIntByte(*valptr)...)
			config[lenindex] = append(config[lenindex], "int", "8")
			lenindex++
			numOfTerm++

		case reflect.Float32:
			valptr := (*float32)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getFloat32Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "float32", "4")
			lenindex++
			numOfTerm++
		case reflect.Float64:
			valptr := (*float64)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			data = append(data, getFloat64Byte(*valptr)...)
			config[lenindex] = append(config[lenindex], "float64", "8")
			lenindex++
			numOfTerm++

		case reflect.String:
			valptr := (*string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			if strings.Count(*valptr, "")-1 == 0 {
				*valptr = getDefaultString()
			}
			data = append(data, getStringByte(*valptr)...)
			config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count(*valptr, "")-1))
			lenindex++
			numOfTerm++

		case reflect.Slice:
			// DONE :get its lenth
			sliceLen := *(*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset + 8))
			subtype := typename[tpSubfield.Type.Elem().Kind()]
			if subtype == "" {
				subtype = "unknown"
			}
			if sliceLen == 0 {
				config[lenindex] = append(config[lenindex], "slice", strconv.Itoa(defaultSliceLen), subtype)
			} else {
				config[lenindex] = append(config[lenindex], "slice", strconv.Itoa(sliceLen), subtype)
			}
			sliceIndex := lenindex
			lenindex++
			numOfTerm++
			switch tpSubfield.Type.Elem().Kind() {
			case reflect.Int:
				valptr := (*[]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
				for i := 0; i < sliceLen; i++ {
					data = append(data, getIntByte((*valptr)[i])...)
					config[lenindex] = append(config[lenindex], "int", "8")
					lenindex++
					numOfTerm++
				}
				if sliceLen == 0 {
					for i := 0; i < defaultSliceLen; i++ {
						data = append(data, getIntByte(0)...)
						config[lenindex] = append(config[lenindex], "int", "8")
						lenindex++
						numOfTerm++
					}
				}
			case reflect.Int32:
				valptr := (*[]int32)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
				for i := 0; i < sliceLen; i++ {
					data = append(data, getInt32Byte((*valptr)[i])...)
					config[lenindex] = append(config[lenindex], "int32", "4")
					lenindex++
					numOfTerm++
				}
				if sliceLen == 0 {
					for i := 0; i < defaultSliceLen; i++ {
						data = append(data, getInt32Byte(0)...)
						config[lenindex] = append(config[lenindex], "int32", "8")
						lenindex++
						numOfTerm++
					}
				}
			case reflect.Uint8:
				valptr := (*[]uint8)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
				for i := 0; i < sliceLen; i++ {
					data = append(data, byte((*valptr)[i]))
					config[lenindex] = append(config[lenindex], "uint8", "1")
					lenindex++
					numOfTerm++
				}
				if sliceLen == 0 {
					for i := 0; i < defaultSliceLen; i++ {
						data = append(data, byte(0))
						config[lenindex] = append(config[lenindex], "uint8", "1")
						lenindex++
						numOfTerm++
					}
				}
			case reflect.String:
				valptr := (*[]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
				for i := 0; i < sliceLen; i++ {
					data = append(data, getStringByte((*valptr)[i])...)
					config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count((*valptr)[i], "")-1))
					lenindex++
					numOfTerm++
				}
				if sliceLen == 0 {
					for i := 0; i < defaultSliceLen; i++ {
						data = append(data, getStringByte(getDefaultString())...)
						config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count(getDefaultString(), "")-1))
						lenindex++
						numOfTerm++
					}
				}

			//DONE to correct pointer submit
			case reflect.Struct:
				for i := 0; i < sliceLen; i++ {
					valptr := *(*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					tmpbyte, tmpint := struct2Byte(unsafe.Pointer(uintptr(valptr+int(tpSubfield.Type.Elem().Size())*i)), tpSubfield.Type.Elem())
					data = append(data, tmpbyte...)
					config[sliceIndex] = append(config[sliceIndex], strconv.Itoa(tmpint))
					numOfTerm += tmpint
				}
				if sliceLen == 0 {
					for i := 0; i < defaultSliceLen; i++ {
						tmpptr := reflect.New(tpSubfield.Type.Elem())
						tmpbyte, tmpint := struct2Byte(unsafe.Pointer(tmpptr.Pointer()), tpSubfield.Type.Elem())
						data = append(data, tmpbyte...)
						config[sliceIndex] = append(config[sliceIndex], strconv.Itoa(tmpint))
						numOfTerm += tmpint
					}
				}

			default:
				fmt.Println("unknown elem type: ", tpSubfield.Type.Elem().Kind())
			}

		case reflect.Map:
			// TODO(jx) to implememt default value for empty map
			switch tpSubfield.Type.Key().Kind() { // type of key
			case reflect.Int:
				switch tpSubfield.Type.Elem().Kind() { //type of value
				case reflect.Int:
					valptr := (*map[int]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					mapsize := len(*valptr)
					config[lenindex] = append(config[lenindex],
						"map[int]int", strconv.Itoa(mapsize),
						typename[tpSubfield.Type.Key().Kind()],
						typename[tpSubfield.Type.Elem().Kind()])
					lenindex++
					numOfTerm++
					//Done add all elem into data according to mapsize
					for k := range *valptr {
						data = append(data, getIntByte(k)...)
						config[lenindex] = append(config[lenindex], "int", "8")
						lenindex++
						numOfTerm++
						data = append(data, getIntByte((*valptr)[k])...)
						config[lenindex] = append(config[lenindex], "int", "8")
						lenindex++
						numOfTerm++
					}
					//fmt.Println(*valptr)
				case reflect.String:
					valptr := (*map[int]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					mapsize := len(*valptr)
					config[lenindex] = append(config[lenindex], "map[int]string", strconv.Itoa(mapsize), typename[tpSubfield.Type.Key().Kind()], typename[tpSubfield.Type.Elem().Kind()])
					lenindex++
					numOfTerm++
					for k := range *valptr {
						data = append(data, getIntByte(k)...)
						config[lenindex] = append(config[lenindex], "int", "8")
						lenindex++
						numOfTerm++
						data = append(data, getStringByte((*valptr)[k])...)
						config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count((*valptr)[k], "")-1))
						lenindex++
						numOfTerm++
					}
				default:
					fmt.Println("unknow value type", tpSubfield.Type.Elem().Kind())
				}

			case reflect.String:
				switch tpSubfield.Type.Elem().Kind() { //type of value
				case reflect.Int:
					valptr := (*map[string]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					mapsize := len(*valptr)
					config[lenindex] = append(config[lenindex], "map[string]int", strconv.Itoa(mapsize), typename[tpSubfield.Type.Key().Kind()], typename[tpSubfield.Type.Elem().Kind()])
					lenindex++
					numOfTerm++
					for k := range *valptr {
						data = append(data, getStringByte(k)...)
						config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count(k, "")-1))
						lenindex++
						numOfTerm++
						data = append(data, getIntByte((*valptr)[k])...)
						config[lenindex] = append(config[lenindex], "int", "8")
						lenindex++
						numOfTerm++
					}
				case reflect.String:
					valptr := (*map[string]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					mapsize := len(*valptr)
					config[lenindex] = append(config[lenindex], "map[string]string", strconv.Itoa(mapsize), typename[tpSubfield.Type.Key().Kind()], typename[tpSubfield.Type.Elem().Kind()])
					lenindex++
					numOfTerm++
					for k := range *valptr {
						data = append(data, getStringByte(k)...)
						config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count(k, "")-1))
						lenindex++
						numOfTerm++
						data = append(data, getStringByte((*valptr)[k])...)
						config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count((*valptr)[k], "")-1))
						lenindex++
						numOfTerm++
					}

				default:
					fmt.Println("unknow value type", tpSubfield.Type.Elem().Kind())
				}

			default:
				fmt.Println("unknow key type", tpSubfield.Type.Key())

			}
		case reflect.Ptr:
			ptraddr := (*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			//config[lenindex] = int(GetBoolByte(ptrnotnil))
			//lenindex++

			ptrtype := tpSubfield.Type.Elem()
			switch ptrtype.Kind() {
			case reflect.String:
				realptr := (*string)(unsafe.Pointer(uintptr(*ptraddr)))
				if realptr == nil {
					s := getDefaultString()
					realptr = &s
				}
				val := *realptr
				data = append(data, getStringByte(val)...)
				config[lenindex] = append(config[lenindex], "string", strconv.Itoa(strings.Count((val), "")-1))
				lenindex++
				numOfTerm++
			case reflect.Int:
				realptr := (*int)(unsafe.Pointer(uintptr(*ptraddr)))
				if realptr == nil {
					n := 0
					realptr = &n
				}
				val := *realptr
				data = append(data, getIntByte(val)...)
				config[lenindex] = append(config[lenindex], "int", "8")
				lenindex++
				numOfTerm++
			}

		default:
			fmt.Println("\nunknown type: ", tpSubfield.Type.Kind())
		}
	}

	return data, numOfTerm
}
