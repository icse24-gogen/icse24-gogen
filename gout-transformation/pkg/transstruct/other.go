package transstruct

import (
	"fmt"
	"path/filepath"
	"reflect"
	"unsafe"
)

//var config []byte
//var config map[int]int // stands for the lenth of the i th var-len member
var config map[int][]string
var lenindex int = 0
var lenconfigFile = "./lenconfig"
var initcorpus = "initcorpus"
var corpusDir = "./corpus"
var tableDrivenIdx = 0
var corpusName string

var defaultStringLen int = 32
var defaultSliceLen int = 7

var typename map[reflect.Kind]string

var cache map[interface{}]interface{}

func init() {
	corpusName = filepath.Join(corpusDir, initcorpus)

	typename = make(map[reflect.Kind]string, 0)
	typename[reflect.Int] = "int"
	typename[reflect.String] = "string"
	typename[reflect.Uint8] = "uint8"
	typename[reflect.Int32] = "int32"
	typename[reflect.Struct] = "struct"

}

/********************** output APIs for debugging **********************************/
func viewFieldsByPtr(ptr unsafe.Pointer, tp reflect.Type, indent int) {
	fnum := tp.NumField()
	for i := 0; i < fnum; i++ {
		tpSubfield := tp.Field(i)
		if tpSubfield.Type.Kind() == reflect.Struct {
			viewFieldsByPtr(unsafe.Pointer(uintptr(ptr)+tpSubfield.Offset), tpSubfield.Type, indent+4)
			continue
		}

		fmtstr := fmt.Sprintf("%%%vs", indent)
		fmt.Printf(fmtstr, "")

		fmt.Printf("field %v, name %s, offset %v, type %v, size %v\t ", i, tpSubfield.Name, tpSubfield.Offset, tpSubfield.Type, tpSubfield.Type.Size())

		switch tpSubfield.Type.Kind() {
		case reflect.Bool:
			valptr := (*bool)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			fmt.Println(*valptr)
		case reflect.Int:
			valptr := (*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			//fmt.Printf("valptr: 0x%x\n", valptr)
			fmt.Println(*valptr)
		case reflect.String:
			valptr := (*string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			fmt.Println(*valptr)
		case reflect.Slice:
			// DONE :get its lenth
			sliceLen := *(*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset + 8))
			fmt.Println("slice len is ", sliceLen)

			switch tpSubfield.Type.Elem().Kind() {
			case reflect.Int:
				valptr := (*[]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
				fmt.Println(*valptr)
			case reflect.String:
				valptr := (*[]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
				fmt.Println(*valptr)
			//DONE to correct pointer submit
			case reflect.Struct:
				for i := 0; i < sliceLen; i++ {
					valptr := *(*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					viewFieldsByPtr(unsafe.Pointer(uintptr(valptr+24*i)), tpSubfield.Type.Elem(), indent+4)
				}

			default:
				fmt.Println("unknown elem type: ", tpSubfield.Type.Elem().Kind())
			}
		case reflect.Map:
			switch tpSubfield.Type.Key().Kind() { // type of key
			case reflect.Int:
				switch tpSubfield.Type.Elem().Kind() { //type of value
				case reflect.Int:
					valptr := (*map[int]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					fmt.Println(*valptr)
				case reflect.String:
					valptr := (*map[int]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					fmt.Println(*valptr)
				default:
					fmt.Println("unknow value type", tpSubfield.Type.Elem().Kind())

				}

			case reflect.String:
				switch tpSubfield.Type.Elem().Kind() { //type of value
				case reflect.Int:
					valptr := (*map[string]int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					fmt.Println(*valptr)
				case reflect.String:
					valptr := (*map[string]string)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
					fmt.Println(*valptr)
				default:
					fmt.Println("unknow value type", tpSubfield.Type.Elem().Kind())
				}

			default:
				fmt.Println("unknow key type", tpSubfield.Type.Key())

			}
		case reflect.Ptr:
			valptr := (*int)(unsafe.Pointer(uintptr(ptr) + tpSubfield.Offset))
			ptrtype := tpSubfield.Type.Elem()
			showPtr(uintptr(*valptr), ptrtype.Kind())
		default:
			fmt.Println("\nunknown type: ", tpSubfield.Type.Kind())
		}
	}
}

func showPtr(ptr uintptr, tp reflect.Kind) {
	if unsafe.Pointer(ptr) == nil {
		fmt.Println(nil)
		return
	}

	switch tp {
	case reflect.Int:
		intptr := (*int)(unsafe.Pointer(ptr))
		fmt.Println(*intptr)
	case reflect.String:
		fmt.Println(*(*string)(unsafe.Pointer(ptr)))

	}
}

/*****************************Abandoned solution********************************/
func rewriteFields(result interface{}, data []byte, totalOffset int, indent int) interface{} {

	resultptr := *(*int)(unsafe.Pointer(uintptr(unsafe.Pointer(&result)) + 8))

	if reflect.ValueOf(result).Kind() != reflect.Struct {
		return nil
	}

	tp := reflect.TypeOf(result)
	val := reflect.ValueOf(result)
	field_num := tp.NumField()
	fmtstr := fmt.Sprintf("%%%vs", indent)
	fmt.Printf(fmtstr, "")
	fmt.Println("struct name:", tp.Name())

	for i := 0; i < field_num; i++ {
		//sf := val.Field(i)
		//fmt.Println(sf)
		subField := tp.Field(i)
		subType := subField.Type.Kind()
		//
		if subType == reflect.Struct {
			_ = rewriteFields(val.Field(i).Interface(), data, totalOffset+int(subField.Offset), indent+4)
			continue
		}
		switch val.Field(i).Kind() {
		case reflect.Int:
			//fmt.Println("int")
			ptr := (*int)(unsafe.Pointer(uintptr(resultptr) + subField.Offset))
			*ptr = -1
			//*ptr = BytesToInt(data)
			//data = data[8:]

		case reflect.String:
			//fmt.Println("string")
			ptr := (*string)(unsafe.Pointer(uintptr(resultptr) + subField.Offset))
			//fmt.Printf("ptr: 0x%x, *ptr: 0x%x\n", uintptr(unsafe.Pointer(ptr)), *ptr)
			*ptr = "hacked"
			//*ptr = BytesToString(data, 10)
			//data = data[10:]
		default:
			fmt.Println("unknown type:", val.Field(i).Kind())

		}
	}

	//fmt.Println(result)
	return result
}

func viewStructs(result interface{}, totalOffset int, indent int) {
	//resultptr := *(*int)(unsafe.Pointer(uintptr(unsafe.Pointer(&result)) + 8))
	if reflect.ValueOf(result).Kind() != reflect.Struct {
		return
	}
	tp := reflect.TypeOf(result)
	val := reflect.ValueOf(result)
	field_num := tp.NumField()
	//fmtstr := fmt.Sprintf("%%%vs", indent)
	//fmt.Printf(fmtstr, "")
	//fmt.Println("struct name:", tp.Name())
	for i := 0; i < field_num; i++ {
		subField := tp.Field(i)
		subType := subField.Type.Kind()
		if subType == reflect.Struct {
			viewStructs(val.Field(i).Interface(), totalOffset+int(subField.Offset), indent+4)
			continue
		}
		//fmtstr := fmt.Sprintf("%%%vs", indent)
		//fmt.Printf(fmtstr, "")
		//fmt.Println("field =", i,
		//	"; name =", subField.Name,
		//	"; type =", subType,
		//	"; value =", val.Field(i),
		//	"; len =", subField.Type.Size(),
		//	"; offset =", totalOffset+int(subField.Offset))
	}
}
