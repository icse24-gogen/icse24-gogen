package transstruct

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

//SetFuzzData is called in generated fuzz drivers to prepare the data and lenconfig
func SetFuzzData(data []byte) {
	cache = make(map[interface{}]interface{}) // clear map for each loop of fuzz
	genCorpus = ifGenInitCorpus()
	// if len(data) == 0 {
	// 	genCorpus = true
	// }
	if genCorpus {
		lenindex = 0
		config = make(map[int][]string)
		corpusBytes = make([]byte, 0)

	} else {
		// data passed from fuzz driver
		corpusBytes = data
		lenindex = 0
		if len(corpusBytes) < 10000 {
			corpusBytes = bytesCombine1000(corpusBytes)
		}

		//use the default lenconfig tmp
		jsonByte, err := ioutil.ReadFile(lenconfigFile)
		if err != nil {
			pwd, _ := os.Getwd()
			panic("open config file failed > " + pwd + "/" + lenconfigFile)
		}
		if err = json.Unmarshal(jsonByte, &config); err != nil {
			panic("lenconfig json unmarshal failed")
		}
	}

}

//General Fuzz API
func GetFuzzData(obj interface{}) interface{} {
	//WARNNING: GetFuzzData and APIs like GetInt cannot appear in the same fuzz driver
	//FIXME: if third arg is "lenconfig", gen initcorpus only
	if ifGenInitCorpus() {
		GenerateInitCorpus(obj)
		return obj
	}
	return getFuzzData(obj, corpusBytes) // fetch from `ioutil.ReadFile(os.Args[3])`
}

func GetFuzzDataWithoutInit(initobj interface{}, data []byte) interface{} {
	if !fileExists("./corpus/initcorpus") {
		GenerateInitCorpus(initobj)
	}
	return getFuzzData(initobj, data)
}

func GenerateInitCorpus(initobj interface{}) []byte {
	var initbyte []byte
	switch obj := initobj.(type) {
	case string:
		input := struct {
			s string
		}{
			s: initobj.(string),
		}
		initbyte, _ = struct2Byte(unsafe.Pointer(&input), reflect.TypeOf(input))
	case []byte:
		input := struct {
			s []byte
		}{
			s: initobj.([]byte),
		}
		initbyte, _ = struct2Byte(unsafe.Pointer(&input), reflect.TypeOf(input))
	default:
		initbyte, _ = struct2Byte(unsafe.Pointer((uintptr(*(*int)(unsafe.Pointer(uintptr(int(uintptr(unsafe.Pointer(&initobj))) + 8)))))), reflect.TypeOf(obj))
	}
	corpusBytes = append(corpusBytes, initbyte...)
	saveCorpus()

	return initbyte
}

var genCorpus bool // the first time to run, generate init corpus and return the orig value
var corpusBytes []byte

//RefreshConfig is only called in backend, before fuzz driver is called during each loop
func ReFreshConfig() {
	genCorpus = ifGenInitCorpus()
	lenindex = 0
	if genCorpus {
		config = make(map[int][]string)
		corpusBytes = make([]byte, 0)
	} else {
		initCorpus, err := ioutil.ReadFile(os.Args[3])
		if err != nil {
			panic(err)
		}
		if env := os.Getenv("__AFL_LENCONFIG"); env != "" {
			argid, err := strconv.Atoi(env)
			if err == nil {
				lenconfigFile = os.Args[argid]
			}
		} else {
			fmt.Println("__AFL_LENCONFIG is not set\nThe default value 'lenconfig will be used.'")
		}
		corpusBytes = initCorpus
		jsonByte, err := ioutil.ReadFile(lenconfigFile)
		if err != nil {
			pwd, _ := os.Getwd()
			panic("open config file failed > " + pwd + "/" + lenconfigFile)
		}
		if err = json.Unmarshal(jsonByte, &config); err != nil {
			panic("lenconfig json unmarshal failed")
		}
	}
}

func GetBool(flag bool) bool {
	var val bool
	if genCorpus {
		corpusBytes = append(corpusBytes, getBoolByte(flag))
		addConfig([]string{"bool", "1"})
		saveCorpus()
		return flag
	} else {
		val, corpusBytes = getBool(corpusBytes)
		return val
	}
}

func GetUint8(num uint8) uint8 {
	var val uint8
	if genCorpus {
		// generate init corpus and return the orig value
		corpusBytes = append(corpusBytes, getUint8Byte(num))
		addConfig([]string{"uint8", "1"})
		saveCorpus()
		return num
	} else {
		// get mutated data from corpusBytes
		val, corpusBytes = getUint8(corpusBytes)
		return val
	}
}

func GetUint16(num uint16) uint16 {
	var val uint16
	if genCorpus {
		corpusBytes = append(corpusBytes, getUint16Byte(num)...)
		addConfig([]string{"uint16", "2"})
		saveCorpus()
		return num
	} else {
		val, corpusBytes = getUint16(corpusBytes)
		return val
	}
}

func GetUint32(num uint32) uint32 {
	var val uint32
	if genCorpus {
		corpusBytes = append(corpusBytes, getUint32Byte(num)...)
		addConfig([]string{"uint32", "4"})
		saveCorpus()
		return num
	} else {
		val, corpusBytes = getUint32(corpusBytes)
		return val
	}
}

func GetUint64(num uint64) uint64 {
	var val uint64
	if genCorpus {
		corpusBytes = append(corpusBytes, getUint64Byte(num)...)
		addConfig([]string{"uint64", "8"})
		saveCorpus()
		return num
	} else {
		val, corpusBytes = getUint64(corpusBytes)
		return val
	}
}

func GetInt8(num int8) int8 {
	var val int8
	if genCorpus {
		// generate init corpus and return the orig value
		corpusBytes = append(corpusBytes, getInt8Byte(num))
		addConfig([]string{"int8", "1"})
		saveCorpus()
		return num
	} else {
		// get mutated data from corpusBytes
		val, corpusBytes = getInt8(corpusBytes)
		return val
	}
}

func GetInt16(num int16) int16 {
	var val int16
	if genCorpus {
		corpusBytes = append(corpusBytes, getInt16Byte(num)...)
		addConfig([]string{"int16", "2"})
		saveCorpus()
		return num
	} else {
		val, corpusBytes = getInt16(corpusBytes)
		return val
	}
}

func GetInt32(num int32) int32 {
	var val int32
	if genCorpus {
		corpusBytes = append(corpusBytes, getInt32Byte(num)...)
		addConfig([]string{"int32", "4"})
		saveCorpus()
		return num
	} else {
		val, corpusBytes = getInt32(corpusBytes)
		return val
	}
}

func GetInt64(num int64) int64 {
	var val int64
	if genCorpus {
		corpusBytes = append(corpusBytes, getInt64Byte(num)...)
		addConfig([]string{"int64", "8"})
		saveCorpus()
		return num
	} else {
		val, corpusBytes = getInt64(corpusBytes)
		return val
	}
}

func GetInt(num int) int {
	var val int
	if genCorpus {
		corpusBytes = append(corpusBytes, getIntByte(num)...)
		addConfig([]string{"int", "8"})
		saveCorpus()
		return num
	}
	val, corpusBytes = getInt(corpusBytes)
	return val
}

func GetUint(num uint) uint {
	var val uint
	if genCorpus {
		corpusBytes = append(corpusBytes, getUintByte(num)...)
		addConfig([]string{"uint", "8"})
		saveCorpus()
		return num
	}
	val, corpusBytes = getUint(corpusBytes)
	return val
}

func GetFloat32(num float32) float32 {
	var val float32
	if genCorpus {
		corpusBytes = append(corpusBytes, getFloat32Byte(num)...)
		addConfig([]string{"float32", "4"})
		saveCorpus()
		return num
	}
	val, corpusBytes = getFloat32(corpusBytes)
	return val
}

func GetFloat64(num float64) float64 {
	var val float64
	if genCorpus {
		corpusBytes = append(corpusBytes, getFloat64Byte(num)...)
		addConfig([]string{"float64", "8"})
		saveCorpus()
		return num
	}
	val, corpusBytes = getFloat64(corpusBytes)
	return val
}

func GetString(str string) string {
	// lenth is the max lenth of mutated string
	// if length == 0, ignore the rule

	var val string
	if genCorpus {
		corpusBytes = append(corpusBytes, getStringByte(str)...)
		addConfig([]string{"string", strconv.Itoa(len(str))})
		saveCorpus()
		return str
	} else {
		val, corpusBytes = getString(corpusBytes)
		// if length > 0 && len(val) > length {
		// 	val = val[:length]
		// }
		return val
	}
}

func GetStringWithAlias(str string, isAlias bool) string {
	var val string
	if genCorpus {
		if isAlias {
			if _, ok := cache[str]; ok {
				return str
			}
			cache[str] = str
		}
		corpusBytes = append(corpusBytes, getStringByte(str)...)
		addConfig([]string{"string", strconv.Itoa(len(str))})
		saveCorpus()
		return str
	} else {
		if isAlias {
			if mutatedStr, ok := cache[str]; ok {
				return mutatedStr.(string)
			}
		}
		val, corpusBytes = getString(corpusBytes)
		// if length > 0 && len(val) > length {
		// 	val = val[:length]
		// }
		if isAlias {
			cache[str] = val
		}
		return val
	}
}

func GetBytes(arr []byte) []byte {
	var val []byte
	if genCorpus {
		corpusBytes = append(corpusBytes, arr...)
		addConfig([]string{"bytes", strconv.Itoa(len(arr))})
		saveCorpus()
		return arr
	} else {
		val, corpusBytes = getBytes(corpusBytes)
		return val
	}
}

func GetIntEnum(nums []int) int {
	// no logging into lenconfig
	idx := rand.Intn(len(nums))
	return nums[idx]
}

func GetIntEnumEx(nums []int) int {
	// no logging into lenconfig
	var val int
	var repeat bool = true
	for repeat {
		repeat = false
		val = rand.Int()
		for _, v := range nums {
			if val == v {
				repeat = true
				break
			}
		}
	}
	return val
}

func GetStringEnum(strs []string) string {
	// no logging into lenconfig
	idx := rand.Intn(len(strs))
	return strs[idx]
}

func GetStringEnumEx(strs []string) string {
	// load string from backend first
	// if repeated, generate a random string
	var val string
	if genCorpus {
		combine := strings.Join(strs, "")
		res := GetString(combine)
		addConfig([]string{"string", strconv.Itoa(len(combine))})
		saveCorpus()
		return res
	}
	val, corpusBytes = getString(corpusBytes)
	var repeat bool = false
	for _, s := range strs {
		if s == val {
			repeat = true
			break
		}
	}
	if !repeat {
		return val
	}
	// string from backend is repeated
	// generate a random string to return

	len := rand.Intn(1024)
	var res string

	for repeat {
		repeat = false
		data := make([]byte, 0)
		for i := 0; i < len; i++ {
			data = append(data, byte(rand.Intn(256)))
		}
		res = string(data)
		for _, s := range strs {
			if s == res {
				repeat = true
				break
			}
		}
	}
	return res
}

func GetNumInRange(minNum, maxNum int) int {
	// no logging into lenconfig
	return minNum + rand.Intn(maxNum-minNum)
}

func GetNumInRangeEx(minNum, maxNum int) int {
	// fetch the number from backend first
	// if repeated, generate a random int to return
	var val int64
	if genCorpus {
		corpusBytes = append(corpusBytes, getInt64Byte(int64(maxNum+1))...)
		addConfig([]string{"int", "8"})
		saveCorpus()
		return maxNum + 1
	}

	val, corpusBytes = getInt64(corpusBytes)
	if int(val) < minNum || int(val) >= maxNum {
		return int(val)
	}
	var inrange bool = true
	var res int
	for inrange {
		inrange = false
		res = rand.Int()
		if res >= minNum && res < maxNum {
			inrange = true
		}
	}
	return res
}

func GetJson(jsonStr string, pattren int) (string, error) {
	// not supported
	// no way to identify the elems in json string
	return "", nil
}

func GetMap(m interface{}, pattern int) (interface{}, error) {
	// no implemention
	// no way to support all the map types
	// maybe limited types like map[int/string]int/string is possible
	// meta type is possible, but complex type like pointer is no way to support
	switch realmap := m.(type) {
	case map[int]int:
		if genCorpus {
			addConfig([]string{"map[int]int", strconv.Itoa(len(realmap)), "int", "int"})
			for key, val := range realmap {
				GetInt(key)
				GetInt(val)
			}
			return realmap, nil
		}
		//TODO(jx): tell the backend, mutations for map shouldn't shorten the it
		// longer is better

		// get mutated values
		origLen := len(realmap)
		mutatedMapLen, _ := getLenFromConfig()
		switch pattern {
		case 0:
			// len is fixed
			// only value can be modified
			for key := range realmap {
				_ = GetInt(0)
				realmap[key] = GetInt(1)
			}
		case 1:
			// len is fixed
			// only key can be modified
			origVals := make([]int, 0)
			for key, val := range realmap {
				origVals = append(origVals, val)
				delete(realmap, key)
			}
			for i := 0; i < origLen; i++ {
				realmap[GetInt(1)] = origVals[i]
				GetInt(0)
			}
		case 2:
			// len is fixed
			// key and value can be modified at same time
			for key := range realmap {
				delete(realmap, key)
			}
			for i := 0; i < origLen; i++ {
				realmap[GetInt(1)] = GetInt(1)
			}

		case 3:
			// len can be modified
			// any can be modified
			for key := range realmap {
				delete(realmap, key)
			}
			for i := 0; i < mutatedMapLen; i++ {
				realmap[GetInt(1)] = GetInt(1)
			}
		default:
			panic("unknown pattern value")
		}
		if pattern < 3 { // need to clear the extra key value pair
			for i := origLen; i < mutatedMapLen; i++ {
				GetInt(0) // extra key
				GetInt(0) // extra value
			}
		}
		return realmap, nil

	case map[string]string:
		if genCorpus {
			addConfig([]string{"map[string]string", strconv.Itoa(len(realmap)), "string", "string"})
			for key, val := range realmap {
				GetString(key)
				GetString(val)
			}
			return realmap, nil
		}
		origLen := len(realmap)
		mutatedMapLen, _ := getLenFromConfig()
		switch pattern {
		case 0:
			for key := range realmap {
				_ = GetString("")
				realmap[key] = GetString("")
			}
		case 1:
			origVals := make([]string, 0)
			for key, val := range realmap {
				origVals = append(origVals, val)
				delete(realmap, key)
			}
			for i := 0; i < origLen; i++ {
				realmap[GetString("")] = origVals[i]
				GetString("")
			}
		case 2:
			for key := range realmap {
				delete(realmap, key)
			}
			for i := 0; i < origLen; i++ {
				realmap[GetString("")] = GetString("")
			}
		case 3:
			for key := range realmap {
				delete(realmap, key)
			}
			for i := 0; i < mutatedMapLen; i++ {
				realmap[GetString("")] = GetString("")
			}
		default:
			panic("unknown pattern value")
		}
		if pattern < 3 {
			for i := origLen; i < mutatedMapLen; i++ {
				GetString("")
				GetString("")
			}
		}
		return realmap, nil
	default:
		fmt.Errorf("more type is waiting")

	}
	return m, fmt.Errorf("map type is too complex to fuzz")

}

func GetStruct(x interface{}) (interface{}, error) {
	// 'x – 任意struct类型变量或struct指针类型变量' -- from doc
	//
	if !(reflect.TypeOf(x).Kind() == reflect.Struct || (reflect.TypeOf(x).Kind() == reflect.Ptr &&
		reflect.TypeOf(reflect.ValueOf(x)).Kind() == reflect.Struct)) {
		return nil, fmt.Errorf("elem of x is not a struct or a pointer to struct")
	}

	// TODO(jx): fix lenconfig in byte2Struct
	if genCorpus {
		if reflect.TypeOf(x).Kind() == reflect.Struct {
			structByte, _ := struct2Byte(unsafe.Pointer((uintptr(*(*int)(unsafe.Pointer(uintptr(int(uintptr(unsafe.Pointer(&x))) + 8)))))), reflect.TypeOf(x))
			corpusBytes = append(corpusBytes, structByte...)
			saveCorpus()
		} else {
			// pointer to a struct
			fmt.Println("Pointer is not supported temporarily\nPlease pass the *arg into me")
		}

		return x, nil
	}
	//else
	if reflect.TypeOf(x).Kind() == reflect.Struct {
		byte2Struct(unsafe.Pointer((uintptr(*(*int)(unsafe.Pointer(uintptr(int(uintptr(unsafe.Pointer(&x))) + 8)))))),
			reflect.TypeOf(x), corpusBytes)
	} else { // FIXME(jx): to test and fix the pointer offset
		fmt.Println("Pointer is not supported temporarily\nPlease pass the *arg into me")
		// byte2Struct(unsafe.Pointer((uintptr(
		// 	*(*int)(unsafe.Pointer(uintptr(
		// 		int(uintptr(unsafe.Pointer(&x))) + 8)))))),
		// 	reflect.TypeOf(reflect.ValueOf(x)), corpusBytes)
	}
	return x, nil
}

func GetSlice(slice interface{}) interface{} {
	// no way to support all the types
	// maybe limited types like []int, []string is pok
	switch arr := slice.(type) {
	case []byte:
		if genCorpus {
			addConfig([]string{"slice", strconv.Itoa(len(arr)), "uint8"})
			for _, elem := range arr {
				GetUint8(elem)
			}
			return arr
		} else {
			length, _ := getLenFromConfig()
			var news []byte
			for i := 0; i < length; i++ {
				news = append(news, GetUint8(0))
			}
			return news
		}
	case []int:
		if genCorpus {
			addConfig([]string{"slice", strconv.Itoa(len(arr)), "int"})
			for _, elem := range arr {
				GetInt(elem)
			}
			return arr
		} else {
			length, _ := getLenFromConfig()
			var news []int
			for i := 0; i < length; i++ {
				news = append(news, GetInt(0))
			}
			return news
		}

	case []string:
		if genCorpus {
			addConfig([]string{"slice", strconv.Itoa(len(arr)), "string"})
			for _, elem := range arr {
				GetString(elem)
			}
			return arr
		} else {
			length, _ := getLenFromConfig()
			var news []string
			for i := 0; i < length; i++ {
				news = append(news, GetString(""))
			}
			return news
		}
	default:
		panic("elem of slice is not supported")
	}
}

func GetFixSlice(slice interface{}, length int) interface{} {
	// no way to support all the types
	// maybe limited types like []int, []string is ok
	// regard the fix slice as a seq of value, so the length after mutation won't change

	switch arr := slice.(type) {
	case []byte:
		var res []byte
		if len(arr) <= length {
			for _, elem := range arr {
				res = append(res, GetUint8(elem))
			}
			for i := 0; i < length-len(arr); i++ {
				res = append(res, GetUint8(uint8(rand.Int())))
			}
		} else {
			for i := 0; i < length; i++ {
				res = append(res, GetUint8(arr[i]))
			}
		}
		return res
	case []int:
		var res []int
		if len(arr) <= length {
			for _, elem := range arr {
				res = append(res, GetInt(elem))
			}
			for i := 0; i < length-len(arr); i++ {
				res = append(res, GetInt(0))
			}
		} else {
			for i := 0; i < length; i++ {
				res = append(res, GetInt(arr[i]))
			}
		}
		return res
	case []string:
		var res []string
		if len(arr) <= length {
			for _, elem := range arr {
				res = append(res, GetString(elem))
			}
			for i := 0; i < length-len(arr); i++ {
				res = append(res, GetString("example"))
			}
		} else {
			for i := 0; i < length; i++ {
				res = append(res, GetString(arr[i]))
			}
		}
		return res
	default:
		panic("elem of slice is not supported")
	}
}

func LableTableDrivenLoopEnd() (ifbreak bool) {
	tableDrivenIdx++
	corpusName = filepath.Join(corpusDir, initcorpus+strconv.Itoa(tableDrivenIdx))
	lenconfigFile = "./lenconfig" + strconv.Itoa(tableDrivenIdx)

	lenindex = 0
	if genCorpus {
		corpusBytes = make([]byte, 0)
		config = make(map[int][]string)
	} else {
		// break loop in fuzz, and continue in gencorpus
		ifbreak = true
	}
	return

}
