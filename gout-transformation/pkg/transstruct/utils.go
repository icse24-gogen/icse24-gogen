package transstruct

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

func init() {
	// ReFreshConfig()
}

func fileExists(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func ifGenInitCorpus() bool {
	// if len(os.Args) > 3 && os.Args[3] == "lenconfig" {
	// 	return true // generate initcorpus, not fuzz
	// }
	// return false

	// if lenconfig and initcorpus not exist, generate initcorpus
	if !fileExists(lenconfigFile) || !fileExists("./corpus/initcorpus") {
		os.RemoveAll("./corpus")
		os.RemoveAll(lenconfigFile)
		return true
	}
	return false
}

func addConfig(info []string) {
	config[lenindex] = append(config[lenindex], info...)
	lenindex++
}

// saveCorpus save the initcorpus and lenconfig at each GetXxx
func saveCorpus() {
	var jsonbyte []byte
	for i := 0; i < len(config); i++ { // for lenconfig is in sort
		tmpconfig := make(map[int][]string)
		tmpconfig[i] = config[i]
		tmpbyte, _ := json.MarshalIndent(tmpconfig, "", "	")
		jsonbyte = append(jsonbyte, tmpbyte...)
	}
	ioutil.WriteFile(lenconfigFile,
		[]byte(strings.Replace(string(jsonbyte), "\n}{", ",", -1)), 0666)

	os.MkdirAll("./corpus", 0777)

	ioutil.WriteFile(corpusName, corpusBytes, 0666)
}

func bytesCombine1000(data []byte) []byte {
	if len(data) == 0 {
		data = []byte("\x00")
	}
	var buffer bytes.Buffer
	buffer.Write(data)
	buffer.Write(data)

	data = buffer.Bytes()

	for len(data) < 1024*10 {
		data = bytesCombine1000(data)
	}
	return data
}

func getLenFromConfig() (int, error) {
	if len(config[lenindex]) > 1 {
		// lenconfig is correct
		length, _ := strconv.Atoi(config[lenindex][1])
		lenindex++
		return length, nil
	} else {
		// config match has be ruined
		// lenconfig will not be multified
		length := rand.Int() % defaultStringLen
		return length, nil
	}
}
