package transstruct

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
)

func TestReloadConfig_Sep(t *testing.T) {
	os.Args = append(os.Args, "1", "2")
	os.Setenv("__AFL_LENCONFIG", "4")
	os.Chdir("./testdata")

	//gen with seperated API
	os.Args[3] = "lenconfig"
	ReFreshConfig()
	str1 := GetString("zzzzzzzzzz")
	str2 := GetString("yyyyyyyyyyyyyyy")
	str3 := GetString("xxxxx")
	fmt.Println(str1, str2, str3)

	//fuzz with seperated API
	for i := 1; i < 4; i++ {
		configfile := "config" + strconv.Itoa(i)
		corpusfile := "corpus" + strconv.Itoa(i)
		os.Args[3] = corpusfile
		os.Args[4] = configfile
		ReFreshConfig()
		println(configfile, corpusfile)
		str1 = GetString("zzzzzzzzzz")
		str2 = GetString("yyyyyyyyyyyyyyy")
		str3 = GetString("xxxxx")
		fmt.Println(str1, str2, str3)
	}
}

func TestReloadConfig_General(t *testing.T) {
	os.Args = append(os.Args, "1", "2")
	os.Setenv("__AFL_LENCONFIG", "4")
	os.Chdir("./testdata")

	//gen with general API
	type T struct {
		a string
		b string
		c string
	}
	obj := T{
		"mmmmmmmmmm",
		"nnnnnnnnnnnnnnn",
		"iiiii",
	}
	os.Args[3] = "lenconfig"
	ReFreshConfig()
	// You should call GetFuzzData directly,
	// and here we call GenerateInitCorpus to avoid exiting after generation
	// GetFuzzData(obj)
	GenerateInitCorpus(obj)

	//fuzz with general API
	for i := 1; i < 4; i++ {
		configfile := "config" + strconv.Itoa(i)
		corpusfile := "corpus" + strconv.Itoa(i)
		os.Args[3] = corpusfile
		os.Args[4] = configfile
		ReFreshConfig()
		println(configfile, corpusfile)
		newobj := GetFuzzData(obj).(T)
		fmt.Println(newobj)
	}
}

func TestGetInt(t *testing.T) {
	corpus, _ := ioutil.ReadFile("./corpus/initcorpus")
	SetFuzzData(corpus)
	a := GetInt(5)
	b := GetInt(256)
	fmt.Println(a, b)
}

func TestTableDriven(t *testing.T) {
	corpus, _ := ioutil.ReadFile("./corpus/initcorpus")
	SetFuzzData(corpus)
	tcs := []int{1, 2, 3, 4, 5}
	for _, i := range tcs {

		a := GetInt(i)
		b := GetInt(i)
		c := GetInt64(65536)
		fmt.Println(a, b, c)
		if LableTableDrivenLoopEnd() {
			break
		}
	}

}

func TestStrCache(t *testing.T) {
	SetFuzzData([]byte{})

	a := GetStringWithAlias("aaaa", true)
	b := GetStringWithAlias("aaaa", true)

	c := GetStringWithAlias("abcdefg", false)
	d := GetStringWithAlias("abcdefg", true)

	e := GetStringWithAlias("abcdefg", true)
	fmt.Println(a + b + c + d + e)

}
