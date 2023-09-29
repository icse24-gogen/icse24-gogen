package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIni(t *testing.T) {

}

func testint() {
	t := new(testing.T)
	t.Log("test")
}

func TestGetCrashType(t *testing.T) {
	file := "/home/iscsi/goarea/go-fdg-exmaples/rclone/cmd/genautocomplete/resultFuzzTestCompletionZsh/crashers/da39a3ee5e6b4b0d3255bfef95601890afd80709.output"
	filecontent, _ := ioutil.ReadFile(file)
	infolines := strings.Split(string(filecontent), "\n")
	cType := getCrashType(infolines)
	if cType != 2 {
		t.Errorf("type judge error")
	}
}

func TestGetCrashOutput(t *testing.T) {
	fdgwd := filepath.Join(os.Getenv("GOPATH"), "src", "go-fdg-exmaples")

	proj := "rclone"
	binfile := "/home/iscsi/goarea/go-fdg-exmaples/rclone/rcloneFuzzBins.txt"

	binsbytes, err := ioutil.ReadFile(binfile)
	if err != nil {
		panic(err)
	}
	bins := strings.Split(string(binsbytes), "\n")

	os.Chdir(filepath.Join(fdgwd, proj))
	for _, bin := range bins {
		crashes := make([]string, 0)
		if len(bin) == 0 {
			continue
		}
		if bin[0] == '.' {
			bin = bin[2:]
		}
		resultDir := filepath.Join(filepath.Dir(bin), fmt.Sprintf("result%s", strings.Trim(filepath.Base(bin), ".zip")))
		crashdir := filepath.Join(resultDir, "crashers")
		if !fileExists(crashdir) {
			continue
		}
		files, err := ioutil.ReadDir(crashdir)
		if err != nil {
			fmt.Println("con't read dir:", crashdir)
			continue
		}
		viewCrash := 0
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".output") {
				crashes = append(crashes, fmt.Sprintf("%s", filepath.Join(crashdir, file.Name())))
				viewCrash++
			}
			if viewCrash >= viewCrashNumPerDriver {
				break
			}
		}
		fmt.Printf("%s, %d, ", bin, len(crashes))
		for _, c := range crashes {
			fmt.Printf("%s, ", c)
		}
		fmt.Println("")
	}
}
