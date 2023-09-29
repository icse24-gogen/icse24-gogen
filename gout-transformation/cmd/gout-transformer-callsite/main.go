package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
	"xyz.asd.qwe/gout-transformation/internal/callsitecomposer"
	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

var flagYamlDir = flag.String("dir", "", "Yaml Directory")
var flagSpe = flag.String("spe", "", "Specific Test Cases")
var flagNoBuild = flag.Bool("nobuild", false, "Not build driver")

var flagFilter = make(map[string]byte, 0)

func init() {
	flag.Parse()
	givenFuncs := strings.Split(*flagSpe, ",")
	for _, funcName := range givenFuncs {
		flagFilter[funcName] = 1
	}
}

func main() {
	if *flagYamlDir == "" {
		panic("Please specify the yaml directory")
	}
	files, err := ioutil.ReadDir(*flagYamlDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Please check the cwd running this binary")
		panic(err)
	}

	for _, file := range files {
		terms := strings.Split(file.Name(), ".")
		testNameofYamlFile := terms[len(terms)-2]
		if *flagSpe != "" {
			// TODO(jx): more than one test func with same name will be gened more than once
			if _, ok := flagFilter[testNameofYamlFile]; !ok {
				continue
			}
		}

		tcmi := new(metainfo.CallsiteMeta)
		metabyte, err := ioutil.ReadFile(filepath.Join(*flagYamlDir, file.Name()))
		if err != nil {
			panic(err)
		}
		yaml.Unmarshal(metabyte, tcmi)

		if len(tcmi.Name) == 0 {
			continue
		}
		fmt.Fprintln(os.Stderr, "[*] Start to generate fuzz driver for ", tcmi.Name)

		tcd := &callsitecomposer.Composer{
			Testfile: tcmi.SrcPath,
			Metainfo: tcmi,
		}

		driverPath, err := tcd.Generate()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if len(driverPath) > 0 && !*flagNoBuild {
			truBuildFuzzDriver(tcmi, driverPath)
		}
		os.Rename(driverPath, driverPath+".bak")

	}

}

func truBuildFuzzDriver(meta *metainfo.CallsiteMeta, driverPath string) {
	checksucc := exec.Command("cat", driverPath)
	out, _ := checksucc.CombinedOutput()
	gensucc := false
	for _, outinfo := range strings.Split(string(out), "\n") {
		if strings.Contains(outinfo, "transstruct.Get") {
			gensucc = true
			break
		}
	}
	if !gensucc {
		fmt.Fprintln(os.Stderr, "[-] Cannot find transstruct.Get from fuzz driver in", driverPath)
		return
	}

	cwd, _ := os.Getwd()
	os.Chdir(filepath.Dir(meta.SrcPath))
	defer os.Chdir(cwd)

	runbuild := func() ([]byte, error) {
		driverName := "Fuzz" + meta.Name[strings.LastIndex(meta.Name, ".")+1:]
		cmd := exec.Command("go-fuzz-build-test", "-test=true", "-func="+driverName, "-o="+driverName+".zip", "-preserve=testing,jkl/gout-transformation/pkg/transstruct")
		out, err := cmd.CombinedOutput()
		return out, err
	}

	buildsucc := false
	os.Setenv("GOROOT", filepath.Join(os.Getenv("GOPATH"), "src", "gotestenv"))
	out, err := runbuild()
	if err == nil {
		buildsucc = true
	}

	if buildsucc {
		fmt.Fprintln(os.Stderr, "[+] Build fuzz driver successfully for ", "Fuzz"+meta.Name[strings.LastIndex(meta.Name, ".")+1:])

	} else {
		fmt.Fprintln(os.Stderr, "-----------------Error Start-----------------")
		fmt.Fprintf(os.Stderr, "failed to execute go build: %v\n%v", err, string(out))
		fmt.Fprintln(os.Stderr, "-----------------Error Finish----------------")
	}

}
