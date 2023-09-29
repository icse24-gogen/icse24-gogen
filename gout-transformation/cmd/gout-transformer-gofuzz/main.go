package main

import (
	//"fmt"

	"errors"
	"flag"
	"fmt"
	"go/importer"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v2"
	"xyz.asd.qwe/gout-transformation/internal/tcgfcomposer"
	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
	//"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

var flagYamlDir = flag.String("dir", "", "Yaml Directory")
var flagFuncs = flag.String("spe", "", "Specific Test Cases(Not to transform)")
var flagNoBuild = flag.Bool("nobuild", false, "Not build driver")
var flagNoOverwrite = flag.Bool("nooverwrite", false, "Skip transformed test case")

var g_tcmis = make(map[string](*metainfo.TestCaseMetaInfo), 0)
var flagFilter = make(map[string]byte, 0)
var flagSpe bool

func init() {
	flag.Parse()
	flagSpe = false
	if 0 < len(*flagFuncs) {
		flagSpe = true
	}
	givenFuncs := strings.Split(*flagFuncs, ",")
	for _, f := range givenFuncs {
		flagFilter[f] = 1
	}
}
func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func tryToBuildFuzzDriver(mi *metainfo.TestCaseMetaInfo, path string) {
	checkSucc := exec.Command("cat", path)
	out, _ := checkSucc.CombinedOutput()
	genSucc := false
	buildSucc := false
	for _, outinfo := range strings.Split(string(out), "\n") {
		if strings.Contains(outinfo, "transstruct.Get") {
			genSucc = true
			break
		}
	}
	if !genSucc {
		fmt.Fprintln(os.Stderr, "[-] Cannot find transstruct.Get from fuzz driver in", path)
		return
	}

	cwd, _ := os.Getwd()
	os.Chdir(filepath.Dir(mi.SrcPath))
	defer os.Chdir(cwd)
	// origGoroot := os.Getenv("GOROOT")
	runbuild := func() ([]byte, error) {
		driverName := "Fuzz" + mi.Name
		//TODO(jx): run all build actions in same goroot in the future
		//os.Setenv("GOROOT", file	path.Join(os.Getenv("GOPATH"), "src", "gotestenv"))
		cmd := exec.Command("go-fuzz-build-test", "-test=true", "-func="+driverName, "-o="+driverName+".zip", "-preserve=testing,jkl/gout-transformation/pkg/transstruct")

		out, err := cmd.CombinedOutput()
		return out, err
	}
	os.Setenv("GOROOT", filepath.Join(os.Getenv("GOPATH"), "src", "topproj/go"))
	out, err := runbuild()
	if err == nil {
		buildSucc = true
	}

	if buildSucc {
		fmt.Fprintln(os.Stderr, "[+] Build fuzz driver successfully for ", mi.Name)
	} else {
		fmt.Fprintln(os.Stderr, "-----------------Error Start-----------------")
		fmt.Fprintf(os.Stderr, "failed to execute go build: %v\n%v", err, string(out))
		fmt.Fprintln(os.Stderr, "-----------------Error Finish----------------")
	}
}

func tryToBuildFuzzDriverAFLGolang(mi *metainfo.TestCaseMetaInfo, path string) {
	cwd, _ := os.Getwd()
	os.Chdir(filepath.Dir(mi.SrcPath))
	driverName := "Fuzz" + mi.Name
	cmd := exec.Command(fmt.Sprintf("afl-go-instrumentor -func=%s -o %s.zip -dep=/home/user/workspace/gowork/src/GoFuzz/afl-golang/afl-go-build/afl-go-instrumentor/afl-golang-dep ./", driverName, driverName))
	fmt.Fprintln(os.Stderr, "[*] Building fuzz driver for "+mi.Name)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintln(os.Stderr, "[-]Cannot build Driver of ", mi.Name)
		fmt.Fprintln(os.Stderr, "-----------------Error Start-----------------")
		fmt.Fprintf(os.Stderr, "failed to execute go build: %v\n%v", err, string(out))
		fmt.Fprintln(os.Stderr, "-----------------Error Finish----------------")
	} else {
		fmt.Fprintln(os.Stderr, "[+] Build fuzz driver successfully for ", mi.Name)
	}

	os.Chdir(cwd)
}

func main() {

	files, _ := ioutil.ReadDir(*flagYamlDir) //read analyzer output

	for _, file := range files {
		//DONE(jx): opt yaml parse
		// get func name from file name
		// and avoid parsing yaml whose testfunc name is not matched
		terms := strings.Split(file.Name(), ".")
		testNameofYamlFile := terms[len(terms)-2]

		if flagSpe {
			if _, ok := flagFilter[testNameofYamlFile]; !ok {
				continue //pass this test
			}
		}

		tcmi := new(metainfo.TestCaseMetaInfo)
		comingPath := path.Join(*flagYamlDir, file.Name())
		metaBytes, err := ioutil.ReadFile(comingPath)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(metaBytes, tcmi)
		if err != nil {
			panic(err)
		}

		if len(tcmi.Name) == 0 {
			continue
		}
		tcmi.Name = tcmi.Name[strings.LastIndex(tcmi.Name, ".")+1:]

		g_tcmis[path.Join(*flagYamlDir, file.Name())] = tcmi
	} //read all test case meta info

	var tcd *tcgfcomposer.Composer
	for _, tcmi := range g_tcmis { //start to generate
		fmt.Fprintln(os.Stderr, "[*] Start to generate fuzz driver for ", tcmi.Name)
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			panic(cwdErr)
		}
		tcd = &tcgfcomposer.Composer{Importer: importer.Default()}

		if *flagNoOverwrite { //don't overwrite the driver files generated before
			outputFile := tcmi.SrcPath + "_" + tcmi.Name + "_fuzz.go.bak"
			if _, err := os.Stat(outputFile); !errors.Is(err, os.ErrNotExist) {
				continue
			}

		}
		tcd.PreParseSrcOnly(path.Join(cwd, tcmi.SrcPath), tcmi)
		driverPath, err := tcd.Generate()
		if err != nil {
			panic(err)
		}

		if len(driverPath) != 0 && !*flagNoBuild {
			tryToBuildFuzzDriver(tcmi, driverPath)
		}
		os.Rename(driverPath, driverPath+".bak")
	}
}

func isYamlDirStd(yamldir string) bool {
	return strings.HasPrefix(yamldir, "std")
}
