package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var flagProj = flag.String("proj", "std", "proj to analyze")
var flagBins = flag.String("bins", "", "bins")

type crashtype int

const (
	hang crashtype = iota
	runtimePanicInLibcode
	runtimePanicNotLibcode
	notRuntimePanicInLibcode
	notRuntimePanicNotLibcode
	triggerFatal
	discardCrash
)

var crashName []string = []string{"hang", "runtimePanicInLibcode", "runtimePanicNotLibcode", "NotRuntimePanicInLibcode", "NotRuntimePanicNotLibcode", "triggerFatal"}
var viewCrashNumPerDriver int = 10
var allCrash = 0

// crash identifier classify the crashes of a proj into 4 types
// hang is assigned as 0
//                    	   |
//     不在libcode         |        在lib code内
//    Runtime error        |       Runtime error
//-----------------------------------------------------
//     不在libcode         |       在lib code内
//    非Runtime error      |      非Runtime error
//

func main() {
	flag.Parse()
	if *flagProj == "" {
		panic("proj is not assigned")
	}
	fdgwd := filepath.Join(os.Getenv("GOPATH"), "src", "topproj")
	fmt.Println(filepath.Join(fdgwd, *flagProj))
	os.Chdir(filepath.Join(fdgwd, *flagProj))
	var binsbytes []byte
	if *flagBins != "" {
		tmpbytes, err := ioutil.ReadFile(*flagBins)
		if err != nil {
			panic(err)
		}
		binsbytes = tmpbytes
	} else {
		cmdstr := `find . -name "resultFuzz*"`
		cmd := exec.Command("sh", "-c", cmdstr)
		binsbytes, _ = cmd.CombinedOutput()
	}

	bins := strings.Split(string(binsbytes), "\n")
	crashes := make([][]string, len(crashName))

	writeFile_hang, _ := os.Create(fmt.Sprintf("/home/%s/workspace/gowork/src/xyz.asd.qwe/gout-transformation/scripts/crashidentifier/CrashLogHang", os.Getenv("USER")))
	writeFile_runtimePanicInLibcode, _ := os.Create(fmt.Sprintf("/home/%s/workspace/gowork/src/xyz.asd.qwe/gout-transformation/scripts/crashidentifier/CrashLogRuntimePanicInLibcode", os.Getenv("USER")))
	writeFile_runtimePanicNotLibcode, _ := os.Create(fmt.Sprintf("/home/%s/workspace/gowork/src/xyz.asd.qwe/gout-transformation/scripts/crashidentifier/CrashLogRuntimePanicNotLibcode", os.Getenv("USER")))
	writeFile_NotRuntimePanicInLibcode, _ := os.Create(fmt.Sprintf("/home/%s/workspace/gowork/src/xyz.asd.qwe/gout-transformation/scripts/crashidentifier/CrashLogNotRuntimePanicInLibcode", os.Getenv("USER")))
	writeFile_NotRuntimePanicNotLibcode, _ := os.Create(fmt.Sprintf("/home/%s/workspace/gowork/src/xyz.asd.qwe/gout-transformation/scripts/crashidentifier/CrashLogNotRuntimePanicNotLibcode", os.Getenv("USER")))
	writeFile_triggerFatal, _ := os.Create(fmt.Sprintf("/home/%s/workspace/gowork/src/xyz.asd.qwe/gout-transformation/scripts/crashidentifier/CrashLogTriggerFatal", os.Getenv("USER")))
	defer writeFile_hang.Close()
	defer writeFile_runtimePanicInLibcode.Close()
	defer writeFile_runtimePanicNotLibcode.Close()
	defer writeFile_NotRuntimePanicInLibcode.Close()
	defer writeFile_NotRuntimePanicNotLibcode.Close()
	defer writeFile_triggerFatal.Close()

	for _, bin := range bins {
		if len(bin) == 0 {
			continue
		}
		if bin[0] == '.' {
			bin = bin[2:]
		}

		// resultDir := filepath.Join(filepath.Dir(bin), fmt.Sprintf("result%s", strings.Trim(filepath.Base(bin), ".zip")))
		resultDir, err := filepath.Abs(bin)
		if err != nil {
			continue
		}
		crashdir := filepath.Join(resultDir, "crashers")
		if !fileExists(crashdir) {
			continue
		}

		if !isDriverMeaningful(resultDir) {
			// only consider the dirvers with more than 2 corpus
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
				allCrash++
				filecontent, _ := ioutil.ReadFile(filepath.Join(crashdir, file.Name()))
				infolines := strings.Split(string(filecontent), "\n")
				cType := getCrashType(infolines)
				if cType == discardCrash {
					continue
				}
				crashes[cType] = append(crashes[cType], fmt.Sprintf("%s", filepath.Join(crashdir, file.Name())))
				viewCrash++

				filePath := filepath.Join(crashdir, file.Name())
				stream, err := ioutil.ReadFile(filePath)
				if err != nil {
					continue
				}
				readString := filePath + "\n" + string(stream) + "\n-------------------------------\n"
				switch cType {
				case hang:
					writeFile_hang.WriteString(readString)
				case runtimePanicInLibcode:
					writeFile_runtimePanicInLibcode.WriteString(readString)
				case runtimePanicNotLibcode:
					writeFile_runtimePanicNotLibcode.WriteString(readString)
				case notRuntimePanicInLibcode:
					writeFile_NotRuntimePanicInLibcode.WriteString(readString)
				case notRuntimePanicNotLibcode:
					writeFile_NotRuntimePanicNotLibcode.WriteString(readString)
				case triggerFatal:
					writeFile_triggerFatal.WriteString(readString)
				}

			}
			if viewCrash >= viewCrashNumPerDriver {
				break
			}
		}
	}

	for i, cs := range crashes {
		fmt.Printf("------------------ %s -----------------\n", crashName[i])
		for _, c := range cs {
			fmt.Println(c)
		}
		fmt.Println("------------------------------------------------------------------")
	}
	fmt.Println(allCrash)
	fmt.Printf("%s:%d, %s:%d, %s:%d, %s:%d, %s:%d, %s:%d\n",
		crashName[0], len(crashes[0]),
		crashName[1], len(crashes[1]),
		crashName[2], len(crashes[2]),
		crashName[3], len(crashes[3]),
		crashName[4], len(crashes[4]),
		crashName[5], len(crashes[5]))
	//fmt.Fprintf(os.Stderr, "proj,hang,runtimePanicInLibcode,runtimePanicNotLibcode,NotRuntimePanicInLibcode,NotRuntimePanicNotLibcode,triggerFatal\n")
	fmt.Fprintf(os.Stderr, "%s,%d,%d,%d,%d,%d,%d\n", *flagProj, len(crashes[0]), len(crashes[1]),
		len(crashes[2]), len(crashes[3]), len(crashes[4]), len(crashes[5]))
	/*fmt.Fprintf(os.Stderr, "%12s   %s:%3d,  %s:%3d,  %s:%3d,  %s:%3d,  %s:%3d,  %s:%3d\n", *flagProj,
	crashName[0], len(crashes[0]),
	crashName[1], len(crashes[1]),
	crashName[2], len(crashes[2]),
	crashName[3], len(crashes[3]),
	crashName[4], len(crashes[4]),
	crashName[5], len(crashes[5]))
	*/
}

func bugVerify() (path string) {
	// generate a poc automatically
	// and return the poc file path

	// not implemented
	return
}

var crashLoc = make(map[string]bool)

func getCrashType(crashinfo []string) crashtype {

	var ctype crashtype
	trace := make([]string, 0)
	for crashLineIdx, crashLine := range crashinfo {
		if strings.HasPrefix(crashLine, "panic:") {
			crashinfo = crashinfo[crashLineIdx:]
			break
		}
	}

	switch {
	case strings.Contains(crashinfo[0], "hang"):
		return hang
	case strings.Contains(crashinfo[0], "deadlock"): // main call exit()
		return triggerFatal
	default:
		break
	}
	if strings.Contains(crashinfo[0], "panic: runtime error") || strings.Contains(crashinfo[0], "fatal") {
		ctype = runtimePanicInLibcode
	} else {
		ctype = notRuntimePanicInLibcode
	}

	isFirstTrace := true
	for _, line := range crashinfo {
		/*if !strings.Contains(line, "/home/gogen/workspace/gowork/src/topproj") {
			continue
		}*/
		if !strings.Contains(line, ".go:") {
			continue
		} else {
			if strings.Contains(line, "_test.go:") && isFirstTrace {
				break
			}
			isFirstTrace = false
			trace = append(trace, strings.TrimSpace(line))
		}

		if strings.Contains(line, "_fuzz.go") {
			//trace starts with fuzz.go
			break
		}
	}

	if len(trace) == 0 {
		ctype += 1
	} else if strings.Count(trace[0], ".go") == 2 {
		return discardCrash
	} else {
		crashRegex, _ := regexp.Compile("/[A-Za-z0-9_-]+[.]go:[0-9]+")
		crashLocStr := crashRegex.FindString(trace[0])
		if _, ok := crashLoc[crashLocStr]; ok {
			return discardCrash
		} else {
			crashLoc[crashLocStr] = true
		}
		for _, line := range trace {
			// code from go-fuzz
			if strings.Contains(line, "go-fuzz") {
				ctype += 1 // turn crash type to not lib code
				break
			}
			// code from fuzz.go
			if strings.Contains(line, "_fuzz.go") {
				ctype += 1 // turn crash type to not lib code
				break
			}

			// code from goroot
			if !strings.HasPrefix(line, "/") || strings.HasPrefix(line, os.Getenv("GOROOT")) {
				continue
			}
			if strings.HasPrefix(line, filepath.Join(os.Getenv("GOPATH"), "src", "gotestenv")) {
				continue
			}

			// crash is triggered from lib code, break loop
			break
		}
	}
	return ctype
}

func isDriverMeaningful(resultDir string) bool {
	// resultDir := filepath.Join(filepath.Dir(bin), fmt.Sprintf("result%s", strings.Trim(filepath.Base(bin), ".zip")))
	//resultDir := filepath.Dir(bin)
	corpusDir := filepath.Join(resultDir, "corpus")
	fs, _ := ioutil.ReadDir(corpusDir)
	return len(fs) >= 1
}
