package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var flagMode = flag.Int("mode", 2, "1: only run exists bin, 2: only gen, 3:gen and run newly builded bin")

var flagForce = flag.Bool("force", false, "force to generate fuzzbin")

// var flagRun = flag.Bool("run", false, "run fuzzbin when finished")
var flagWorkers = flag.Int("workers", 40, "how many works to run")
var flagBins = flag.String("bins", "", "bins to run")
var flagResName = flag.String("resname", "fuzzRes.txt", "name of result file")
var flagProj = flag.String("projs", "", "projs to fuzz")
var flagRootDir = flag.String("rootdir", "topproj", "root dir of projs")
var flagFuzztime = flag.Int("fuzztime", 4, "fuzz time")

var flagTransformer = flag.String("transformer", "gout-transformer-gofuzz", "transformer to use")

var flagFuzzer = flag.String("fuzzer", "go-fuzz", "fuzzer to use")

var autogofuzz_dir string

const (
	runOnly int = iota + 1
	genOnly
	genAndRunFuzz
)

func genNewBins() {

	projsWithYaml := getProjs()

	fdgwd := filepath.Join(os.Getenv("GOPATH"), "src", *flagRootDir)
	os.Chdir(fdgwd)
	// generatingChan := make(chan string, len(projsWithYaml))
	generatingChan := make(chan string, 5)
	var succChan, fuzzingChan chan string

	projsToGen := make(map[string]string)
	if *flagProj == "" {
		// all
		projsToGen = projsWithYaml
	} else {
		projs := strings.Split(*flagProj, ",")
		for _, p := range projs {
			if yamldir, ok := projsWithYaml[p]; ok {
				projsToGen[p] = yamldir
			} else {
				projsToGen[p] = p + "_yaml_out_dir"
			}
		}

	}

	for proj, yamldir := range projsToGen {

		now := time.Now().Add(8 * time.Hour)
		*flagResName = fmt.Sprintf("fuzzres-%02d%02d-%s.txt", now.Month(), now.Day(), proj)
		os.Chdir(filepath.Join(fdgwd, proj))

		if *flagMode == genAndRunFuzz {
			succChan = make(chan string, 9999)
			fuzzingChan = make(chan string, 1)
			fuzzingChan <- proj
			go runImmediatelyFuzz(succChan, fuzzingChan)
		}

		generatingChan <- proj
		genForProj(proj, yamldir, generatingChan, succChan, fuzzingChan)
		//

	}
	for len(generatingChan) > 0 {
		time.Sleep(time.Minute)
	}

}

func runExistBins() {
	candidatebins := make([]string, 0)
	if *flagBins != "" {
		if !fileExists(*flagBins) {
			panic("target fuzzbinlist not exists")
		}
		fbyte, _ := ioutil.ReadFile(*flagBins)
		candidatebins = strings.Split(string(fbyte), "\n")
	}

	fdgwd := filepath.Join(os.Getenv("GOPATH"), "src", *flagRootDir)
	os.Chdir(fdgwd)
	go clearTmp()
	projsToFuzz := make(map[string]string)
	if *flagProj == "" {
		projsToFuzz = getProjs()
	} else {
		ps := strings.Split(*flagProj, ",")
		for _, p := range ps {
			projsToFuzz[p] = ""
		}
	}

	for proj, _ := range projsToFuzz {
		fmt.Println("---------------------------------------\n[*] Fuzzing", proj)
		*flagResName = fmt.Sprintf("fuzzres-%02d%02d-%s.txt", time.Now().Month(), time.Now().Day(), proj)
		// only std is enabled now
		os.Chdir(filepath.Join(fdgwd, proj))
		bins := make([]string, 0)
		finishedBins := make([]string, 0)
		if *flagBins == "" {
			// no assigned, so use all exsited bins
			findcmd := exec.Command("/bin/sh", "-c", `find . -name "Fuzz*.zip" | grep -v "resultFuzz"`)
			outinfo, err := findcmd.CombinedOutput()
			if err != nil {
				// panic(err)
				fmt.Println(fmt.Errorf("[*] Error: %v", err))
				continue
			}
			bins = strings.Split(strings.TrimRight(string(outinfo), "\n"), "\n")
		} else {
			for _, bin := range candidatebins {
				if fileExists(bin) {
					bins = append(bins, bin)
				}
			}
		}
		if fileExists(filepath.Join(autogofuzz_dir, "finishedbin.list")) {
			fbyte, _ := ioutil.ReadFile(filepath.Join(autogofuzz_dir, "finishedbin.list"))
			finishedBins = strings.Split(string(fbyte), "\n")
		}

		//fmt.Println(bins)

		fuzzWorkPool := make(chan string, *flagWorkers)
		results := make([]*FuzzRes, 0)
		wg := new(sync.WaitGroup)
		mu := new(sync.Mutex)
		for _, binname := range bins {
			if strings.Contains(binname, "resultFuzz") {
				continue
			}
			if elemInStringSlice(binname, finishedBins) {
				continue
			}
			if fileExists(filepath.Join(autogofuzz_dir, "suspendFuzz")) {
				// DONE(jx): if want suspend the fuzz, create the file, and wait the existing fuzz to finish
				// rm that file to continue add new fuzz target into pool
				for {
					time.Sleep(5 * time.Minute)
					if !fileExists(filepath.Join(autogofuzz_dir, "suspendFuzz")) {
						break
					}
				}
			}
			wg.Add(1)
			fuzzWorkPool <- binname
			go startFuzz(fuzzWorkPool, binname, results, wg, mu)
		}
		wg.Wait()
	}
}

func main() {
	flag.Parse()
	autogofuzz_dir, _ = os.Getwd()
	if *flagMode == runOnly {
		fmt.Fprintf(os.Stderr, "[*] Only run existed bins with %v workers\n", *flagWorkers)
		runExistBins()
	} else {
		genNewBins()
	}
	// showtiaotiao()
}
