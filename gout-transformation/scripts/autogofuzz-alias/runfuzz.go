package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var bitmapSize = 65536

type Fuzzprocess struct {
	name         string
	relativePath string
	cmd          *exec.Cmd
}

func startFuzz(workpool chan string, binname string, results []*FuzzRes, wg *sync.WaitGroup, mu *sync.Mutex) {

	targetF := binname[strings.LastIndex(binname, "/")+1 : strings.LastIndex(binname, ".")] // FuzzTestXxx
	targetPath := filepath.Dir(binname)
	//resultDir := filepath.Join(targetPath, "alias-result"+targetF) // relative to std/
	resultDir := filepath.Join(targetPath, "user-result"+targetF) // relative to std/

	if !fileExists(resultDir) {
		os.MkdirAll(resultDir, os.ModePerm)
	} else {
		os.RemoveAll(resultDir)
		os.MkdirAll(resultDir, os.ModePerm)
	}
	copycmdstr := fmt.Sprintf("cp %s %s", binname, resultDir)
	exec.Command("/bin/sh", "-c", copycmdstr).Run()

	if !fileExists("oldcorpus") {
		os.Mkdir("oldcorpus", 0777)
	}
	defer os.RemoveAll("oldcorpus")
	defer exec.Command("/bin/sh", "-c", "mv oldcorpus/* corpus/").Wait()
	if fileExists("corpus") {
		exec.Command("/bin/sh", "-c", "cp corpus/* oldcorpus").Wait()
	}
	now := time.Now().Add(8 * time.Hour)
	fuzzcmdstr := fmt.Sprintf(`rm lenconfig; echo "%v" > startFuzz.time; timeout 3m go-fuzz -bin=%s.zip -procs=1 -dryrun=true; timeout %dh go-fuzz -bin=%s.zip -procs=1; rm %s.zip`, now.String(), targetF, *flagFuzztime, targetF, targetF)
	//fuzzcmdstr := fmt.Sprintf("rm lenconfig; timeout 3m go-fuzz -bin=%s.zip -procs=32", targetF)
	fuzzcmd := exec.Command("/bin/sh", "-c", fuzzcmdstr)

	fmt.Printf("start fuzz %s at %v/%v:%v\n", targetF, now.Day(), now.Hour(), now.Minute())
	fuzzcmd.Dir = resultDir
	fProcess := &Fuzzprocess{
		name: targetF,
		cmd:  fuzzcmd,
	}

	res := &FuzzRes{
		name: targetF,
		bin:  binname,
	}

	res.corpus, res.cover, res.crashes, res.coveredBugPointCount = watchFuzzCmd(fProcess)

	mu.Lock()
	// fmt.Println(res)
	if strings.HasPrefix(res.bin, "./") {
		res.bin = res.bin[2:]
	}
	outputInfo := fmt.Sprintf("%s, %v, %v, %v\n", res.bin, res.corpus, res.cover, res.crashes)
	// fmt.Printf("%s, %v, %v, %v, %v\n", res.bin, res.corpus, res.cover, res.crashes, res.coveredBugPointCount)

	results = append(results, res)
	mu.Unlock()
	os.Remove(filepath.Join(resultDir, targetF+".zip"))
	<-workpool
	resFile, _ := os.OpenFile(filepath.Join(autogofuzz_dir, *flagResName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	defer resFile.Close()
	writer := bufio.NewWriter(resFile)
	writer.WriteString(outputInfo)
	writer.Flush()
	wg.Done()
}

func watchFuzzCmd(fprocess *Fuzzprocess) (corpus, cover, crashes, coveredBugPointCount int) {
	fuzzcmd := fprocess.cmd
	corpus, cover, crashes = 0, 0, 0
	coveredBugPointCount = 0
	stderr, _ := fuzzcmd.StderrPipe()
	fuzzcmd.Start()
	uptime := 0
	r := bufio.NewReader(stderr)

	parseLine := func(line []byte) int {
		info := strings.Replace(string(line), "\n", "", -1)
		if info == "" {
			return 1
		}
		terms := strings.Split(info, ", ")
		if len(terms) != 7 {
			return 1
		}
		corpus, _ = strconv.Atoi(strings.Split(strings.Split(terms[1], ": ")[1], " (")[0])
		// cover, _ = strconv.Atoi(strings.Split(terms[5], ": ")[1])
		crashes, _ = strconv.Atoi(strings.Split(terms[2], ": ")[1])
		uptimestr := strings.Split(terms[6], ": ")[1]
		cover = func() (coverCount int) {
			// parse cover according to bitmap instead of output of fuzzer
			coverCount = 0
			bitmapFile := filepath.Join(fprocess.cmd.Dir, "maxCover.log")

			coverMap, err := ioutil.ReadFile(bitmapFile)
			if err != nil {
				return
			}
			for _, cov := range coverMap {
				if cov > 0 {
					coverCount++
				}
			}
			return coverCount
		}()

		if strings.Contains(uptimestr, "m") {
			min, _ := strconv.Atoi(strings.Split(uptimestr, "m")[0])
			sec, _ := strconv.Atoi(strings.Split(strings.Split(uptimestr, "m")[1], "s")[0])
			uptime = min*60 + sec
		}
		return 0
	}

	// hitPotentialBugPoint := func() {
	// 	parseMetaData := func(metadatafile string, bitmap []string) error {
	// 		content, err := ioutil.ReadFile(metadatafile)
	// 		if err != nil {
	// 			return fmt.Errorf("metadata file read error: %v", err)
	// 		}
	// 		metadata := &MetaData{}
	// 		err = json.Unmarshal(content, metadata)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		for _, b := range metadata.Blocks {
	// 			var targetLoc string
	// 			if strings.HasPrefix(b.File, "/home/user/workspace/gowork/src/gotestenv/src/") { // tmp GOROOT
	// 				targetLoc = strings.Replace(b.File, "/home/user/workspace/gowork/src/gotestenv/src/", "", -1)
	// 			} else if strings.Contains(b.File, "go-fdg-exmaples/std/") { //fdg
	// 				targetLoc = b.File[strings.LastIndex(b.File, "go-fdg-exmaples/std/")+len("go-fdg-exmaples/std/"):]
	// 			} else { // in /tmp
	// 				continue
	// 			}
	// 			bitmap[b.ID] = fmt.Sprintf("%s:%d", targetLoc, b.StartLine)
	// 		}
	// 		return nil
	// 	}
	// 	parseBitmap := func(bitmap []string, coverfile string, coveredBlocksId *[]int) {
	// 		coverMap, err := ioutil.ReadFile(coverfile)
	// 		if err != nil {
	// 			return
	// 		}
	// 		for i, v := range coverMap {
	// 			if v >= 1 {
	// 				*coveredBlocksId = append(*coveredBlocksId, i) // attention to offset, maybe i+1?
	// 			}
	// 		}
	// 	}
	// 	parseStaticcheck := func(staticcheckFile string, potentialBugs map[string]bool) error {
	// 		//{"code":"FDU0006","severity":"error","location":{"file":"/home/user/.local/gosource/go1.17.8/src/unicode/casetables.go",
	// 		// "line":13,"column":20},"end":{"file":"/home/user/.local/gosource/go1.17.8/src/unicode/casetables.go","line":18,"column":2},
	// 		// "message":"safe%!(EXTRA string=nil length - rule4)"}
	// 		content, err := ioutil.ReadFile(staticcheckFile)
	// 		if err != nil {
	// 			return fmt.Errorf("staticcheck file read error: %v", err)
	// 		}
	// 		contentLines := bytes.Split(content, []byte("\n"))
	// 		for _, reportLine := range contentLines {
	// 			report := &JsonResult{}
	// 			err := json.Unmarshal(reportLine, report)
	// 			if err != nil {
	// 				continue
	// 			}
	// 			// ad-hoc to goroot as /home/user/.local/go/src/
	// 			// TODO(jx): maybe get this info from metainfo of func is more reasonable?
	// 			potentialPoint := fmt.Sprintf("%s:%d", strings.SplitN(report.Location.File, "src/", 2)[1], report.Location.Line)
	// 			potentialBugs[potentialPoint] = true
	// 		}
	// 		return nil
	// 	}
	// 	unzipstr := fmt.Sprintf("unzip %s/%s.zip \"metadata\" -d %s", fprocess.cmd.Dir, fprocess.name, fprocess.cmd.Dir)
	// 	exec.Command("/bin/sh", "-c", unzipstr).Run()
	// 	metadatafile := filepath.Join(fprocess.cmd.Dir, "metadata")
	// 	defer os.Remove(metadatafile)
	// 	// all file path here is normalized, split it from src/ or std/
	// 	coverfile := filepath.Join(fprocess.cmd.Dir, "maxCover.log") // DONE(jx): mudify the go-fuzz to generate this file
	// 	bitmap := make([]string, bitmapSize)
	// 	parseMetaData(metadatafile, bitmap)    // bitmap is ret arg
	// 	potentialBugs := make(map[string]bool) // DONE(jx): parse the staticcheck output
	// 	staticcheckFile := filepath.Join(os.Getenv("GOROOT"), "src", fprocess.cmd.Dir, "staticcheckresult-"+fprocess.name[4:])
	// 	parseStaticcheck(staticcheckFile, potentialBugs) // potentialBugs is ret arg
	// 	coveredPotential := make(map[string]bool)
	// 	coveredBlocksId := make([]int, 0)
	// 	parseBitmap(bitmap, coverfile, &coveredBlocksId) // coveredBlocks is ret arg
	// 	for _, coveredBbId := range coveredBlocksId {
	// 		if potentialBugs[bitmap[coveredBbId]] {
	// 			coveredPotential[bitmap[coveredBbId]] = true
	// 		}
	// 	}
	// 	// fuzz has exited
	// 	var resBytes string
	// 	for coveredP := range coveredPotential {
	// 		resBytes += coveredP + "\n"
	// 	}
	// 	coveredBugPointCount = len(coveredPotential)
	// 	ioutil.WriteFile(filepath.Join(fprocess.cmd.Dir, "covered.txt"), []byte(resBytes), 0644)
	// }

	fuzzOutputF, err := os.OpenFile(filepath.Join(fprocess.cmd.Dir, "fuzzOutput.log"), os.O_CREATE|os.O_WRONLY, 0666)
	defer fuzzOutputF.Close()
	if err != nil {
		panic("fuzz output log open failed")
	}
	lineidx := 0

	for fuzzcmd.ProcessState == nil {
		time.Sleep(1 * time.Second)
		outline, _, err := r.ReadLine()
		if err != nil {
			if fuzzcmd.ProcessState != nil && fuzzcmd.Process != nil {
				fuzzcmd.Process.Kill()
			}
			break
		}
		if lineidx%3 == 0 {
			// about log 1 line per 9 seconds
			fuzzOutputF.Write(append(outline, []byte("\n")...))
		}
		lineidx++
		if parseLine(outline) != 0 {
			continue
		}
		if uptime > 600 && cover == 0 {
			if fuzzcmd.ProcessState != nil && fuzzcmd.Process != nil {
				corpus, cover, crashes = -1, -1, 0
				fuzzcmd.Process.Kill()
			}
			break
		}
		if crashes > 100 {
			if fuzzcmd.ProcessState != nil && fuzzcmd.Process != nil {
				fuzzcmd.Process.Kill()
			}
			break
		}
	}

	//hitPotentialBugPoint()
	return
}

func runImmediatelyFuzz(succChan chan string, fuzChan chan string) {
	workPool := make(chan string, *flagWorkers)
	results := make([]*FuzzRes, 0)
	wg := new(sync.WaitGroup)
	mu := new(sync.Mutex)
	go clearTmp()

	for binname := range succChan {
		if strings.Contains(binname, "resultFuzz") {
			continue
		}

		for {
			// DONE(jx): if want suspend the fuzz, create the file, and wait the existing fuzz to finish
			// rm that file to continue add new fuzz target into pool
			if !fileExists(filepath.Join(autogofuzz_dir, "suspendFuzz")) {
				break
			}
			time.Sleep(5 * time.Minute)
		}

		wg.Add(1)
		workPool <- binname
		go startFuzz(workPool, binname, results, wg, mu)
	}
	wg.Wait()
	<-fuzChan
}
