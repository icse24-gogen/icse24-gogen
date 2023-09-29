package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var flagProjs = flag.String("projs", "", "proj to analyze, use\",\"to ")
var flagDir = flag.String("dir", "", "relative path from $GOPATH/src/")

func main() {
	flag.Parse()
	if *flagProjs == "" || *flagDir == "" {
		panic("arg not set")
	}
	cwd, _ := os.Getwd()
	workdir := filepath.Join(os.Getenv("GOPATH"), "src", *flagDir)
	os.Chdir(workdir)
	projs := strings.Split(*flagProjs, ",")
	for _, p := range projs {
		fmt.Println("[*] Running proj", p)
		os.Chdir(filepath.Join(workdir, p))

		coverage := make(map[string]int) // which fuzz driver cover blocks
		resname := fmt.Sprintf("testCov-%02d%02d-%s.json", time.Now().Month(), time.Now().Day(), p)
		resfile, _ := os.OpenFile(filepath.Join(cwd, resname), os.O_CREATE|os.O_WRONLY /*(|os.O_APPEND)*/, 0666)
		// resfile.Write([]byte("Fuzz入口, Testcase覆盖基本块数量\n"))
		findcmd := exec.Command("/bin/sh", "-c", `find . -name "Fuzz*.zip" | grep -v "result"`)
		outinfo, err := findcmd.CombinedOutput()
		if err != nil {
			fmt.Println(fmt.Errorf("[*] Error: %v", err))
			continue
		}
		bins := strings.Split(strings.TrimRight(string(outinfo), "\n"), "\n")
		for idx, binname := range bins {
			if !true {
				//TODO(jx): exclude the bins that can't run successfully
				continue
			}
			coverBBNum := getCoverBBNum(binname)
			if coverBBNum > 0 {
				coverage[binname] = coverBBNum
			}

			// resfile.Write([]byte(fmt.Sprintf("%s, %d\n", binname, coverBBNum)))
			if idx%100 == 0 {
				clearsys()
			}

		}
		covByte, _ := json.MarshalIndent(coverage, "", "	")
		resfile.Write(covByte)
		resfile.Close()
		fmt.Printf("[+] %d for proj %s\n", len(coverage), p)

	}
}

func getCoverBBNum(binpath string) (count int) {
	projwd, _ := os.Getwd()
	os.Chdir(filepath.Dir(binpath))
	defer os.Chdir(projwd)
	testDryRunCov := "testDryRunCov"
	binname := filepath.Base(binpath)
	os.Mkdir(testDryRunCov, 0777)
	defer os.RemoveAll(testDryRunCov)

	//cp bin to that dir
	// dry run the bin
	// count cover block num through maxcover.log
	// return
	exec.Command("/bin/sh", "-c", fmt.Sprintf("cp %s %s", binname, testDryRunCov)).Run()
	os.Chdir(testDryRunCov)
	defer os.Chdir("..")
	fuzzcmd := `go-fuzz -dryrun=true -procs=1 -bin=` + binname
	exec.Command("/bin/sh", "-c", fuzzcmd).Run()
	bitmap, err := os.ReadFile("maxCover.log")
	if err != nil {
		// fmt.Println(fmt.Errorf("[-] bitmap read failed for %s", binname))
		return -1
	}
	for _, b := range bitmap {
		if b > 0 {
			count++
		}
	}
	return
}

func clearsys() {
	exec.Command("/bin/sh", "-c", `cd /tmp; find . -maxdepth 1 -user user -type f -delete -mmin +5`).Run()
	// exec.Command("/bin/sh", "-c", `kill -9 $(ps -ef | grep fuzz |grep -v grep|awk '{print $2}')`).Run()
}
