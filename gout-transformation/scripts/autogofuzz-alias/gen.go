package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sbwhitecap/tqdm"
	"github.com/sbwhitecap/tqdm/iterators"
	"gopkg.in/yaml.v2"
	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

func checkTargetIsAlias(yamlname string) bool {
	tcmi := new(metainfo.TestCaseMetaInfo)
	metabytes, err := ioutil.ReadFile(yamlname)
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = yaml.Unmarshal(metabytes, tcmi)
	if err != nil {
		fmt.Println(err)
		return false
	}
	for _, relatedVar := range tcmi.VariableList {
		for _, relatedConst := range relatedVar.VarRelatedConstSources {
			if len(relatedConst.MustAlias) > 0 {
				return true
			}
		}
	}
	return false
}

func genForProj(proj, yamldir string, finishChan chan string, succChan chan string, fuzzinchan chan string) {
	fmt.Fprintf(os.Stderr, "[+] Start to generate %s\n", proj)
	succ := make([]string, 0)
	fail := make([]string, 0)
	nogetx := make([]string, 0)
	nores := make([]string, 0)

	logDirName := fmt.Sprintf("FuzzGenResult/%02d%02d/%s", int(time.Now().Month()), time.Now().Day(), proj)
	fmt.Println("start to gen for ", proj)
	fmt.Println(logDirName)
	if !fileExists(logDirName) {
		os.MkdirAll(logDirName, os.ModePerm)
	}
	rd, err := ioutil.ReadDir(yamldir)
	if err != nil {
		panic(err)
	}

	tqdm.With(iterators.Interval(0, len(rd)), "Generating", func(v interface{}) (brk bool) {

		clearCmd := "find . -name \"*test.go*fuzz.go\" | xargs rm"
		exec.Command("/bin/sh", "-c", clearCmd).Run()
		clearCmd = "find . -name \"*test.go*test.go\" | xargs rm"
		exec.Command("/bin/sh", "-c", clearCmd).Run()

		metaInfo := new(TestCaseMetaInfo)
		// metaInfo := new(CallsiteMeta)
		_ = metaInfo
		fi := rd[v.(int)]
		if !checkTargetIsAlias(filepath.Join(yamldir, fi.Name())) {
			return
		}

		targetF := strings.Split(fi.Name(), ".")[len(strings.Split(fi.Name(), "."))-2]
		yamlbyte, _ := ioutil.ReadFile(filepath.Join(yamldir, fi.Name()))
		yaml.Unmarshal([]byte(yamlbyte), metaInfo)
		targetPath := filepath.Dir(metaInfo.SrcPath)

		fuzzZipName := fmt.Sprintf("Fuzz%s.zip", targetF)
		if haveGened(proj, filepath.Join(targetPath, fuzzZipName), true) {
			return
		}
		genCmd := fmt.Sprintf("%s -dir=%s -spe=%s", *flagTransformer, yamldir, targetF)
		cmd := exec.Command("/bin/sh", "-c", genCmd)

		comOut, _ := cmd.CombinedOutput()

		if haveGened(proj, filepath.Join(targetPath, fuzzZipName), false) {
			if succChan != nil {
				succChan <- filepath.Join(targetPath, fuzzZipName)
			}
			succ = append(succ, filepath.Join(targetPath, targetF))
		} else {
			// failed
			findReason := false
			for _, line := range strings.Split(string(comOut), "\n") {
				if strings.Contains(line, "[-] Cannot find transstruct.Get") {
					nogetx = append(nogetx, filepath.Join(targetPath, targetF))
					findReason = true
					break
				} else if strings.Contains(line, "[-] Cannot build") {
					fail = append(fail, filepath.Join(targetPath, targetF))
					findReason = true
					break
				}
			}
			if !findReason {
				nores = append(nores, filepath.Join(targetPath, targetF))
			}
			ioutil.WriteFile(filepath.Join(logDirName, fmt.Sprintf("%s-%s.log", strings.Replace(targetPath, "/", "-", -1), targetF)), comOut, 0666)
		}
		return
	})

	succBytes := make([]byte, 0)
	failBytes := make([]byte, 0)
	noGetXBytes := make([]byte, 0)
	noResBytes := make([]byte, 0)

	for _, v := range succ {
		succBytes = append(succBytes, []byte(v+"\n")...)
	}
	for _, v := range fail {
		failBytes = append(failBytes, []byte(v+"\n")...)
	}
	for _, v := range nogetx {
		noGetXBytes = append(noGetXBytes, []byte(v+"\n")...)
	}
	for _, v := range nores {
		noResBytes = append(noResBytes, []byte(v+"\n")...)
	}
	ioutil.WriteFile(filepath.Join(logDirName, "succ.txt"), succBytes, os.ModePerm)
	ioutil.WriteFile(filepath.Join(logDirName, "fail.txt"), failBytes, os.ModePerm)
	ioutil.WriteFile(filepath.Join(logDirName, "nogetx.txt"), noGetXBytes, os.ModePerm)
	ioutil.WriteFile(filepath.Join(logDirName, "nores.txt"), noResBytes, os.ModePerm)

	<-finishChan

	if succChan != nil {
		close(succChan)
	}
	fmt.Fprintf(os.Stderr, "[+] All bins has finished generating for %s \n", proj)
	if succChan != nil { // or mode=3
		for len(fuzzinchan) > 0 {
			time.Sleep(time.Minute)
		}
		fmt.Fprintf(os.Stderr, "[+] All fuzzin has finished fuzzing for %s \n", proj)
	}

}

func haveGened(proj, binloc string, checkForce bool) bool {
	if checkForce && *flagForce {
		os.Rename(binloc, binloc+".bak")
		return false
	}
	exist := fileExists(binloc)
	if !exist {
		os.Rename(binloc+".bak", binloc)
	} else {
		os.Remove(binloc + ".bak")
	}
	return exist
}
