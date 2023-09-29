package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

var flagProj = flag.String("proj", "", "project name")

var flagRootDir = flag.String("rootdir", "go-fdg-exmaples", "root dir")

func main() {
	flag.Parse()
	fdgpath := filepath.Join(os.Getenv("GOPATH"), "src", *flagRootDir)
	projsWithYaml := getProjs()
	var candidates map[string]string
	if *flagProj == "" {
		candidates = projsWithYaml //all proj
	} else {
		candidates = make(map[string]string)
		candidates[*flagProj] = projsWithYaml[*flagProj]
	}
	for proj, yamlDir := range candidates {
		os.Chdir(filepath.Join(fdgpath, proj))
		fmt.Println(proj, yamlDir)
		if proj == "etcd" || proj == "kubernetes" || proj == "tidb" || proj == "gorm" || proj == "std" {
			continue
		}
		yamlNum := 0
		failNum := 0
		NoGetX := 0
		otherErr := 0

		// failCase := make(map[FailType]int)
		failFromIR := make([]string, 0)
		failFromAst := make([]string, 0)

		metainfo := new(TestCaseMetaInfo)
		fs, _ := ioutil.ReadDir(yamlDir)
		for _, yamlf := range fs {
			yamlNum++
			yamlbytes, _ := ioutil.ReadFile(filepath.Join(yamlDir, yamlf.Name()))
			yaml.Unmarshal(yamlbytes, metainfo)
			testName := metainfo.Name[strings.LastIndex(metainfo.Name, ".")+1:]

			logname := strings.Join(strings.Split(metainfo.Name[strings.LastIndex(metainfo.Name, "/"+proj+"/")+1:], "/")[1:], "-")
			if strings.HasPrefix(logname, "v2") || strings.HasPrefix(logname, "v3") {
				logname = logname[3:]
			}
			logname = strings.Replace(logname, ".", "-", -1) + ".log" //TODO: dis v2

			datefs, _ := ioutil.ReadDir("FuzzGenResult")
			foundLog := false
			for _, datedir := range datefs {
				logfs, _ := ioutil.ReadDir(filepath.Join("FuzzGenResult", datedir.Name(), proj))
				for _, logf := range logfs {
					if logf.Name() == logname {
						failNum++
						foundLog = true
						failinfo, _ := ioutil.ReadFile(filepath.Join("FuzzGenResult", datedir.Name(), proj, logf.Name()))

						if strings.Contains(string(failinfo), "Cannot find transstruct.Get") {
							NoGetX++
							// parse the yaml to judge if the fail dues to IR or AST
							if yamlHasArg(metainfo) {
								failFromAst = append(failFromAst, yamlf.Name())
							} else {
								failFromIR = append(failFromIR, yamlf.Name())
							}
						} else {
							otherErr++
						}
						break
					}
				}
				if foundLog {
					break
				}
			}
			if !foundLog && !fileExists(filepath.Join(filepath.Dir(metainfo.SrcPath), "Fuzz"+testName+".zip")) {
				otherErr++
			}

		}

		fmt.Printf("%s, %d, %d, %d, %d, %d, %d\n", proj, yamlNum, failNum, otherErr, NoGetX, len(failFromIR), len(failFromAst))
		for _, yf := range failFromAst {
			fmt.Println(yf)
		}

	}

}
