package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v2"
	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

var flagRootDir = flag.String("root", "purelib", "Root directory to search for files")
var flagProj = flag.String("proj", "", "Project to search for files")

func main() {
	flag.Parse()
	if *flagProj == "" {
		panic("No project specified")
	}
	yamldir := *flagProj + "_yaml_out_dir"
	os.Chdir(filepath.Join(os.Getenv("GOPATH"), "src", *flagRootDir, *flagProj))
	rd, err := ioutil.ReadDir(yamldir)
	if err != nil {
		panic(err)
	}

	numOfTestCases := len(rd)
	fuzzCallInfo := make(map[string][]int) //the whole call info for proj
	sameCallButDifferentArgs := 0
	affectedTestCases := 0

	for _, yamlf := range rd {
		yamlbyte, err := ioutil.ReadFile(filepath.Join(yamldir, yamlf.Name()))
		if err != nil {
			panic(err)
		}
		meta := &metainfo.TestCaseMetaInfo{}
		err = yaml.Unmarshal(yamlbyte, meta)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] yaml unmarshal failed for %s\n", yamlf.Name())
			continue
		}
		//fuzzedCall marks the which args are fuzzed for a call
		fuzzedCall := make(map[string][]int)
		for _, relatedVar := range meta.VariableList {
			if relatedVar.IsImmediateVariable {
				if relatedVar.VarType == -1 {
					continue
				}
				addFuzzedArgs(fuzzedCall, relatedVar.Callee, relatedVar.ArgIndex)
			} else {
				if len(relatedVar.VarRelatedConstSources) == 0 && len(relatedVar.VarRelatedGlobalSources) == 0 {
					continue
				}
				addFuzzedArgs(fuzzedCall, relatedVar.Callee, relatedVar.ArgIndex)
			}
		}
		affected := false
		for callee, fuzzedArgs := range fuzzedCall {
			// sort
			sort.Sort(sort.IntSlice(fuzzedArgs))
			fuzzedCall[callee] = fuzzedArgs

			// check it in fuzzCallInfo
			if _, ok := fuzzCallInfo[callee]; !ok {
				fuzzCallInfo[callee] = fuzzedArgs
				continue
			} else {
				if !listEqual(fuzzedArgs, fuzzCallInfo[callee]) {
					sameCallButDifferentArgs++
					affected = true
				}
			}
		}
		if affected {
			affectedTestCases++
		}

	}

	fmt.Printf("[+] %d different fuzz-arg calls in %d testcases, %d in tatal.\n", sameCallButDifferentArgs, affectedTestCases, numOfTestCases)
}

func addFuzzedArgs(fuzzedCall map[string][]int, callee string, fuzzedArgIdx int) {
	if _, ok := fuzzedCall[callee]; !ok {
		fuzzedCall[callee] = []int{fuzzedArgIdx}
	} else {
		if !isElemInList(fuzzedArgIdx, fuzzedCall[callee]) {
			fuzzedCall[callee] = append(fuzzedCall[callee], fuzzedArgIdx)
		}
	}
}

func isElemInList(elem int, list []int) bool {
	for _, e := range list {
		if elem == e {
			return true
		}
	}
	return false
}

func listEqual(lista, listb []int) bool {
	if len(lista) != len(listb) {
		return false
	}
	for i := 0; i < len(lista); i++ {
		if lista[i] != listb[i] {
			return false
		}
	}
	return true
}
