package apiutil

import (
	"encoding/json"
	"fmt"
	"go/types"
	"golang.org/x/tools/go/ssa"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func getAllAPIMap(path string) *pkgCallableAPIMap {
	mapOfProj := &pkgCallableAPIMap{
		path: path,
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println("New a map file")
		if err := ioutil.WriteFile(path, []byte("{}"), 0644); err != nil {
			panic(err)
		}
	} else {
		f, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(f, &mapOfProj.allFuncMethodDecl)
		if err != nil {
			panic(err)
		}
	}
	return mapOfProj
}

func (p *pkgCallableAPIMap) printFuncMap() {
	for key, lists := range p.allFuncMethodDecl {
		fmt.Println(key)
		for _, fn := range lists {
			fmt.Println("\t-----", fn)
			fmt.Println()
		}
	}

}

func (p *pkgCallableAPIMap) printFuncMapLen() {
	fmt.Println(len(p.allFuncMethodDecl))
}

func (p *pkgCallableAPIMap) storeMapToFile() {
	bytes, err := json.MarshalIndent(p.allFuncMethodDecl, "", "\t")
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(p.path, bytes, 0644)
	if err != nil {
		panic(err)
	}
}

func (p *pkgCallableAPIMap) setOneFuncCalleesToAllFuncMathodDecl(fn *ssa.Function, lastFile string) {
	for _, block := range fn.Blocks {
		for _, inst := range block.Instrs {
			if callPtr, toCallOk := inst.(*ssa.Call); toCallOk {
				callee := callPtr.Call.StaticCallee()
				if callee != nil {
					calleeFile := fn.Prog.Fset.Position(callee.Pos()).Filename
					thisFile := fn.Prog.Fset.Position(fn.Pos()).Filename
					if thisFile == calleeFile && thisFile != lastFile {
						lastFile = thisFile // prevent form recursively call, inter-procedure get only 1 depth
						p.setOneFuncCalleesToAllFuncMathodDecl(callee, lastFile)
						continue
					}
					p.allFuncMethodDecl[callPtr.Call.StaticCallee().String()] = fn.String()
				} else {
					fmt.Println("\t----Abstract(No IR): ", callPtr.String())
				}
			}
		}
	}
}

func (p *pkgCallableAPIMap) setOneFuncToAllFuncMethodDecl(fn types.Object, pkg *ssa.Package) {
	fileName := pkg.Prog.Fset.Position(fn.Pos()).Filename
	if fileNameFilter(fileName) {
		return
	}
	lineNum := pkg.Prog.Fset.Position(fn.Pos()).Line
	funcString := fn.String()
	p.allFuncMethodDecl[getFileNumStr(fileName, lineNum)] = funcString
}

func (p *pkgCallableAPIMap) setOneFuncToAllFuncDecl(fn *ssa.Function) {
	fileName := fn.Prog.Fset.Position(fn.Pos()).Filename
	if fileNameFilter(fileName) {
		return
	}
	lineNum := fn.Prog.Fset.Position(fn.Pos()).Line
	funcString := fn.String()
	p.allFuncDecl[getFileNumStr(fileName, lineNum)] = funcString
}

func (p *pkgCallableAPIMap) setOneFuncToExportFuncDecl(fn *ssa.Function) {
	fileName := fn.Prog.Fset.Position(fn.Pos()).Filename
	if fileNameFilter(fileName) {
		return
	}
	lineNum := fn.Prog.Fset.Position(fn.Pos()).Line
	funcString := fn.String()
	p.exportFuncDecl[getFileNumStr(fileName, lineNum)] = funcString
}

func (p *pkgCallableAPIMap) setOneFuncToInternalFuncDecl(fn *ssa.Function) {
	fileName := fn.Prog.Fset.Position(fn.Pos()).Filename
	if fileNameFilter(fileName) {
		return
	}
	lineNum := fn.Prog.Fset.Position(fn.Pos()).Line
	funcString := fn.String()
	p.internalFuncDecl[getFileNumStr(fileName, lineNum)] = funcString
}

func (p *pkgCallableAPIMap) setOneFuncToAllMethodDecl(fn types.Object, pkg *ssa.Package) {
	fileName := pkg.Prog.Fset.Position(fn.Pos()).Filename
	if fileNameFilter(fileName) {
		return
	}
	lineNum := pkg.Prog.Fset.Position(fn.Pos()).Line
	funcString := fn.String()
	p.allMethodDecl[getFileNumStr(fileName, lineNum)] = funcString
}

func (p *pkgCallableAPIMap) setOneFuncToExportMethodDecl(fn types.Object, pkg *ssa.Package) {
	fileName := pkg.Prog.Fset.Position(fn.Pos()).Filename
	if fileNameFilter(fileName) {
		return
	}
	lineNum := pkg.Prog.Fset.Position(fn.Pos()).Line
	funcString := fn.String()
	p.exportMethodDecl[getFileNumStr(fileName, lineNum)] = funcString
}

func (p *pkgCallableAPIMap) setOneFuncToInternalMethodDecl(fn types.Object, pkg *ssa.Package) {
	fileName := pkg.Prog.Fset.Position(fn.Pos()).Filename
	if fileNameFilter(fileName) {
		return
	}
	lineNum := pkg.Prog.Fset.Position(fn.Pos()).Line
	funcString := fn.String()
	p.internalMethodDecl[getFileNumStr(fileName, lineNum)] = funcString
}

func getFileNumStr(fileName string, lineNum int) string {
	return strings.Join([]string{fileName, ":", strconv.Itoa(lineNum)}, "")
}

func fileNameFilter(path string) bool {
	if strings.Contains(path, ".local/go") ||
		strings.Contains(path, "/home/gogen/workspace/gowork/pkg/") ||
		strings.Contains(path, "_test.go") {
		return true
	}
	return false
}
