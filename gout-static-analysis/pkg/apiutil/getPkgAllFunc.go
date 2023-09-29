package apiutil

import (
	"golang.org/x/tools/go/ssa"
	"xyz.asd.qwe/gout-static-analysis/pkg/pkgutils"
)

type FuncType int32

const (
	// FUZZ : get Fuzz funcs, set Fuzzer's callee to Map
	FUZZ FuncType = 0 //func Fuzz(...

	// AllAPI : get funcs, methods, set funcs, methods to Map
	AllAPI FuncType = 1

	// ExportFunc InternalFunc AllFunc : get funcs, set funcs to Map
	ExportFunc   FuncType = 2 //Func [A-Z].*(...
	InternalFunc FuncType = 3 //Func [a-z].*(...
	AllFunc      FuncType = 4 //Func [A-Za-z].*(...

	// ExportMethodFunc InternalMethodFunc AllMethodFunc : get methods, set methods to Map
	ExportMethodFunc   FuncType = 5 //Func (.* \*{0,1}"$struct") [A-Z].*(...
	InternalMethodFunc FuncType = 6 //Func (.* \*{0,1}"$struct") [a-z].*(...
	AllMethodFunc      FuncType = 7 //Func (.* \*{0,1}"$struct") [A-Za-z].*(...

	//
	//todo : abstract?
)

type pkgCallableAPIMap struct {
	/*
	   key:value -- func : appear where
	   for FUZZ
	       func = the fuzzed api's String(pkgString+name) appear in fuzzer
	       appear where = the callee is fuzzed in "which" fuzzer's func String(pkgString+name)
	   for Others
	       func = the func/method String(pkgString+name)
	       appear where = "$fileName:$lineNumber"
	*/
	allFuncMethodDecl map[string]string `json:"allFuncMethodDecl"`

	/*
	   subset of allFuncMethodDecl exportFuncDecl internalFuncDecl allFuncDecl exportMethodDecl internalMethodDecl allMethodDecl
	   will be initialized in handler
	*/
	exportFuncDecl     map[string]string `json:"exportFuncDecl"`
	internalFuncDecl   map[string]string `json:"internalFuncDecl"`
	allFuncDecl        map[string]string `json:"allFuncDecl"`
	exportMethodDecl   map[string]string `json:"exportMethodDecl"`
	internalMethodDecl map[string]string `json:"internalMethodDecl"`
	allMethodDecl      map[string]string `json:"allMethodDecl"`
	//看要不要再抽象出一层pkg

	//store path,json format
	path string `json:"path"`
}

func LoadPkg(storePath string) {
	strings := []string{"./..."}
	pkgsSsa := pkgutils.LoadProjPackages(strings)

	//stdMap := getAllAPIMap("/home/gogen/workspace/gowork/src/oss/gostd/tmp.json")
	projMap := getAllAPIMap(storePath)
	for _, pkg := range pkgsSsa {
		if pkg == nil {
			continue
		}
		handlePkgGetCallableAPIs(pkg, projMap, AllAPI)
	}
	projMap.storeMapToFile()
	projMap.printFuncMapLen()
}

var pkgHandlerList = []func(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap){
	handlePkgSetFuzzFuncCallee, //get Fuzz funcs, set Fuzzer's callee to Map
	handlePkgSetAllAPI,
	handlePkgSetExportFunc,
	handlePkgSetInternalFunc,
	handlePkgSetAllFunc,
	handlePkgSetExportMethod,
	handlePkgSetInternalMethod,
	handlePkgSetAllMethod,
}

func handlePkgGetCallableAPIs(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap, whatFunc FuncType) {
	handlerFunc := pkgHandlerList[whatFunc]
	handlerFunc(pkg, mapOfProj)
}
