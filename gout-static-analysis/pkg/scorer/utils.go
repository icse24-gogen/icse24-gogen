package scorer

import (
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log"
	"os"
	"path"
	"xyz.asd.qwe/gout-static-analysis/pkg/metainfo"
	"xyz.asd.qwe/gout-static-analysis/pkg/pkgutils"
	"strconv"
	"strings"
)

type globalDebugInfoController struct {
	logFileDir         string
	nowTestCaseName    string
	nowTestCaseLogFile *os.File
	nowProjLogFile     *os.File
}

var GDIC = globalDebugInfoController{}

func setLogFileDir(dir string) {
	GDIC.logFileDir = dir
	if _, err := os.Stat(dir); err != nil {
		err := os.MkdirAll(dir, 0777)
		if err != nil {
			panic(err)
		}
	}
	f, err := os.OpenFile(path.Join(GDIC.logFileDir, "proj.log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}
	GDIC.nowProjLogFile = f
}

func setTCName(name string) {
	GDIC.nowTestCaseName = name
	tname := strings.Replace(name, ".", "_", -1)
	tname = strings.Replace(tname, "/", "-", -1)
	f, err := os.OpenFile(path.Join(GDIC.logFileDir, tname+".log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}
	GDIC.nowTestCaseLogFile = f
}

func printDebugInfo(info string) {
	log.SetOutput(GDIC.nowTestCaseLogFile)
	log.Println(info)
}

func printProjDebugInfo(info string) {
	log.SetOutput(GDIC.nowProjLogFile)
	log.Println(info)
}

func judgeWrapper(testCase *ssa.Function, fn *ssa.Function) bool { //统计test内封装函数的情况，看test内有没有（callee所在的文件不是以_test.go结尾的）
	callees := CollectCalleeOfFunction(testCase, fn, metainfo.DefaultAPICallType, nil)
	for _, callee := range callees {
		fileName := fn.Prog.Fset.Position(callee.Callee.Pos()).Filename
		if !strings.HasSuffix(fileName, "_test.go") {
			return false
		}
	}
	return true
}

/*
Extra Test Functions
*/

// MyExtractTry
// fn.String() -> github.com/beego/beego/v2/adapter.TestDate
// fn.Name() -> TestDate
func MyExtractTry(rootPatterns []string) {
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,

		Tests: true,
	}
	initial, err := packages.Load(cfg, rootPatterns[0:1]...)
	if err != nil {
		panic(err)
	}

	//prog, pkgs := ssautil.AllPackages(initial, ssa.NaiveForm)
	prog, pkgs := ssautil.Packages(initial, ssa.NaiveForm) //when specific project
	prog.Build()
	for _, pkg := range pkgs { //handle package
		if pkg != nil {
			for _, member := range pkg.Members {
				if fn, ok := member.(*ssa.Function); ok {
					if fn.String() == "command-line-arguments.main" {
						//if strings.Contains(fn.String(), "TestEndCall") {
						for _, inst := range fn.Blocks[0].Instrs {
							if inst, toStoreOk := inst.(*ssa.Store); toStoreOk {
								fmt.Println(fn.Prog.Fset.Position(inst.Pos()).Line)
								fmt.Println(fn.Prog.Fset.Position(inst.Pos()).Column)
							}
						}
						fn.WriteTo(os.Stdout)
					}
				}
			}
		}
	}
}

func trimFilePathPrefix(filepath string) string {
	return strings.TrimPrefix(filepath, filePrefix)
}

var pkgStructList map[string][]string

func judgeFuncLoc(testCase *ssa.Function, callee *ssa.Function) metainfo.CalleeType {
	/*testCaseFile := testCase.Prog.Fset.File(testCase.Pos()).Name()
	  calleFile := callee.Prog.Fset.File(testCase.Pos()).Name()
	  if testCaseFile == calleFile {
	      return metainfo.CalleeInTheSameFile
	  }*/
	/*calleeName := callee.Name()
	  if strings.Contains(calleeName, "[") { //go 1.18 Generics
	      calleeName = calleeName[:strings.Index(calleeName, "[")]
	  }
	*/
	/*printDebugInfo(calleeName)
	  printDebugInfo(calleeString)
	  printDebugInfo(calleePkgString)*/
	if callee.Pkg == nil { //Can't judge location
		return metainfo.MayThirdPackageCallee
	}
	calleeName := callee.Name()
	calleeString := callee.String()
	calleePkgString := callee.Pkg.String()

	if memberFun, ok := testCase.Pkg.Members[calleeName]; ok && calleePkgString == memberFun.Package().String() {
		return metainfo.ThisPackageCallee
	} //if found directly

	thisPkgStructList := pkgStructList[testCase.Pkg.String()]
	for _, structType := range thisPkgStructList {
		if strings.Contains(calleeString, structType) { //A Method
			return metainfo.ThisPackageCallee
		}
	}

	for _, pkg := range pkgutils.ThisProjPkgs {
		if pkg == nil || testCase.Package() == pkg {
			continue
		} else if pkg.Pkg.Path() == "testing" {
			continue
		}
		memberFun, ok := pkg.Members[calleeName]
		if ok && calleePkgString == memberFun.Package().String() {
			if strings.Contains(testCase.Pkg.String(), "_test") { //如果是_test包的其他包callee，还需要判断
				originPkgString := testCase.Pkg.String()[0 : len(testCase.Pkg.String())-5]
				if calleePkgString == originPkgString {

				}
				return metainfo.ThisPackageCallee
			}
			return metainfo.OtherPackageCallee
		}
		otherPkgStructList := pkgStructList[pkg.String()]
		for _, structType := range otherPkgStructList {
			if strings.Contains(calleeString, structType) { //A Method
				if strings.Contains(testCase.Pkg.String(), "_test") { //如果是_test包的其他包callee，还需要判断
					originPkgString := testCase.Pkg.String()[0 : len(testCase.Pkg.String())-5]
					if calleePkgString == originPkgString {

					}
					return metainfo.ThisPackageCallee
				}
				return metainfo.OtherPackageCallee
			}
		}
	}

	if pkgutils.JudgePkgIsStd(callee.Pkg.Pkg.Path()) {
		return metainfo.StdCallee
	}
	if pkgutils.JudgePkgIsTesting(callee.Pkg.Pkg.Path()) {
		return metainfo.TestingCallee
	}
	return metainfo.MayThirdPackageCallee
}

func findTestingBodyFunc(testFuncName string, callInstr ssa.CallInstruction, testCase *ssa.Function) *ssa.Function {

	switch testFuncName {
	case "Run":
		if funcPtr, toFuncOk := callInstr.Common().Args[2].(*ssa.Function); toFuncOk {
			return funcPtr
		} else if closurePtr, toClosureOk := callInstr.Common().Args[2].(*ssa.MakeClosure); toClosureOk {
			return closurePtr.Fn.(*ssa.Function)
		} else if unPtr, toUnOpOk := callInstr.Common().Args[2].(*ssa.UnOp); toUnOpOk {
			if allocPtr, toAllocOk := unPtr.X.(*ssa.Alloc); toAllocOk {
				for _, refInstr := range *allocPtr.Referrers() {
					if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk {
						if funcPtr, toFuncOk := storePtr.Val.(*ssa.Function); toFuncOk {
							return funcPtr
						} else if closurePtr, toClosureOk := storePtr.Val.(*ssa.MakeClosure); toClosureOk {
							return closurePtr.Fn.(*ssa.Function)
						}
					}
				}
			}
		}
	case "AllocsPerRun":
		if funcPtr, toFuncOk := callInstr.Common().Args[1].(*ssa.Function); toFuncOk {
			return funcPtr
		} else if closurePtr, toClosureOk := callInstr.Common().Args[1].(*ssa.MakeClosure); toClosureOk {
			return closurePtr.Fn.(*ssa.Function)
		} else if unPtr, toUnOpOk := callInstr.Common().Args[1].(*ssa.UnOp); toUnOpOk {
			if allocPtr, toAllocOk := unPtr.X.(*ssa.Alloc); toAllocOk {
				for _, refInstr := range *allocPtr.Referrers() {
					if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk {
						if funcPtr, toFuncOk := storePtr.Val.(*ssa.Function); toFuncOk {
							return funcPtr
						} else if closurePtr, toClosureOk := storePtr.Val.(*ssa.MakeClosure); toClosureOk {
							return closurePtr.Fn.(*ssa.Function)
						}
					}
				}
			}
		}
	}
	return nil
}

func constructPCGOfTestCase(g *callgraph.Graph, caller *callgraph.Node) {
	//callee := caller.Func.Blocks[0].Instrs[1].(*ssa.Call).Call.StaticCallee()
	//fNode := g.CreateNode(callee)
	//callgraph.AddEdge(caller, caller.Func.Blocks[0].Instrs[1].(ssa.CallInstruction), fNode)
	//return

	nextConstructList := make([]*callgraph.Node, 0)
	callerFile := caller.Func.Prog.Fset.Position(caller.Func.Pos()).Filename
	for _, block := range caller.Func.Blocks {
		for _, instr := range block.Instrs {
			if site, ok := instr.(ssa.CallInstruction); ok { //函数内找call指令，并对三种API进行PCG的构建
				callee := site.Common().StaticCallee()
				if callee == nil {
					continue
				}

				calleeFile := callee.Prog.Fset.Position(callee.Pos()).Filename
				if strings.HasSuffix(callerFile, "_test.go") && // call的函数在_test.go文件内，认为是wrapper
					strings.HasSuffix(calleeFile, "_test.go") &&
					!strings.Contains(callee.String(), "$") &&
					callee.Signature.Recv() == nil {
					//若caller和callee都在_test.go文件中，且callee不是匿名函数,不是结构体，则添加边
					if _, ok := g.Nodes[callee]; !ok {
						if debugMode {
							printDebugInfo("----[ok]Found a wrapper function: " + callee.String())
						}
						nextConstructList = append(nextConstructList, g.CreateNode(callee))
					}
					fNode := g.CreateNode(callee) //If not exist, CreatNode will creat a new one
					callgraph.AddEdge(caller, site, fNode)
				}

				//testing API
				if callee.String() == "(*testing.T).Run" { //对testing API的建模，树上的节点是匿名函数，边用的是call testingAPI
					funcBody := findTestingBodyFunc("Run", site, g.Root.Func)
					if funcBody == nil {
						continue
					}
					if _, ok := g.Nodes[funcBody]; !ok {
						if debugMode {
							printDebugInfo("----[ok]Found (*testing.T).Run")
						}
						nextConstructList = append(nextConstructList, g.CreateNode(funcBody))
					}
					fNode := g.CreateNode(funcBody) //If not exist, creat a new one
					callgraph.AddEdge(caller, site, fNode)
					testCaseHaveTestingAPI = true
				} else if callee.String() == "testing.AllocsPerRun" {
					funcBody := findTestingBodyFunc("AllocsPerRun", site, g.Root.Func)
					if funcBody == nil {
						continue
					}
					if _, ok := g.Nodes[funcBody]; !ok {
						if debugMode {
							printDebugInfo("----[ok]Found testing.AllocsPerRun")
						}
						nextConstructList = append(nextConstructList, g.CreateNode(funcBody))
					}
					fNode := g.CreateNode(funcBody) //If not exist, CreatNode will creat a new one
					callgraph.AddEdge(caller, site, fNode)
					testCaseHaveTestingAPI = true
				}
			}
		}
	}
	for _, next := range nextConstructList {
		constructPCGOfTestCase(g, next) //递归构建，广度遍历
	}
}

func constructFCGOfTestCase(testcase *ssa.Function, g *callgraph.Graph, caller *callgraph.Node) {
	nextConstructList := make([]*callgraph.Node, 0)
	//callerLoc := judgeFuncLoc(testcase, caller.Func)
	for _, block := range caller.Func.Blocks {
		for _, instr := range block.Instrs {
			if site, ok := instr.(ssa.CallInstruction); ok {
				callee := site.Common().StaticCallee()
				if callee == nil {
					continue
				}

				calleeLoc := judgeFuncLoc(testcase, callee) //需要和testcase在一个包
				if pkgutils.JudgePkgIsStd(testcase.Pkg.String()) {
					if calleeLoc != metainfo.ThisPackageCallee || strings.Contains(callee.String(), "$") {
						continue
					}
				} else {
					if calleeLoc == metainfo.MayThirdPackageCallee || calleeLoc == metainfo.StdCallee ||
						strings.Contains(callee.String(), "$") {
						continue
					}
				}

				//若caller和callee都是库中的函数
				if _, ok := g.Nodes[callee]; !ok {
					nextConstructList = append(nextConstructList, g.CreateNode(callee))
				}
				fNode := g.CreateNode(callee) //If not exist, creat a new one
				callgraph.AddEdge(caller, site, fNode)

				//testing API
				if callee.String() == "(*testing.T).Run" {
					funcBody := findTestingBodyFunc("Run", site, g.Root.Func)
					if funcBody == nil {
						continue
					}
					if _, ok := g.Nodes[funcBody]; !ok {
						nextConstructList = append(nextConstructList, g.CreateNode(funcBody))
					}
					fNode := g.CreateNode(funcBody) //If not exist, creat a new one
					callgraph.AddEdge(caller, site, fNode)
				} else if callee.String() == "testing.AllocsPerRun" {
					funcBody := findTestingBodyFunc("AllocsPerRun", site, g.Root.Func)
					if funcBody == nil {
						continue
					}
					if _, ok := g.Nodes[funcBody]; !ok {
						nextConstructList = append(nextConstructList, g.CreateNode(funcBody))
					}
					fNode := g.CreateNode(funcBody) //If not exist, CreatNode will creat a new one
					callgraph.AddEdge(caller, site, fNode)
				}
			}
		}
	}
	for _, next := range nextConstructList {
		constructFCGOfTestCase(testcase, g, next) //递归构建
	}
}

func findLocalTableLengthAndItemElemCount(allocTable *ssa.Alloc) (int, int) {
	for _, refInst := range *allocTable.Referrers() {
		if storePtr, toStoreOk := refInst.(*ssa.Store); toStoreOk &&
			storePtr.Addr.Name() == allocTable.Name() {
			if slicePtr, toSliceOk := storePtr.Val.(*ssa.Slice); toSliceOk {
				newAllocPtr, toAllocOk := slicePtr.X.(*ssa.Alloc)
				if !toAllocOk {
					newAllocPtr, toAllocOk = slicePtr.X.(*ssa.UnOp).X.(*ssa.Alloc)
					if !toAllocOk {
						return -1, -1
					}
				}

				lengthStr := newAllocPtr.Type().String()
				length, err := strconv.Atoi(lengthStr[strings.Index(lengthStr, "[")+1 : strings.Index(lengthStr, "]")])
				if err != nil {
					if debugMode {
						printDebugInfo("------Can't get length of local Table")
					}
					return -1, -1
				}

				elemCount := -1
				for _, findIndexRefInst := range *newAllocPtr.Referrers() {
					if indexAddrPtr, toIndexAddrOk := findIndexRefInst.(*ssa.IndexAddr); toIndexAddrOk {
						elemCount = len(*indexAddrPtr.Referrers())
						break
					}
				}
				if elemCount == -1 {
					if debugMode {
						printDebugInfo("------Can't get elemCount of local Table")
					}
					return -1, -1
				}

				return length, elemCount
			}
		}
	}
	return -1, -1
}

func findGlobalTableLengthAndItemElemCount(globalTable *ssa.Global) (int, int) {
	initFunc := globalTable.Pkg.Members["init"].(*ssa.Function)

	var storeToGlobalTable *ssa.Store
	for _, block := range initFunc.Blocks {
		for _, inst := range block.Instrs {
			if storeInst, toStoreOk := inst.(*ssa.Store); toStoreOk {
				if globalPtr, toGlobalOk := storeInst.Addr.(*ssa.Global); toGlobalOk {
					if globalPtr == globalTable {
						storeToGlobalTable = storeInst
						break
					}
				}
			}
		}
		if storeToGlobalTable != nil {
			break
		}
	}
	if storeToGlobalTable == nil || storeToGlobalTable.Val == nil {
		return -1, -1
	}
	if slicePtr, toSliceOk := storeToGlobalTable.Val.(*ssa.Slice); toSliceOk {

		newAllocPtr := slicePtr.X.(*ssa.Alloc)

		lengthStr := newAllocPtr.Type().String()
		length, err := strconv.Atoi(lengthStr[strings.Index(lengthStr, "[")+1 : strings.Index(lengthStr, "]")])
		if err != nil {
			if debugMode {
				printDebugInfo("Can't get length of global Table")
			}
			return -1, -1
		}

		elemCount := -1
		for _, findIndexRefInst := range *newAllocPtr.Referrers() {
			if indexAddrPtr, toIndexAddrOk := findIndexRefInst.(*ssa.IndexAddr); toIndexAddrOk {
				elemCount = len(*indexAddrPtr.Referrers())
				break
			}
		}
		if elemCount == -1 {
			if debugMode {
				printDebugInfo("Can't get elemCount of global Table")
			}
			return -1, -1
		}

		return length, elemCount

	} else {
		if debugMode {
			printDebugInfo("Global Table isn't Array!")
		}
		return -1, -1
	}
}

func fromCallInstInfoToAPIInfo(callees []*CallInstInfo) []metainfo.APIInfo {
	APIs := make([]metainfo.APIInfo, 0)
	for _, callee := range callees {
		apiInfo := metainfo.APIInfo{
			APICallLine:     callee.CallInstr.Parent().Prog.Fset.Position(callee.CallInstr.Pos()).Line,
			APICallColum:    callee.CallInstr.Parent().Prog.Fset.Position(callee.CallInstr.Pos()).Column,
			APICallLocation: callee.MayAPICallInfo,
			TableInfo:       callee.MayTableDrivenInfo,
		}
		APIs = append(APIs, apiInfo)
	}
	return APIs
}

var functionInternalFuncTaintMap map[*ssa.Function][]*funcTaintInfo

func initTheInternalFuncTaintMap(testCase *ssa.Function, fn *ssa.Function, withLocationAnalysis bool) (isFileRelatedFunction bool) {
	isFileRelatedFunction = false
	if _, ok := functionInternalFuncTaintMap[fn]; ok {
		return
	} else { //进Function发现没有初始化过所有callee的taint信息
		if debugMode {
			printDebugInfo("----------Init PCG Internal call TaintMap of: " + fn.String())
		}
		if functionInternalFuncTaintMap == nil {
			functionInternalFuncTaintMap = make(map[*ssa.Function][]*funcTaintInfo)
		}
		functionInternalFuncTaintMap[fn] = []*funcTaintInfo{}
	}

	var callInstrStructs []*CallInstInfo
	for _, block := range fn.Blocks { //遍历func内部所有的call指令
		for _, instr := range block.Instrs {
			if callInstr, toCallOk := instr.(*ssa.Call); toCallOk {
				callee := callInstr.Call.StaticCallee()
				if callee != nil { //能分析function body
					calleeLoc := judgeFuncLoc(testCase, callee)
					if calleeLoc != metainfo.TestingCallee {
						if withLocationAnalysis {
							callInstrStructs = append(callInstrStructs, &CallInstInfo{CallInstr: callInstr, CalleeLocation: calleeLoc})
						} else {
							callInstrStructs = append(callInstrStructs, &CallInstInfo{CallInstr: callInstr})
						}
					}
				}
			}
		}
	}

	for _, callInstrStruct := range callInstrStructs { //计算每个call能够taint to哪些call
		if debugMode {
			printDebugInfo("-----------Look at: " + callInstrStruct.CallInstr.String())
		}
		_, isFileRelatedFunc := fileRelatedFunctionList[callInstrStruct.CallInstr.Call.StaticCallee().String()]
		_, isRegexRelatedFunc := regexRelatedFunctionList[callInstrStruct.CallInstr.Call.StaticCallee().String()]
		_, isNetRelatedFunc := netRelatedFunctionList[callInstrStruct.CallInstr.Call.StaticCallee().String()]
		retValueUsedInstrs := analyzeFunRetUse(callInstrStruct.CallInstr)

		reachReturn := false
		fixedAllTaintedNodes := make([]ssa.Node, 0)
		for _, usedInstr := range retValueUsedInstrs {
			onceTNodes, onceJudgeToRet := analyzeFuncRetTaintByUsedInstr(usedInstr)
			if _, toRetOk := usedInstr.(*ssa.Return); toRetOk {
				onceJudgeToRet = true
			}
			reachReturn = onceJudgeToRet

			fixedAllTaintedNodes = deduplicationNodeAppend(fixedAllTaintedNodes, onceTNodes)
		}

		if isFileRelatedFunc {
			if reachReturn {
				isFileRelatedFunction = true
				return
			}
			continue
		}
		if isRegexRelatedFunc { //fix
			if reachReturn {
				isFileRelatedFunction = true
				return
			}
			continue
		}
		if isNetRelatedFunc { //fix
			if reachReturn {
				isFileRelatedFunction = true
				return
			}
			continue
		}

		taintTo := make([]*CallInstInfo, 0)
		for _, tNode := range fixedAllTaintedNodes {
			if callNode, toCallOk := tNode.(*ssa.Call); toCallOk {
				callee := callNode.Call.StaticCallee()

				if callee == nil { //不能分析function body
					continue
				} else if calleeLoc := judgeFuncLoc(fn, callee); calleeLoc == metainfo.TestingCallee {
					continue
				}
				_, isFRF := fileRelatedFunctionList[callNode.Call.StaticCallee().String()] //TODO:这里可能要加文件名参数位点匹配
				if callNode.Name() == callInstrStruct.CallInstr.Name() && isFRF {
					continue
				}
				if withLocationAnalysis {
					if debugMode {
						printDebugInfo("------------Taint to: " + callNode.String())
					}
					taintTo = append(taintTo, &CallInstInfo{CallInstr: callNode, CalleeLocation: judgeFuncLoc(fn, callee)})
				} else {
					if debugMode {
						printDebugInfo("------------Taint to: " + callNode.String())
					}
					taintTo = append(taintTo, &CallInstInfo{CallInstr: callNode})
				}
			}
		}

		functionInternalFuncTaintMap[fn] = append(functionInternalFuncTaintMap[fn],
			&funcTaintInfo{
				callInstInfo:     callInstrStruct,
				taintTo:          taintTo,
				allTaintResults:  fixedAllTaintedNodes,
				canReachToReturn: reachReturn,
			},
		)
	}

	if withLocationAnalysis { //only for testCase now
		tMapList := functionInternalFuncTaintMap[fn]
		for _, fTInfo := range tMapList {
			for _, toCall := range fTInfo.taintTo {
				for i := 0; i < len(tMapList); i++ {
					if tMapList[i].callInstInfo.CallInstr.Pos() == toCall.CallInstr.Pos() {
						tMapList[i].taintFrom = append(tMapList[i].taintFrom, fTInfo.callInstInfo)
					}
				}
			}
		}
	}
	return
}

var pcgInternalFuncTaintMap map[*callgraph.Graph][]*funcTaintInfo

func getAllCallInstInFunc(testCase *ssa.Function, fn *ssa.Function, withLocationAnalysis bool, pcgParentCall ssa.Instruction) []*CallInstInfo {
	var callInstrStructs []*CallInstInfo
	for _, block := range fn.Blocks { //遍历func内部所有的call指令
		for _, instr := range block.Instrs {
			if callInstr, toCallOk := instr.(*ssa.Call); toCallOk {
				callee := callInstr.Call.StaticCallee()
				if callee != nil { //能分析function body
					calleeLoc := judgeFuncLoc(testCase, callee)
					if calleeLoc != metainfo.TestingCallee {
						if withLocationAnalysis {
							callInstrStructs = append(callInstrStructs, &CallInstInfo{CallInstr: callInstr, CalleeLocation: calleeLoc, PCGParentCall: pcgParentCall})
						} else {
							callInstrStructs = append(callInstrStructs, &CallInstInfo{CallInstr: callInstr, PCGParentCall: pcgParentCall})
						}
					}
				}
			}
		}
	}
	return callInstrStructs
}

func getAllCallInstInPCG(pcg *callgraph.Graph, withLocationAnalysis bool) []*CallInstInfo {
	res := getAllCallInstInFunc(pcg.Root.Func, pcg.Root.Func, withLocationAnalysis, nil)
	callgraph.GraphVisitEdges(pcg, func(e *callgraph.Edge) error {
		res = append(res, getAllCallInstInFunc(pcg.Root.Func, e.Callee.Func, withLocationAnalysis, e.Site)...)
		return nil
	})
	return res
}

func initTheInternalPCGTaintMap(pcg *callgraph.Graph, withLocationAnalysis bool) { //todo:调试一下这个函数
	if _, ok := pcgInternalFuncTaintMap[pcg]; ok {
		return
	} else { //进Function发现没有初始化过所有callee的taint信息
		if debugMode {
			printDebugInfo("----------Init Function Internal call TaintMap of: " + pcg.Root.Func.String())
		}
		if pcgInternalFuncTaintMap == nil {
			pcgInternalFuncTaintMap = make(map[*callgraph.Graph][]*funcTaintInfo)
		}
		pcgInternalFuncTaintMap[pcg] = []*funcTaintInfo{}
	}

	var callInstrStructs = getAllCallInstInPCG(pcg, withLocationAnalysis)

	for _, callInstrStruct := range callInstrStructs { //计算每个call能够taint to哪些call
		if debugMode {
			printDebugInfo("-----------Look at: " + callInstrStruct.CallInstr.String())
		}

		retValueUsedInstrs := analyzeFunRetUse(callInstrStruct.CallInstr)
		var callSite *ssa.Call = nil
		if _, callSiteToCallOk := callInstrStruct.PCGParentCall.(*ssa.Call); callSiteToCallOk {
			callSite = callInstrStruct.PCGParentCall.(*ssa.Call)
		}
		reachReturn := false
		fixedAllTaintedNodes := make([]ssa.Node, 0)
		for _, usedInstr := range retValueUsedInstrs {

			onceTNodes, onceJudgeToRet := analyzeFuncRetTaintByUsedInstrPCG(pcg, usedInstr, callSite)
			if _, toRetOk := usedInstr.(*ssa.Return); toRetOk {
				onceJudgeToRet = true
			}
			reachReturn = onceJudgeToRet

			fixedAllTaintedNodes = deduplicationNodeAppend(fixedAllTaintedNodes, onceTNodes)
		}

		taintTo := make([]*CallInstInfo, 0)
		for _, tNode := range fixedAllTaintedNodes {
			if callNode, toCallOk := tNode.(*ssa.Call); toCallOk {
				callee := callNode.Call.StaticCallee()

				if callee == nil { //不能分析function body
					continue
				} else if calleeLoc := judgeFuncLoc(pcg.Root.Func, callee); calleeLoc == metainfo.TestingCallee {
					continue
				} else if callNode == callSite {
					continue
				}
				_, isFRF := fileRelatedFunctionList[callNode.Call.StaticCallee().String()] //TODO:这里可能要加文件名参数位点匹配
				if callNode.Name() == callInstrStruct.CallInstr.Name() && isFRF {
					continue
				}
				if withLocationAnalysis {
					if debugMode {
						printDebugInfo("------------Taint to: " + callNode.String())
					}
					taintTo = append(taintTo, &CallInstInfo{CallInstr: callNode, CalleeLocation: judgeFuncLoc(pcg.Root.Func, callee)})
				} else {
					if debugMode {
						printDebugInfo("------------Taint to: " + callNode.String())
					}
					taintTo = append(taintTo, &CallInstInfo{CallInstr: callNode})
				}
			}
		}

		pcgInternalFuncTaintMap[pcg] = append(pcgInternalFuncTaintMap[pcg],
			&funcTaintInfo{
				callInstInfo:     callInstrStruct,
				taintTo:          taintTo,
				allTaintResults:  fixedAllTaintedNodes,
				canReachToReturn: reachReturn,
			},
		)
	}

	if withLocationAnalysis { //only for testCase now
		tMapList := pcgInternalFuncTaintMap[pcg]
		for _, fTInfo := range tMapList {
			for _, toCall := range fTInfo.taintTo {
				for i := 0; i < len(tMapList); i++ {
					if tMapList[i].callInstInfo.CallInstr.Pos() == toCall.CallInstr.Pos() {
						tMapList[i].taintFrom = append(tMapList[i].taintFrom, fTInfo.callInstInfo)
					}
				}
			}
		}
	}
	return
}
