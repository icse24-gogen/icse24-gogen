package scorer

import (
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"xyz.asd.qwe/gout-static-analysis/pkg/metainfo"
	"xyz.asd.qwe/gout-static-analysis/pkg/parameterutils"
	"strings"
)

var testcaseWithFileName = map[*ssa.Function][]string{} //TestXxx:{filePattern1,...}
var testcaseWithRegexPattern = map[*ssa.Function][]string{}
var testcaseWithIpAddress = map[*ssa.Function][]string{}

var fileRelatedFunctionList = map[string][]int{
	"os.Create": {0}, "os.Remove": {0}, "os.RemoveAll": {0}, "os.Stat": {0}, "os.Open": {0},
	"os.Chmod": {0}, "os.Chown": {0}, "os.Chtimes": {0}, "os.ReadFile": {0}, "os.MkdirAll": {0},
	"os.ReadDir": {0}, "os.Chdir": {0}, "os.CreateTemp": {-1}, "os.Link": {-1}, "os.Mkdir": {-1}, "os.OpenFile": {0},
	"os.Readlink": {0}, "os.Rename": {0}, "os.Symlink": {-1}, "os.WriteFile": {0}, "os.Truncate": {-1},

	"filepath.Join": {-1}, "filepath.Glob": {0}, "filepath.Walk": {0}, "filepath.WalkDir": {0},
	"tar.FileInfoHeader": {-1}, "zip.FileInfoHeader": {-1},
	"fs.ReadFile": {-1}, "fs.FileInfoToDirEntry": {-1}, "fs.ReadDir": {-1}, "fs.Glob": {-1}, "fs.Stat": {-1},
	"fs.Sub": {-1}, "fs.ValidPath": {-1}, "fs.WalkDir": {-1},
}

var regexRelatedFunctionList = map[string][]int{
	"regexp.Compile": {0}, "regexp.CompilePOSIX": {0}, "regexp.MustCompile": {0}, "regexp.MustCompilePOSIX": {0},
	"regexp.SubexpIndex": {0}, "regexp.MatchReader": {0}, "regexp.MatchString": {0}, "regexp.Match": {0},
}

var netRelatedFunctionList = map[string][]int{
	"net.ParseIP": {1},
}

func addFilePattern(fn *ssa.Function, fileString string) {

	var haveThisPattern = false
	for _, pattern := range testcaseWithFileName[fn] {
		if pattern == fileString {
			haveThisPattern = true
			break
		}
	}
	if !haveThisPattern {
		testcaseWithFileName[fn] =
			append(testcaseWithFileName[fn], fileString) //add
		if debugMode {
			printDebugInfo("-----[ok]Found pattern: " + fileString)
		}
	}
}

func addRegexPattern(fn *ssa.Function, regxString string) {

	var haveThisPattern = false
	for _, pattern := range testcaseWithRegexPattern[fn] {
		if pattern == regxString {
			haveThisPattern = true
			break
		}
	}
	if !haveThisPattern {
		testcaseWithRegexPattern[fn] =
			append(testcaseWithRegexPattern[fn], regxString) //add
		if debugMode {
			printDebugInfo("-----[ok]Found pattern: " + regxString)
		}
	}
}

func addIpPattern(fn *ssa.Function, ipString string) {

	var haveThisPattern = false
	for _, pattern := range testcaseWithIpAddress[fn] {
		if pattern == ipString {
			haveThisPattern = true
			break
		}
	}
	if !haveThisPattern {
		testcaseWithIpAddress[fn] =
			append(testcaseWithIpAddress[fn], ipString) //add
		if debugMode {
			printDebugInfo("-----[ok]Found pattern: " + ipString)
		}
	}
}

func constructFileNamePatternOfFunc(fn *ssa.Function) {
	if _, ok := testcaseWithFileName[fn]; ok { //have constructed
		return
	}
	if debugMode {
		fmt.Println("-Find fileName pattern...")
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if call.Call.StaticCallee() == nil {
					continue
				}
				callee := call.Call.StaticCallee()
				callString := callee.String()
				for funcName, argIdxList := range fileRelatedFunctionList {
					if funcName == callString {
						if argIdxList[0] != -1 {
							for _, argIdx := range argIdxList {
								fileString := call.Call.Args[argIdx].String() //get Arg String
								addFilePattern(fn, fileString)
							}
						} else {
							for idx, fileString := range call.Call.Args {
								if callee.Signature.Recv() != nil && idx == 0 { //skip self
									continue
								}
								addFilePattern(fn, fileString.String())
							}
						}
					}
				}
				for paraIdx, param := range callee.Params {
					if strings.Contains(strings.ToLower(param.String()), "file") ||
						strings.Contains(strings.ToLower(param.String()), "path") ||
						strings.Contains(strings.ToLower(param.String()), "dir") {
						if callee.Signature.Recv() != nil && paraIdx == 0 { //skip self
							continue
						}
						addFilePattern(fn, call.Call.Args[paraIdx].String()) //callee.Params contain "Self"
					}
				}
			}
		}
	}
}

func constructFileNamePatternOfFuncWithCG(pcg *PartialCGStruct) { //FileNamePattern包含函数签名
	fn := pcg.TestCaseCG.Root.Func
	if _, ok := testcaseWithFileName[fn]; ok { //have constructed
		return
	}
	if debugMode {
		printDebugInfo("----Find fileName pattern...")
	}
	for _, cgCallee := range pcg.CGCallees {
		if cgCallee.Callee != nil {
			callee := cgCallee.Callee
			callString := callee.String()
			for funcName, argIdxList := range fileRelatedFunctionList {
				if funcName == callString {
					if argIdxList[0] != -1 {
						for _, argIdx := range argIdxList {
							fileStringSig := cgCallee.CallInstr.Call.Args[argIdx].String() + "|" + cgCallee.CallSite.Parent().String() //get Arg String，这里要打上函数标签
							addFilePattern(fn, fileStringSig)
						}
					} else {
						for idx, fileString := range cgCallee.CallInstr.Call.Args {
							if callee.Signature.Recv() != nil && idx == 0 { //skip self
								continue
							}
							fileStringSig := fileString.String() + "|" + cgCallee.CallSite.Parent().String()
							addFilePattern(fn, fileStringSig)
						}
					}
				}
			}
			for paraIdx, param := range callee.Params {
				if strings.Contains(strings.ToLower(param.Name()), "file") ||
					strings.ToLower(param.Name()) == "path" ||
					strings.Contains(strings.ToLower(param.Name()), "dir") {
					if callee.Signature.Recv() != nil && paraIdx == 0 { //skip self
						continue
					}
					fileStringSig := cgCallee.CallInstr.Call.Args[paraIdx].String() + "|" + cgCallee.CallSite.Parent().String()
					addFilePattern(fn, fileStringSig) //callee.Params contain "Self"
				}
			}
		}
	}
}

func constructRegexPatternOfFuncWithCG(pcg *PartialCGStruct) {
	fn := pcg.TestCaseCG.Root.Func
	if _, ok := testcaseWithRegexPattern[fn]; ok { //have constructed
		return
	}
	if debugMode {
		printDebugInfo("----Find Regex pattern...")
	}
	for _, cgCallee := range pcg.CGCallees {
		if cgCallee.Callee != nil {
			callee := cgCallee.Callee
			callString := callee.String()
			for funcName, argIdxList := range regexRelatedFunctionList {
				if funcName == callString {
					if argIdxList[0] != -1 {
						for _, argIdx := range argIdxList {
							regexStringSig := cgCallee.CallInstr.Call.Args[argIdx].String() + "|" + cgCallee.CallSite.Parent().String() //get Arg String，这里要打上函数标签
							addRegexPattern(fn, regexStringSig)
						}
					} else {
						for idx, fileString := range cgCallee.CallInstr.Call.Args {
							if callee.Signature.Recv() != nil && idx == 0 { //skip self
								continue
							}
							regexStringSig := fileString.String() + "|" + cgCallee.CallSite.Parent().String()
							addRegexPattern(fn, regexStringSig)
						}
					}
				}
			}
			for paraIdx, param := range callee.Params {
				if strings.Contains(strings.ToLower(param.String()), "regex") {
					if callee.Signature.Recv() != nil && paraIdx == 0 { //skip self
						continue
					}
					regexStringSig := cgCallee.CallInstr.Call.Args[paraIdx].String() + "|" + cgCallee.CallSite.Parent().String()
					addRegexPattern(fn, regexStringSig) //callee.Params contain "Self"
				}
			}
		}
	}
}

func constructIpPatternOfFuncWithCG(pcg *PartialCGStruct) {
	fn := pcg.TestCaseCG.Root.Func
	if _, ok := testcaseWithIpAddress[fn]; ok { //have constructed
		return
	}
	if debugMode {
		printDebugInfo("----Find Ip pattern...")
	}
	for _, cgCallee := range pcg.CGCallees {
		if cgCallee.Callee != nil {
			callee := cgCallee.Callee
			callString := callee.String()
			for funcName, argIdxList := range netRelatedFunctionList {
				if funcName == callString {
					if argIdxList[0] != -1 {
						for _, argIdx := range argIdxList {
							ipStringSig := cgCallee.CallInstr.Call.Args[argIdx].String() + "|" + cgCallee.CallSite.Parent().String() //get Arg String，这里要打上函数标签
							addIpPattern(fn, ipStringSig)
						}
					} else {
						for idx, fileString := range cgCallee.CallInstr.Call.Args {
							if callee.Signature.Recv() != nil && idx == 0 { //skip self
								continue
							}
							ipStringSig := fileString.String() + "|" + cgCallee.CallSite.Parent().String()
							addIpPattern(fn, ipStringSig)
						}
					}
				}
			}
			for paraIdx, param := range callee.Params {
				if strings.ToLower(param.String()) == "ip" ||
					strings.ToLower(param.String()) == "address" {
					if callee.Signature.Recv() != nil && paraIdx == 0 { //skip self
						continue
					}
					ipStringSig := cgCallee.CallInstr.Call.Args[paraIdx].String() + "|" + cgCallee.CallSite.Parent().String()
					addIpPattern(fn, ipStringSig) //callee.Params contain "Self"
				}
			}
		}
	}
}

const (
	FileArg  = 1
	RegexArg = 2
	IpArg    = 3
)

func isSpecificTag(callInst *ssa.Call, paraIndex int, argType int) bool {
	var patternString map[*ssa.Function][]string
	switch argType {
	case FileArg:
		patternString = testcaseWithFileName
	case RegexArg:
		patternString = testcaseWithRegexPattern
	case IpArg:
		patternString = testcaseWithIpAddress
	}
	for _, pattern := range patternString[callInst.Parent()] {
		if strings.Contains(strings.ToLower(callInst.Call.Args[paraIndex].String()+"|"+callInst.Parent().String()),
			strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

type interceptArgInfo struct {
	TaintFrom         *funcTaintInfo
	InterceptArgIndex int
}

//intercept array contains this arg
func intArrayContaints(arr []interceptArgInfo, i int) bool {
	for _, elem := range arr {
		if elem.InterceptArgIndex == i {
			return true
		}
	}
	return false
}

func CollectNeedInterceptArgsOfPCG(pcg *callgraph.Graph) map[*ssa.Call][]interceptArgInfo {
	allNeedInterceptArgs := make(map[*ssa.Call][]interceptArgInfo)
	onceIntercepted := findNeedInterceptArgsFromNoneAPICalleeRes(pcg, pcg.Root.Func)
	for callInstr, arr := range onceIntercepted {
		allNeedInterceptArgs[callInstr] = arr
	}
	callgraph.GraphVisitEdges(pcg, func(e *callgraph.Edge) error {
		onceIntercepted := findNeedInterceptArgsFromNoneAPICalleeRes(pcg, e.Callee.Func)
		for callInstr, arr := range onceIntercepted {
			allNeedInterceptArgs[callInstr] = arr
		}
		return nil
	})
	return allNeedInterceptArgs
}

func findNeedInterceptArgsFromNoneAPICalleeRes(pcg *callgraph.Graph, fn *ssa.Function) map[*ssa.Call][]interceptArgInfo {
	needInterceptArgs := make(map[*ssa.Call][]interceptArgInfo)
	initTheInternalFuncTaintMap(pcg.Root.Func, fn, true)
	funcTaintInfos := functionInternalFuncTaintMap[fn]
	for _, fTFrom := range funcTaintInfos {
		if (fTFrom.callInstInfo.CalleeLocation & APIStandard) == metainfo.EmptyCalleeType { //找到那些可能的第三方函数
			if debugMode {
				printDebugInfo("-----------Look into [" + fTFrom.callInstInfo.CallInstr.String() + "]'s taint info")
			}
			for _, fTTo := range fTFrom.taintTo {
				_, isWrapperCall := pcg.Nodes[fTTo.Callee]
				if debugMode {
					printDebugInfo("------------[?]" + fTTo.CallInstr.String())
				}
				if (fTTo.CalleeLocation&APIStandard) != metainfo.EmptyCalleeType && !isWrapperCall { //返回值能taint到本包函数(API)
					//找是第几个参数
					for argIdx, arg := range fTTo.CallInstr.Call.Args {
						for _, tNode := range fTFrom.allTaintResults {
							if tNode.Pos() == arg.Pos() && tNode.String() == arg.String() &&
								!intArrayContaints(needInterceptArgs[fTTo.CallInstr], argIdx) &&
								parameterutils.SwitchType(arg.Type().String()) != metainfo.UnKnown {
								if debugMode {
									printDebugInfo("------------[ok]A Arg needs to be intercepted")
									printDebugInfo("------------In  :" + fn.String())
									printDebugInfo("------------From:" + fTFrom.callInstInfo.CallInstr.String())
									printDebugInfo("------------To  :" + fTTo.CallInstr.String())
								}
								testCaseHaveInterceptArg = true
								needInterceptArgs[fTTo.CallInstr] = append(needInterceptArgs[fTTo.CallInstr], interceptArgInfo{fTFrom, argIdx})
							}
						}
					}
				}
			}
		}
	}
	return needInterceptArgs
}

func filterArrayContaints(arr []*CallInstInfo, e *CallInstInfo) bool {
	for _, elem := range arr {
		if elem.CallInstr == e.CallInstr {
			return true
		}
	}
	return false
}

func filterCalleeInPCG(pcg *callgraph.Graph, callees []*CallInstInfo, interceptArgs map[*ssa.Call][]interceptArgInfo) (res []*CallInstInfo) {
	res = filterCalleeOfTestCase(pcg.Root.Func, pcg.Root.Func, callees, interceptArgs)
	callgraph.GraphVisitEdges(pcg, func(e *callgraph.Edge) error {
		res = filterCalleeOfTestCase(pcg.Root.Func, e.Callee.Func, res, interceptArgs)
		return nil
	})
	return res
}

func filterCalleeOfTestCase(testCase *ssa.Function, fn *ssa.Function, callees []*CallInstInfo, interceptArgs map[*ssa.Call][]interceptArgInfo) (res []*CallInstInfo) {
	res = make([]*CallInstInfo, 0)
	initTheInternalFuncTaintMap(testCase, fn, true)
	funcTaintInfos := functionInternalFuncTaintMap[fn]

	var needFilter []*CallInstInfo
	if filterAllThirdPartyCalleeByPolicy {
		for _, fTInfo := range funcTaintInfos { //过滤没有API taint到的第三方callee
			if (fTInfo.callInstInfo.CalleeLocation & APIStandard) == metainfo.EmptyCalleeType { //找到那些非API标准的函数
				haveRelatedTaintFrom := false
				haveRelatedTaintTo := false
				for _, tCall := range fTInfo.taintFrom {
					if (tCall.CalleeLocation & APIStandard) != metainfo.EmptyCalleeType {
						haveRelatedTaintFrom = true
						break
					}
				}
				for _, tCall := range fTInfo.taintTo {
					if (tCall.CalleeLocation & APIStandard) != metainfo.EmptyCalleeType {
						haveRelatedTaintTo = true

						if fTInfo.callInstInfo.CalleeLocation == metainfo.MayThirdPackageCallee ||
							fTInfo.callInstInfo.CalleeLocation == metainfo.StdCallee ||
							fTInfo.callInstInfo.CalleeLocation == metainfo.OtherPackageCallee { //otherPackage->third?
							testCaseHaveThirdPartyDependency = true
						}

						break
					}
				}
				if notAPIFuncMustHaveTaintFlowFromAPI && !haveRelatedTaintFrom { //如果taintFrom或taintTo没有API函数
					needFilter = append(needFilter, fTInfo.callInstInfo)
					continue
				} else if notAPIFuncMustHaveTaintFlowToAPI && !haveRelatedTaintTo {
					needFilter = append(needFilter, fTInfo.callInstInfo)
					continue
				}
			} else if (fTInfo.callInstInfo.CalleeLocation & APIStandard) != metainfo.EmptyCalleeType { //找到那些API标准的函数,这一步仅用于统计特征
				for _, tCall := range fTInfo.taintTo {
					if (tCall.CalleeLocation & APIStandard) != metainfo.EmptyCalleeType {
						testCaseHaveAPIDependency = true
						break
					}
				}
			}

		}
	}
	for _, INTArgsInACall := range interceptArgs { //过滤那些拦截处的第三方call来源
		for _, INTArg := range INTArgsInACall {
			if !filterArrayContaints(needFilter, INTArg.TaintFrom.callInstInfo) {
				needFilter = append(needFilter, INTArg.TaintFrom.callInstInfo)
			}
		}
	}

	for _, callee := range callees {
		needAdd := true

		for _, fCallee := range needFilter {
			if callee.CallInstr.Pos() == fCallee.CallInstr.Pos() {
				needAdd = false
				break
			}
		}

		if needAdd {
			res = append(res, callee)
		} else {
			if debugMode {
				printDebugInfo("----[OK]filter: " + callee.Callee.String())
			}
		}
	}
	return res
}
