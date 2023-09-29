package scorer

import (
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/propagation"
	"xyz.asd.qwe/gout-static-analysis/pkg/funcutils"
	"xyz.asd.qwe/gout-static-analysis/pkg/metainfo"
	"xyz.asd.qwe/gout-static-analysis/pkg/parameterutils"
	"xyz.asd.qwe/gout-static-analysis/pkg/pkgutils"
	"sigs.k8s.io/yaml"
	"sort"
	"strconv"
	"strings"
)

type statisticInfo struct {
	AllTestCaseNum             int //所有TestCase的数量
	ChangeableTestCaseNum      int //理论可转换的TestCase
	ChangeableTestCaseList     []string
	NoDependencyDriverNum      int //TestCase内没有依赖
	HaveTwoDependencyDriverNum int //既有API依赖，又有其他库API的依赖
	OtherDriverNum             int //其他类型的依赖

	AllCalleeNum               int //有意义的Callee序列(API+一些有依赖的其他库调用)
	CoveredAPINum              int //覆盖到的API数量(本包的API)
	FuzzedAPI                  int
	APIDensity                 float64                            //API密度：总API数/TestCase数
	FuzzedAPIMap               map[string]map[string]map[int]bool //APIString:[](Fuzz API的TestCase以及其中的信息)
	fuzzDifArgInDifTestCaseAPI map[string][]string

	AllArgNum   int //处理的所有参数数量
	FuzzedArgs  int
	SelfArgNum  int //其中处理的Self参数数量
	FileArgNum  int //文件名参数数量
	RegexArgNum int //Regexp参数数量
	IpArgNum    int //Ip参数数量

	WrapperNum        int //包含Wrapper的数量
	HandledWrapperNum int //能处理的Wrapper数量

	MustAliasTestCaseNum int
}

var statisticRecode = statisticInfo{
	0, 0, []string{}, 0, 0,
	0, 0, 0, 0, 0.00,
	make(map[string]map[string]map[int]bool), make(map[string][]string),
	0, 0, 0, 0, 0,
	0, 0, 0, 0,
}

func (scorer Scorer) ShowStatistics() {
	fmt.Println(
		fmt.Sprintf(
			"AllTestCaseNum:%d\n"+
				"ChangeableTestCaseNum:%d\n"+
				"NoDependencyDriverNum:%d\n"+
				"HaveTwoDependencyDriverNum:%d\n"+
				"OtherDriverNum:%d\n\n"+
				"AllCalleeNum:%d\n"+
				"CoveredAPINum:%d\n"+
				"APIDensity:%f\n\n"+
				"AllArgNum:%d\n"+
				"SelfArgNum:%d\n"+
				"FileArgNum:%d\n"+
				"RegexArgNum:%d\n"+
				"IpArgNum:%d\n\n"+
				"HandledWrapperNum:%d\n"+
				"WrapperNum:%d\n\n"+
				"MustAliasTestCaseNum:%d\n",
			statisticRecode.AllTestCaseNum,
			statisticRecode.ChangeableTestCaseNum,
			statisticRecode.NoDependencyDriverNum,
			statisticRecode.HaveTwoDependencyDriverNum,
			statisticRecode.OtherDriverNum,

			statisticRecode.AllCalleeNum,
			statisticRecode.CoveredAPINum,
			statisticRecode.APIDensity,

			statisticRecode.AllArgNum,
			statisticRecode.SelfArgNum,
			statisticRecode.FileArgNum,
			statisticRecode.RegexArgNum,
			statisticRecode.IpArgNum,

			statisticRecode.HandledWrapperNum,
			statisticRecode.WrapperNum,
			statisticRecode.MustAliasTestCaseNum,
		),
	)
	fmt.Println("----------------All Changeable TestCase----------------")
	for _, tc := range statisticRecode.ChangeableTestCaseList {
		fmt.Println(tc)
	}
	fmt.Print("----------------Dependency Info----------------\nnoDependency")
	for _, testCaseStr := range threeTypeTestCase[noDependency] {
		fmt.Print("," + testCaseStr)
	}
	fmt.Print("\nhaveTwoDependency")
	for _, testCaseStr := range threeTypeTestCase[haveAPIDependency|haveThirdPartyDependency] {
		fmt.Print("," + testCaseStr)
	}
	fmt.Print("\notherDependency")
	for _, testCaseStr := range threeTypeTestCase[otherDependency] {
		fmt.Print("," + testCaseStr)
	}
	fmt.Println()
	fmt.Println("-------API fuzzed info-------")
	for api, fuzzedTestCase := range statisticRecode.FuzzedAPIMap {
		fmt.Println(api, "--Fuzzed in :")
		tmpRecordMap := make(map[int]bool)
		once := true
		onceTestCase := ""
		for testCase, fuzzedArgs := range fuzzedTestCase {
			if once { //第一次记录Fuzz的Arg
				onceTestCase = testCase
				fmt.Print("--", testCase+"[")
				for argIdx := range fuzzedArgs {
					fmt.Print(argIdx, ",")
					tmpRecordMap[argIdx] = true
				}
				fmt.Println("]")
				once = false
			} else { //之后看有没有Fuzz不一样的
				fmt.Print("--", testCase+"[")
				for argIdx := range fuzzedArgs {
					if _, ok := tmpRecordMap[argIdx]; !ok { //如果有不一样的
						fmt.Print("(!", argIdx, "),")
						statisticRecode.fuzzDifArgInDifTestCaseAPI[api] =
							append(statisticRecode.fuzzDifArgInDifTestCaseAPI[api], testCase)
						continue
					}
					fmt.Print(argIdx, ",")
				}
				fmt.Println("]")
			}
		}
		if _, ok := statisticRecode.fuzzDifArgInDifTestCaseAPI[api]; ok {
			statisticRecode.fuzzDifArgInDifTestCaseAPI[api] =
				append(statisticRecode.fuzzDifArgInDifTestCaseAPI[api], onceTestCase)
		}
		fmt.Println()
	}
	fmt.Println("Fuzz different argument of API in different fuzz driver:")
	for api, testCases := range statisticRecode.fuzzDifArgInDifTestCaseAPI {
		fmt.Println(api, testCases)
	}
}

type CallInstInfo struct {
	IsMethod           bool
	Callee             *ssa.Function
	CalleeLocation     metainfo.CalleeType
	MayAPICallInfo     metainfo.APICallType
	MayTableDrivenInfo metainfo.TableDrivenInfo
	CallInstr          *ssa.Call
	CallSite           *ssa.BasicBlock
	CallInstrIndex     int

	PCGParentCall ssa.Instruction
}

type DirectCalleeInfo struct {
	calleeSelf              *ssa.Function
	calleeLocation          metainfo.CalleeType
	InfoOfParameters        []*parameterutils.ParamInfo
	ParamNumWithSelf        int
	CalleeArgFuzzable       bool
	ReturnValueFlowToOracle bool
}

type PartialCGStruct struct {
	TestCaseCG *callgraph.Graph
	CGCallees  []*CallInstInfo
}

type TestCaseInfo struct {
	TestCaseSelf  *ssa.Function
	TestCaseCGS   *PartialCGStruct
	DirectCallees []*DirectCalleeInfo
}

type PackageInfo struct {
	TestCases []*TestCaseInfo
	Path      string
}

type Scorer struct {
	PackageInfos []*PackageInfo
}

func deduplicationRecordInterceptArgInfo(callPtr *ssa.Call, info interceptArgInfo) {
	if _, ok := recordedNeedInterceptArgs[callPtr]; !ok {
		recordedNeedInterceptArgs[callPtr] = make([]interceptArgInfo, 0)
	}
	for _, iInfo := range recordedNeedInterceptArgs[callPtr] {
		if iInfo.InterceptArgIndex == info.InterceptArgIndex {
			return
		}
	}
	recordedNeedInterceptArgs[callPtr] = append(recordedNeedInterceptArgs[callPtr], info)
}

//argIndex may start from "self"
var tableRecorded ssa.Node

func recordTableTaintedArgs(unOpPtr ssa.Node, callPtr *ssa.Call) {
	tNodes := propagation.TaintWithoutCallRes(unOpPtr).GetTaintedNodes()
	//collect args
	args := make([]ssa.Value, 0)
	for _, tmpNode := range callPtr.Call.Args {
		args = append(args, tmpNode)
	}
	for _, tmpNode := range tNodes {
		for argIdx, arg := range args {
			if reflect.TypeOf(tmpNode) == reflect.TypeOf(arg) &&
				tmpNode.Pos() == arg.Pos() {
				if tableRecorded == unOpPtr { //don't taint a table twice
					return
				} else {
					tableRecorded = unOpPtr //todo: table used multiple times?
				}
				deduplicationRecordInterceptArgInfo(callPtr, interceptArgInfo{InterceptArgIndex: argIdx})
			}
		}
	}
}

func judgeLoopBlockIsTableDriven(blockLH *ssa.BasicBlock, blockBody *ssa.BasicBlock) (*metainfo.TableDrivenInfo, bool) {
	if len(blockLH.Instrs) < 2 {
		return nil, false
	}
	if compareInstr, toCmpOk := blockLH.Instrs[len(blockLH.Instrs)-2].(*ssa.BinOp); toCmpOk {
		callLenInstr, toCallOk := compareInstr.Y.(*ssa.Call)
		if !toCallOk {
			if debugMode {
				printDebugInfo("------[?]Loop isn't control by len()")
			}
			return nil, false
		}
		lenPtr, toBuiltInOk := callLenInstr.Call.Value.(*ssa.Builtin)
		if toBuiltInOk && lenPtr.String() == "builtin len" {
			unOpPtr, toUnOpOk := callLenInstr.Call.Args[0].(*ssa.UnOp)
			if !toUnOpOk || unOpPtr.X == nil {
				if debugMode {
					printDebugInfo("------[?]Unknown Loop ctrl: not \"x<y\" type")
				}
				return nil, false
			}

			tableInfo := &metainfo.TableDrivenInfo{}
			switch unOpPtr.X.(type) { //是局部变量而且能taint到基本块内的call
			case *ssa.Alloc:
				allocPtr := unOpPtr.X.(*ssa.Alloc)
				prog := propagation.Taint(unOpPtr)
				tNodes := prog.GetTaintedNodes()
				for _, tNode := range tNodes {
					if callPtr, toCallOk := tNode.(*ssa.Call); toCallOk {
						if callPtr.Block() == blockBody {
							tableLength, elemCount := findLocalTableLengthAndItemElemCount(allocPtr)
							if tableLength != -1 && elemCount != -1 {
								//record table tainted arg
								recordTableTaintedArgs(unOpPtr, callPtr)
								tableInfo.IsFromGlobalVarTable = false
								tableInfo.TableVarName = allocPtr.Comment
								tableInfo.TableLength = tableLength
								tableInfo.TableItemElemCount = elemCount
								tableInfo.LocalTableLine = blockLH.Parent().Prog.Fset.Position(allocPtr.Pos()).Line
								tableInfo.LocalTableColumn = blockLH.Parent().Prog.Fset.Position(allocPtr.Pos()).Column
								return tableInfo, true
							} else {
								return nil, false
							}
						}
					}
				}
			case *ssa.Global:
				globalPtr := unOpPtr.X.(*ssa.Global)
				prog := propagation.Taint(unOpPtr)
				tNodes := prog.GetTaintedNodes()
				for _, tNode := range tNodes {
					if callPtr, toCallOk := tNode.(*ssa.Call); toCallOk {
						if callPtr.Block() == blockBody {
							tableLength, elemCount := findGlobalTableLengthAndItemElemCount(globalPtr)
							if tableLength != -1 && elemCount != -1 {
								tableInfo.IsFromGlobalVarTable = true
								tableInfo.TableVarName = globalPtr.String()
								tableInfo.GlobalTable = metainfo.VariableGlobalSourceInfo{
									GlobalName:    globalPtr.String(),
									GlobalSrcPath: trimFilePathPrefix(blockLH.Parent().Prog.Fset.File(globalPtr.Pos()).Name()),
									SourceLine:    blockLH.Parent().Prog.Fset.Position(globalPtr.Pos()).Line,
									SourceColumn:  blockLH.Parent().Prog.Fset.Position(globalPtr.Pos()).Column,
									GlobalType:    globalPtr.Type().String(),
								}
								tableInfo.TableLength = tableLength
								tableInfo.TableItemElemCount = elemCount
								return tableInfo, true
							} else {
								return nil, false
							}
						}
					}
				}
			}
			if debugMode {
				printDebugInfo("------[-]No Call in loop block")
			}
		} else {
			if debugMode {
				printDebugInfo("------[?]Loop isn't control by len()")
			}
		}
	} else {
		if debugMode {
			printDebugInfo("------[?]loop block dont have cmp?")
		}
	}

	return nil, false
}

func CollectCalleeOfFunction(testCase *ssa.Function, fn *ssa.Function, APICallType metainfo.APICallType, infoIfFromTableDrivenTRun *metainfo.TableDrivenInfo) []*CallInstInfo {
	var res []*CallInstInfo

	for _, block := range fn.Blocks {
		additionalType := metainfo.DefaultAPICallType
		var tableDrivenInfo metainfo.TableDrivenInfo
		if strings.Contains(block.Comment, "rangeindex.body") || //先判断是不是table driver的block
			strings.Contains(block.Comment, "for.body") {
			if debugMode {
				printDebugInfo("-----[?]Found a loop block. Table-Driven block?")
			}
			for _, preB := range block.Preds {
				if strings.Contains(preB.Comment, "loop") {
					if tDInfo, isTableDriven := judgeLoopBlockIsTableDriven(preB, block); isTableDriven && tDInfo != nil {
						if debugMode {
							printDebugInfo("-----[ok]A Table-Driven block")
						}
						haveTableDriven = true
						testCaseHaveTableDriven = true
						tableDrivenInfo = *tDInfo
						additionalType |= metainfo.InTableDriven
					}
				}
			}
		}
		if infoIfFromTableDrivenTRun != nil { //example:t.Run in table-Driven
			tableDrivenInfo = *infoIfFromTableDrivenTRun
			additionalType |= metainfo.InTableDriven
		}

		for instrIdx, instr := range block.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if function := call.Call.Method; function == nil {
					if callee, ok := call.Call.Value.(*ssa.MakeClosure); ok {
						loc := judgeFuncLoc(testCase, callee.Fn.(*ssa.Function))
						if loc == metainfo.TestingCallee {
							continue
						}
						if debugMode {
							printDebugInfo("-----[ok]Collected Callee: " + callee.Fn.(*ssa.Function).String() + "[" + strconv.Itoa(int(loc)) + "]")
						}
						res = append(res,
							&CallInstInfo{
								IsMethod:           false,
								Callee:             callee.Fn.(*ssa.Function),
								CalleeLocation:     loc,
								MayAPICallInfo:     APICallType | additionalType,
								MayTableDrivenInfo: tableDrivenInfo,
								CallInstr:          call,
								CallSite:           block,
								CallInstrIndex:     instrIdx,
							})
					} else if callee, ok := call.Call.Value.(*ssa.Function); ok {
						loc := judgeFuncLoc(testCase, callee)
						if loc == metainfo.TestingCallee {
							continue
						}
						if debugMode {
							printDebugInfo("-----[ok]Collected Callee: " + callee.String() + "[" + strconv.Itoa(int(loc)) + "]")
						}
						if callee.Signature.Recv() != nil { //a Method
							res = append(res,
								&CallInstInfo{
									IsMethod:           true,
									Callee:             callee,
									CalleeLocation:     loc,
									MayAPICallInfo:     APICallType | additionalType,
									MayTableDrivenInfo: tableDrivenInfo,
									CallInstr:          call,
									CallSite:           block,
									CallInstrIndex:     instrIdx,
								})
						} else {
							res = append(res,
								&CallInstInfo{
									IsMethod:           false,
									Callee:             callee,
									CalleeLocation:     loc,
									MayAPICallInfo:     APICallType | additionalType,
									MayTableDrivenInfo: tableDrivenInfo,
									CallInstr:          call,
									CallSite:           block,
									CallInstrIndex:     instrIdx,
								})
						}
					}
				} else {
					if debugMode {
						printDebugInfo("-----[!]Cannot handle interface Callee: " + function.String())
					}
					//TODO:abstract function don't have IR
				}

			}
		}
	}
	return res
}

func getArgTag(fn *ssa.Function, callInst *ssa.Call, isMethod bool, paraIndex int) *parameterutils.ParamTag {
	PTag := &parameterutils.ParamTag{ArgIndex: -1,
		VariableTag: parameterutils.VariableTag{VarLine: -1, VarName: "", VarColumn: -1}}
	args := callInst.Call.Args
	params := fn.Params

	if callInst.Pos().IsValid() {
		PTag.CallLine = fn.Prog.Fset.Position(callInst.Pos()).Line
		PTag.CallColumn = fn.Prog.Fset.Position(callInst.Pos()).Column
		PTag.CallPos = int(callInst.Pos())
	}

	if isMethod && paraIndex == 0 { //<self> Arg
		PTag.IsSelf = true
		PTag.VType = args[0].Type().String()
		return PTag
	}
	//TODO:Add some other tags*
	if strings.Contains(params[paraIndex].Type().String(), "*") { //<ptr> related Arg
		PTag.VType = args[paraIndex].Type().String()
		PTag.IsPtr = true
	} else {
		if args[paraIndex].Type().String() == "string" { // check if it's filename or path
			var isFileName = isSpecificTag(callInst, paraIndex, FileArg)
			var isRegex = isSpecificTag(callInst, paraIndex, RegexArg)
			var isIpAddress = isSpecificTag(callInst, paraIndex, IpArg)

			if isFileName {
				PTag.MaybeFilenameOrPath = true
			}
			if isRegex {
				PTag.MaybeRegex = true
			}
			if isIpAddress {
				PTag.MaybeIpAddress = true
			}
		}

		PTag.VType = args[paraIndex].Type().String()
	}

	if args[paraIndex].Pos().IsValid() {
		varName := strings.Split(args[paraIndex].String(), ":")[0]
		PTag.VarName = varName
		PTag.VarLine = fn.Prog.Fset.Position(args[paraIndex].Pos()).Line
		PTag.VarColumn = fn.Prog.Fset.Position(args[paraIndex].Pos()).Column
	} else if MIPtr, ok := args[paraIndex].(*ssa.MakeInterface); ok { //make interface don't have pos
		varName := strings.Split(MIPtr.String(), ":")[0]
		PTag.VarName = varName
		PTag.VarLine = fn.Prog.Fset.Position(MIPtr.X.Pos()).Line
		PTag.VarColumn = fn.Prog.Fset.Position(MIPtr.X.Pos()).Column
	} else if !args[paraIndex].Pos().IsValid() { // default:invalid pos--immediate
		PTag.IsImmediate = true
	}

	if isMethod {
		PTag.ArgIndex = paraIndex - 1
	} else {
		PTag.ArgIndex = paraIndex
	}

	PTag.VarPos = int(args[paraIndex].Pos())
	return PTag
}

func generateDirectCalleeInfo(curTestCaseInfo *TestCaseInfo, res *DirectCalleeInfo, t *CallInstInfo,
	needInterceptArgs []interceptArgInfo) {
	res.calleeSelf = t.Callee
	for i, param := range t.Callee.Params {

		if debugMode {
			printDebugInfo(fmt.Sprintf("--------[arg%d]", i))
		}

		score := doScoreParam(t.Callee, param)
		tagStruct := getArgTag(t.Callee, t.CallInstr, t.IsMethod, i)

		if intArrayContaints(needInterceptArgs, i) { //if this arg needs to be intercept
			if debugMode {
				printDebugInfo(fmt.Sprintf("--------[arg%d]Needs to be intercepted", i))
			}
			tagStruct.NeedsIntercepted = true //dont need analyze
			res.ParamNumWithSelf++
			res.InfoOfParameters = append(res.InfoOfParameters, &parameterutils.ParamInfo{
				Score:          score,
				IfFlowToOracle: false,
				Name:           param.Name(),
				Tag:            tagStruct,
			})
			continue
		}

		if debugMode {
			if tagStruct.MaybeFilenameOrPath {
				printDebugInfo(fmt.Sprintf("---------[arg%d]MaybeFilenameOrPath", i))
			}
			if tagStruct.MaybeRegex {
				printDebugInfo(fmt.Sprintf("---------[arg%d]MaybeRegex", i))
			}
			if tagStruct.MaybeIpAddress {
				printDebugInfo(fmt.Sprintf("---------[arg%d]MaybeIpAddress", i))
			}
		}
		var constSourceInfos []metainfo.VariableConstSourceInfo
		var globalSourceInfos []metainfo.VariableGlobalSourceInfo

		if t.IsMethod && i == 0 { //"self" Arg analysis
			if doStatistics {
				statisticRecode.SelfArgNum++
			}
			if debugMode {
				printDebugInfo(fmt.Sprintf("--------[arg%d]Self. Analyzing ConstSourceInfo..", i))
			}
			var relatedToFile, relatedToRegex, relatedToIPAddress bool
			constSourceInfos, relatedToFile, relatedToRegex, relatedToIPAddress = analyzeArgSourceInPCG(curTestCaseInfo.TestCaseCGS, t, i) //需要返回一个source information的数组
			if len(constSourceInfos) == 0 && !relatedToFile && !relatedToRegex && !relatedToIPAddress {                                    //分析函数体对self的赋值
				if debugMode {
					printDebugInfo(fmt.Sprintf("--------[arg%d]Self. ConstSourceInfo fail!", i))
					//printDebugInfo(fmt.Sprintf("--------[arg%d]Self. Try to analyze \"initFunc\"", i))
				}
				/*
				   constSourceInfos = analyzeFuncInternalSourceForStruct(curTestCaseInfo.TestCaseCGS, t, i)
				   if len(constSourceInfos) == 0 && debugMode {
				       printDebugInfo(fmt.Sprintf("--------[arg%d]Self. \"initFunc\" fail!", i))
				   }
				*/
			} else if debugMode {
				printDebugInfo(fmt.Sprintf("--------[arg%d]Self. ConstSourceInfo ok!", i))
			}
		}

		if !(t.IsMethod && i == 0) && !tagStruct.MaybeFilenameOrPath &&
			!tagStruct.MaybeRegex && !tagStruct.MaybeIpAddress { //normal Arg analysis
			if debugMode {
				printDebugInfo(fmt.Sprintf("--------[arg%d]Analyzing ConstSourceInfo..", i))
			}
			var relatedToFile, relatedToRegex, relatedToIPAddress bool
			constSourceInfos, relatedToFile, relatedToRegex, relatedToIPAddress = analyzeArgSourceInPCG(curTestCaseInfo.TestCaseCGS, t, i) //需要返回一个source information的数组

			if len(constSourceInfos) == 0 && !relatedToFile && !relatedToRegex && !relatedToIPAddress { //分析new函数
				if debugMode {
					printDebugInfo(fmt.Sprintf("--------[arg%d]ConstSourceInfo fail!", i))
					//printDebugInfo(fmt.Sprintf("--------[arg%d]Try to analyze \"newFunc\"", i))
				}
				/*
				   constSourceInfos = analyzeArgFuncSource(curTestCaseInfo.TestCaseCGS.TestCaseCGS.Root.Func, t, i)
				   if len(constSourceInfos) == 0 && debugMode {
				       printDebugInfo(fmt.Sprintf("--------[arg%d]\"newFunc\" fail!", i))
				   }

				*/
			} else if debugMode {
				printDebugInfo(fmt.Sprintf("--------[arg%d]ConstSourceInfo ok!", i))
			}

			if debugMode {
				printDebugInfo(fmt.Sprintf("--------[arg%d]Analyzing GlobalSourceInfo..", i))
			}
			globalSourceInfos = analyzeArgGlobalSource(curTestCaseInfo.TestCaseCGS, t, i)
			if len(globalSourceInfos) == 0 {
				if debugMode {
					printDebugInfo(fmt.Sprintf("--------[arg%d]GlobalSourceInfo fail!", i))
				}
			} else if debugMode {
				printDebugInfo(fmt.Sprintf("--------[arg%d]GlobalSourceInfo ok!", i))
			}
		}

		res.ParamNumWithSelf++
		res.InfoOfParameters = append(res.InfoOfParameters, &parameterutils.ParamInfo{
			Score:            score,
			IfFlowToOracle:   false,
			Name:             param.Name(),
			Tag:              tagStruct,
			ConstSourceInfo:  constSourceInfos,
			GlobalSourceInfo: globalSourceInfos,
		})
	}
	res.ReturnValueFlowToOracle = false
}

var haveTableDriven = false

func CollectCalleesOfPCG(pcg *callgraph.Graph) []*CallInstInfo {
	allCallees := make([]*CallInstInfo, 0)
	haveTableDriven = false
	if debugMode {
		printDebugInfo("----[-]Collect callees of: " + pcg.Root.Func.String())
	}
	testCaseCallees := CollectCalleeOfFunction(pcg.Root.Func, pcg.Root.Func, metainfo.InOriginalTestCase, nil)
	allCallees = append(allCallees, testCaseCallees...)
	callgraph.GraphVisitEdges(pcg, func(e *callgraph.Edge) error {
		var oneFuncCallees []*CallInstInfo
		if callee := e.Site.Common().StaticCallee(); callee.String() == "(*testing.T).Run" ||
			callee.String() == "testing.AllocsPerRun" {

			block := e.Site.Block()
			var tableDrivenInfo *metainfo.TableDrivenInfo
			if strings.Contains(block.Comment, "rangeindex.body") ||
				strings.Contains(block.Comment, "for.body") {
				if debugMode {
					printDebugInfo("-----[?]Found a loop block. Table-Driven block?")
				}
				for _, preB := range block.Preds {
					if strings.Contains(preB.Comment, "loop") {
						if tDInfo, isTableDriven := judgeLoopBlockIsTableDriven(preB, block); isTableDriven && tDInfo != nil {
							if debugMode {
								printDebugInfo("-----[ok]A Table-Driven block")
							}
							haveTableDriven = true
							testCaseHaveTableDriven = true
							tableDrivenInfo = tDInfo
						}
					}
				}
			}

			oneFuncCallees = CollectCalleeOfFunction(pcg.Root.Func, e.Callee.Func, metainfo.InTestingAPIArg, tableDrivenInfo)
			allCallees = append(allCallees, oneFuncCallees...)
			return nil
		}
		oneFuncCallees = CollectCalleeOfFunction(pcg.Root.Func, e.Callee.Func, metainfo.InTestWrapper, nil)
		allCallees = append(allCallees, oneFuncCallees...)
		return nil
	})

	var res = make([]*CallInstInfo, 0)
	for _, callee := range allCallees { //除去了所有PCG中的Call
		appendBool := true
		for _, funcCode := range pcg.Nodes {
			if callee.Callee.String() == funcCode.Func.String() {
				if debugMode {
					printDebugInfo("----[!]Exclude PCG Callee: " + callee.Callee.String())
				}
				appendBool = false
				break
			}
		}
		if appendBool {
			res = append(res, callee)
		}
	}

	return res
}

type selectType int

var (
	otherDependency          selectType = 0
	noDependency             selectType = 1
	haveAPIDependency        selectType = 1 << 1
	haveThirdPartyDependency selectType = 1 << 2
)

// Develop control
var (
	/*Runtime control*/
	generateYaml = true
	doStatistics = true
	debugMode    = false

	/*Standard control*/
	APIStandard                        = metainfo.ThisPackageCallee | metainfo.OtherPackageCallee //| metainfo.StdCallee
	filterAllThirdPartyCalleeByPolicy  = true
	notAPIFuncMustHaveTaintFlowFromAPI = false
	notAPIFuncMustHaveTaintFlowToAPI   = true

	/*Collect TestCase control*/
	discardTestSuffix = false
	specifyFunction   = true
	functionName      = "html/template.TestAddrOfIndex"
	//functionName = "command-line-arguments.TestAddrOfIndex"

	/*select TestCase control*/
	selectStandard    = haveAPIDependency | haveThirdPartyDependency
	setCountThreshold = false
	APICountThreshold = 18

	filePrefix = "/Users/liujingcheng/Downloads/"
)

func collectTestCasesFunctionFromPackage(pkg *ssa.Package) []*ssa.Function {
	res := make([]*ssa.Function, 0)
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if funcutils.IsFuncUseless(fn) {
				continue // inline, init, or func added by compiler
			}
			if discardTestSuffix || funcutils.IsFuncTest(fn) {
				if specifyFunction {
					if fn.String() != functionName {
						continue
					}
				}
				if debugMode {
					printProjDebugInfo("[ok]Collected TestCase: " + fn.String())
				}
				//constructFileNamePatternOfFunc(fn) // FileNamePattern of this function
				res = append(res, fn)
			} else { //go-fuzz-corpus have no TestXxx Function
				if debugMode {
					//printDebugInfo("[!]Not TestCase form: " + fn.String())
				}
			}
		}
	}
	return res
}

func needIntercept(needInterceptArgs map[*ssa.Call][]interceptArgInfo, callInstr *CallInstInfo) bool {
	for call, _ := range needInterceptArgs {
		if call == callInstr.CallInstr {
			return true
		}
	}
	return false
}

var testCaseMetaInfo = &metainfo.TestCaseMetaInfo{}

func HandleCallees(curTestCaseInfo *TestCaseInfo, tCMetaInfo *metainfo.TestCaseMetaInfo,
	callees []*CallInstInfo, needInterceptArgs map[*ssa.Call][]interceptArgInfo) (changeable bool) {

	for APIInfoID, instToCallee := range callees {
		if funcutils.IsCalleeUseless(instToCallee.Callee) { //testing function?
			continue
		}
		if debugMode {
			printDebugInfo("------[-]Handle Callee: " + instToCallee.Callee.String())
			printDebugInfo("------[-]Generating DirectCalleeInfo(About Args)")
		}

		dci := &DirectCalleeInfo{CalleeArgFuzzable: false, ParamNumWithSelf: 0,
			calleeLocation: instToCallee.CalleeLocation}

		intArgInfos := make([]interceptArgInfo, 0)
		need := needIntercept(needInterceptArgs, instToCallee)
		if need {
			intArgInfos = needInterceptArgs[instToCallee.CallInstr]
		}

		generateDirectCalleeInfo(curTestCaseInfo, dci, instToCallee, intArgInfos)
		if debugMode {
			printDebugInfo("------[ok]Generating DirectCalleeInfo(About Args) ok")
		}
		if len(dci.InfoOfParameters) != 0 { //no function body like: os.xxx (if load with ssautil.Packages())

			fuzzedArgsIndex := make([]int, 0)
			for argIndex, variable := range dci.InfoOfParameters {
				VMInfo := parameterutils.ParseTagToVariableMetaInfo(variable)
				if VMInfo != nil { //每个参数能转换成相关信息
					VMInfo.Callee = dci.calleeSelf.String()
					VMInfo.CalleeLoc = instToCallee.CalleeLocation
					VMInfo.VarRelatedConstSources = variable.ConstSourceInfo
					VMInfo.VarRelatedGlobalSources = variable.GlobalSourceInfo
					VMInfo.APIInfoIDOfCallee = APIInfoID
					if VMInfo.IsImmediateVariable && VMInfo.VarType != metainfo.UnKnown {
						dci.CalleeArgFuzzable = true
						fuzzedArgsIndex = append(fuzzedArgsIndex, argIndex)
					} else if len(VMInfo.VarRelatedGlobalSources) != 0 || len(VMInfo.VarRelatedConstSources) != 0 {
						dci.CalleeArgFuzzable = true
						fuzzedArgsIndex = append(fuzzedArgsIndex, argIndex)
					}

					if generateYaml {
						tCMetaInfo.VariableList = append(tCMetaInfo.VariableList, *VMInfo)
					}
				}
			}

			if doStatistics {
				if dci.CalleeArgFuzzable && dci.calleeLocation&APIStandard != metainfo.EmptyCalleeType {
					changeable = true
					for _, argIndex := range fuzzedArgsIndex {
						if statisticRecode.FuzzedAPIMap[instToCallee.Callee.String()] == nil {
							statisticRecode.FuzzedAPIMap[instToCallee.Callee.String()] = make(map[string]map[int]bool)
						}
						if statisticRecode.FuzzedAPIMap[instToCallee.Callee.String()][curTestCaseInfo.TestCaseSelf.String()] == nil {
							statisticRecode.FuzzedAPIMap[instToCallee.Callee.String()][curTestCaseInfo.TestCaseSelf.String()] = make(map[int]bool)
						}
						statisticRecode.
							FuzzedAPIMap[instToCallee.Callee.String()][curTestCaseInfo.TestCaseSelf.String()][argIndex] = true
					}
				}
				statisticRecode.AllArgNum += dci.ParamNumWithSelf
			}

			curTestCaseInfo.DirectCallees = append(curTestCaseInfo.DirectCallees, dci)
		}
	}

	return changeable
}

var AllConstsOfTestCase []*constLocation

func getAllConstLocationToMetaInfo() []metainfo.VariableConstSourceInfo {
	metaArray := make([]metainfo.VariableConstSourceInfo, 0)
	for _, relatedC := range AllConstsOfTestCase {
		var metaI metainfo.VariableConstSourceInfo
		if relatedC.constPos == 0 {
			metaI = metainfo.VariableConstSourceInfo{
				VariableSrcPath:     relatedC.constFile,
				SourceLine:          0,
				SourceColumn:        0,
				FuncInternalOffset:  0,
				ConstValue:          relatedC.constValue,
				ConstType:           parameterutils.SwitchType(relatedC.constType),
				ConstUseType:        relatedC.constUseType,
				InWhichFunc:         relatedC.inWhichFunction.String(),
				IsImmediateVariable: true,
				ArgIndex:            relatedC.argIndex,
				CallLine:            relatedC.inWhichFunction.Prog.Fset.Position(relatedC.callInstrPos).Line,
				CallColum:           relatedC.inWhichFunction.Prog.Fset.Position(relatedC.callInstrPos).Column,
				CallPos:             int(relatedC.callInstrPos),
				MayAlias:            relatedC.mayAlias,
				MustAlias:           relatedC.mustAlias,
				IDOfAllConst:        relatedC.IDOfAllConst,
			}
		} else {
			functionInterOffset := relatedC.constPos - relatedC.inWhichFunction.Pos()
			metaI = metainfo.VariableConstSourceInfo{
				VariableSrcPath:    relatedC.constFile,
				SourceLine:         relatedC.inWhichFunction.Prog.Fset.Position(relatedC.constPos).Line,
				SourceColumn:       relatedC.inWhichFunction.Prog.Fset.Position(relatedC.constPos).Column,
				ConstValue:         relatedC.constValue,
				ConstType:          parameterutils.SwitchType(relatedC.constType),
				ConstUseType:       relatedC.constUseType,
				InWhichFunc:        relatedC.inWhichFunction.String(),
				FuncInternalOffset: int(functionInterOffset),
				MayAlias:           relatedC.mayAlias,
				MustAlias:          relatedC.mustAlias,
				IDOfAllConst:       relatedC.IDOfAllConst,
			}
		}
		metaArray = append(metaArray, metaI)
	}
	return metaArray
}

var testCaseIsWrapper bool
var testCaseHaveMustAlias bool
var testCaseHaveTestingAPI bool
var testCaseHaveTableDriven bool
var testCaseHaveInterceptArg bool
var testCaseHaveAPIDependency bool
var testCaseHaveThirdPartyDependency bool

func resetTestCaseStatus() {
	testCaseIsWrapper = false
	testCaseHaveMustAlias = false
	testCaseHaveTestingAPI = false
	testCaseHaveTableDriven = false
	testCaseHaveInterceptArg = false
	testCaseHaveAPIDependency = false
	testCaseHaveThirdPartyDependency = false
}

var APIMap = make(map[string]bool)
var TestCaseAPINumMap = make(map[int][]string)
var threeTypeTestCase = make(map[selectType][]string)
var recordedNeedInterceptArgs = make(map[*ssa.Call][]interceptArgInfo) //CollectNeedInterceptArgsOfPCG(pcgOfTestCase)

func HandleTestCases(curPackageInfo *PackageInfo, testCases []*ssa.Function) {
	for _, testCase := range testCases { //handle these TestCase
		if specifyFunction {
			testCase.WriteTo(os.Stdout)
		}
		resetTestCaseStatus()
		if debugMode {
			setTCName(testCase.String())
		}
		//start := time.Now()
		AllConstsOfTestCase = nil
		if doStatistics {
			if debugMode {
				printDebugInfo("---[*]Star Wrapper judge")
			}
			isWrapper := judgeWrapper(testCase, testCase)
			if isWrapper {
				if debugMode {
					printDebugInfo("---[*]A Wrapper Case")
				}
				statisticRecode.WrapperNum++
			} else {
				printDebugInfo("---[*]Not A Wrapper Case")
			}
		}

		if debugMode {
			printDebugInfo("---[Test Start]Handle TestCase: " + testCase.String())
			printDebugInfo("---[-]Construct CG")
		}

		pcgOfTestCase := callgraph.New(testCase)
		constructPCGOfTestCase(pcgOfTestCase, pcgOfTestCase.Root) //如果有wrapper，构建CG
		if debugMode {
			printDebugInfo("---[ok]PCG Construct Ok")
			printDebugInfo("---[-]Collect callees of PCG")
		}

		callees := CollectCalleesOfPCG(pcgOfTestCase) //Get all Callees of CG. Could be used for exclude a function. Record table tainted arg

		if debugMode {
			printDebugInfo("---[ok]CalleeNum:" + strconv.Itoa(len(callees)))
			printDebugInfo("---[ok]Collect callees of PCG ok")
			printDebugInfo("---[-]Find Args need to be intercepted")
		}

		if debugMode {
			printDebugInfo("---[ok]Find Args need to be intercepted ok")
			printDebugInfo("---[-]Filter Callee In PCG")
		}
		fakeInterceptArgs := make(map[*ssa.Call][]interceptArgInfo) //don't intercept args from other function now
		callees = filterCalleeInPCG(pcgOfTestCase, callees, fakeInterceptArgs)
		if setCountThreshold {
			if len(callees) > APICountThreshold {
				continue
			}
		}
		if debugMode {
			printDebugInfo("---[ok]Filter Callee In PCG ok, CalleeNum:" + strconv.Itoa(len(callees)))
			for _, callee := range callees {
				printDebugInfo("-------Callee:" + callee.Callee.String())
			}
		}

		if doStatistics {
			if testCaseHaveTableDriven {

				/*statisticRecode.OtherDriverNum++
				  threeTypeTestCase[otherDependency] =
				      append(threeTypeTestCase[otherDependency], testCase.String())
				  continue*/
			}
			if !(testCaseHaveAPIDependency || testCaseHaveThirdPartyDependency) {
				statisticRecode.NoDependencyDriverNum++
				threeTypeTestCase[noDependency] = append(threeTypeTestCase[noDependency], testCase.String())
				statisticRecode.AllTestCaseNum++
			} else if testCaseHaveAPIDependency && testCaseHaveThirdPartyDependency {
				statisticRecode.HaveTwoDependencyDriverNum++
				threeTypeTestCase[haveAPIDependency|haveThirdPartyDependency] =
					append(threeTypeTestCase[haveAPIDependency|haveThirdPartyDependency], testCase.String())
				statisticRecode.AllTestCaseNum++
			} else {
				statisticRecode.OtherDriverNum++
				threeTypeTestCase[otherDependency] =
					append(threeTypeTestCase[otherDependency], testCase.String())
				statisticRecode.AllTestCaseNum++
			}
		}

		/*if !(testCaseHaveAPIDependency && testCaseHaveThirdPartyDependency) {
			continue
		}*/

		//TestCaseAPINumMap[len(callees)] = append(TestCaseAPINumMap[len(callees)], testCase.String()) //用来计算density
		/*
				for _, ce := range callees {
					if ce.CallInstr.Parent() == testCase {
						tmpAPICount += 1
					}
				}


			tmpAPICount += int64(len(callees))
		*/
		/*if len(callees) > 3 && len(callees) < 15 && !testCaseHaveTestingAPI && testCaseHaveInterceptArg { //intercept arg还有点问题
		  	fmt.Println(testCase.String())
		  } else {
		  	//fmt.Println(fmt.Sprintf("%.4f", time.Since(start).Seconds()), "[-]", testCase.String())
		  }
		*/

		if doStatistics {
			statisticRecode.AllCalleeNum += len(callees)
			for _, callee := range callees {
				if callee.CalleeLocation&APIStandard != metainfo.EmptyCalleeType {
					APIMap[callee.Callee.String()] = true
				}
			}
		}
		APIInfos := fromCallInstInfoToAPIInfo(callees)

		curTestCaseInfo := &TestCaseInfo{}
		curTestCaseInfo.TestCaseSelf = testCase
		curTestCaseInfo.TestCaseCGS = &PartialCGStruct{TestCaseCG: pcgOfTestCase, CGCallees: callees}

		{
			constructFileNamePatternOfFuncWithCG(curTestCaseInfo.TestCaseCGS)
			constructRegexPatternOfFuncWithCG(curTestCaseInfo.TestCaseCGS)
			constructIpPatternOfFuncWithCG(curTestCaseInfo.TestCaseCGS)
		}

		if generateYaml {
			fileName := testCase.Prog.Fset.File(testCase.Pos()).Name()
			fileName = trimFilePathPrefix(fileName)
			testCaseMetaInfo = &metainfo.TestCaseMetaInfo{Name: testCase.String(),
				APISequence:  APIInfos,
				VariableList: []metainfo.VariableMetaInfo{},
				SrcPath:      fileName,
			}
		}
		if debugMode {
			printDebugInfo("---[-]Start Handle Callee")
		}
		changeable := HandleCallees(curTestCaseInfo, testCaseMetaInfo, callees, recordedNeedInterceptArgs)
		if debugMode {
			printDebugInfo("---[ok]End Handle Callee")
		}
		if doStatistics {
			if changeable {
				statisticRecode.ChangeableTestCaseNum++
				statisticRecode.ChangeableTestCaseList =
					append(statisticRecode.ChangeableTestCaseList, curTestCaseInfo.TestCaseSelf.String())
				if testCaseIsWrapper {
					statisticRecode.HandledWrapperNum++
				}
			}
			if testCaseHaveMustAlias {
				statisticRecode.MustAliasTestCaseNum++
			}
		}
		if generateYaml {
			testCaseMetaInfo.AllConstArray = getAllConstLocationToMetaInfo()
			data, err := yaml.Marshal(testCaseMetaInfo)
			if err != nil {
				panic(err)
			}
			file, err := os.OpenFile(filepath.Join("yaml_out_dir",
				strings.Replace(testCase.String(), "/", "_", -1)+".yaml"),
				os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				panic(err)
			}
			_, err = file.Write(data)
			if err != nil {
				panic(err)
			}
		}
		curPackageInfo.TestCases = append(curPackageInfo.TestCases, curTestCaseInfo)
		if debugMode {
			printDebugInfo("---[Test End]")
		}
	}
}

func resetGlobalVarCache() {
	testcaseWithFileName = make(map[*ssa.Function][]string)                 //testcase:filename
	functionInternalFuncTaintMap = make(map[*ssa.Function][]*funcTaintInfo) //func:taintInfo
	GlobalsOfFunctionMap = make(map[*ssa.Function][]*globalLocation)        //func:globalLocations
	ConstOperandsOfFunctionMap = make(map[*ssa.Function][]*constLocation)   //func:constLocations
}

//find all "struct" of this pkg
func fillPkgStructList(pkgs []*ssa.Package) {
	pkgStructList = make(map[string][]string)
	for _, pkg := range pkgs {
		if pkg != nil {
			for _, member := range pkg.Members {
				if strings.HasPrefix(member.Type().Underlying().String(), "struct{") {
					pkgStructList[pkg.String()] = append(pkgStructList[pkg.String()], member.Type().String())
				}
			}
		}
	}
}

func printPkgMembers(pkg *ssa.Package) {
	for membS, _ := range pkg.Members {
		printDebugInfo(membS)
	}
}

func NewScorerByPackages(pkgs []*ssa.Package) *Scorer {
	res := &Scorer{}
	fillPkgStructList(pkgs)
	for _, pkg := range pkgs { //handle package
		if pkg != nil { //&& strings.Contains(pkg.String(), "tar") {
			resetGlobalVarCache()
			//printPkgMembers(pkg)
			if debugMode {
				printProjDebugInfo("Handle Pkg: " + pkg.String())
				printProjDebugInfo("Collect TestCases..")
			}
			curPackageInfo := &PackageInfo{}
			curPackageInfo.Path = pkg.Pkg.Path()
			testCases := collectTestCasesFunctionFromPackage(pkg) //Get all TestCases. Could be used for specify a function
			if generateYaml {
				os.MkdirAll("yaml_out_dir", 0777)
			}
			HandleTestCases(curPackageInfo, testCases)
			res.PackageInfos = append(res.PackageInfos, curPackageInfo)
		} else {
			if debugMode {
				printProjDebugInfo("nil package!")
			}
		}
	}
	if doStatistics {
		statisticRecode.APIDensity = float64(statisticRecode.AllCalleeNum) / float64(statisticRecode.AllTestCaseNum)
		statisticRecode.CoveredAPINum = len(APIMap)
	}
	return res
}

func NewScorer(rootPatterns []string) *Scorer {
	if debugMode {
		setLogFileDir(path.Join(rootPatterns[1], "debugLog"))
	}
	if debugMode {
		printProjDebugInfo("Start Loading package")
	}
	if len(rootPatterns) == 2 {
		filePrefix = rootPatterns[1]
	}
	rootPatterns = rootPatterns[0:1]
	pkgs := pkgutils.LoadProjPackages(rootPatterns)
	if debugMode {
		printProjDebugInfo(fmt.Sprintf("How many packages:%d", len(pkgs)))
	}
	gPackages = &pkgs

	return NewScorerByPackages(pkgs)
}

var calleeList = []*DirectCalleeInfo{}

func (scorer Scorer) ShowScore() {
	pkginfos := scorer.PackageInfos
	for _, pkginfo := range pkginfos {
		tcs := pkginfo.TestCases
		for _, testcase := range tcs {
			callees := testcase.DirectCallees
			for _, callee := range callees {
				scores := callee.InfoOfParameters
				paramString := ""
				for _, score := range scores {
					paramString += fmt.Sprintf("%s<%s>, %d,", score.Name, parameterutils.ShowTag(score), score.Score)
				}
				calleeLocStr := ""
				switch callee.calleeLocation {
				case metainfo.StdCallee:
					calleeLocStr = "Std Callee"
				case metainfo.ThisPackageCallee:
					calleeLocStr = "This Pkg"
				case metainfo.OtherPackageCallee:
					calleeLocStr = "Other Pkg"
				case metainfo.MayThirdPackageCallee:
					calleeLocStr = "Maybe Third Pkg"
				case metainfo.TestingCallee:
					calleeLocStr = "Go Testing"
				}
				fmt.Printf("%s, %s, %s(%s), %s\n", pkginfo.Path, testcase.TestCaseSelf.Name(),
					callee.calleeSelf.Name(), calleeLocStr, paramString)
			}
		}
	}
}

func (scorer Scorer) OutputDensityCsv() {
	cArray := make([]int, 0)
	for key := range TestCaseAPINumMap {
		cArray = append(cArray, key)
	}
	sort.Ints(cArray)

	for _, key := range cArray {
		fmt.Print(strconv.Itoa(key) + "," + strconv.Itoa(len(TestCaseAPINumMap[key])))
		for _, tName := range TestCaseAPINumMap[key] {
			fmt.Print("," + tName)
		}
		fmt.Println()
	}
}
