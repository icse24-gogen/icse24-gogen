package scorer

import (
	"fmt"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"os"
	"reflect"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/propagation"
	"xyz.asd.qwe/gout-static-analysis/pkg/metainfo"
	"xyz.asd.qwe/gout-static-analysis/pkg/parameterutils"
	"sort"
	"strconv"
	"strings"
)

type testCaseRelatedInfo struct {
	inWhichPCGS       *PartialCGStruct
	PCGCallerCallSite *ssa.Call
	inWhichFullCG     *callgraph.Graph
	IDOfAllConst      int

	propagatedCallees        []*ssa.Function
	allTaintResults          []ssa.Node
	fullTaintResultsForAlias []ssa.Node

	canPropagateToReturn       bool
	canPropagateToFileName     bool
	canPropagateToRegexPattern bool
	canPropagateToIpAddress    bool
	canReachToMethodSelf       bool

	mayAlias  []metainfo.AliasInfo
	mustAlias []metainfo.AliasInfo
}

type constLocation struct {
	testCaseRelatedInfo
	constUsedInstr  ssa.Instruction
	constSelf       *ssa.Const
	constPos        token.Pos
	constFile       string
	constValue      string
	constType       string
	constUseType    metainfo.UseType
	inWhichFunction *ssa.Function

	callInstrPos token.Pos //if in call's args
	argIndex     int

	ImmediateArgForAliasAnalysis bool
}

type constsSlice []*constLocation

func (a constsSlice) Len() int {
	return len(a)
}
func (a constsSlice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a constsSlice) Less(i, j int) bool {
	return a[j].IDOfAllConst > a[i].IDOfAllConst
}

type globalLocation struct {
	globalUsedInstrs  []ssa.Instruction
	globalSelf        *ssa.Global
	globalPos         token.Pos
	globalFile        string
	globalType        string
	globalUseType     metainfo.UseType
	inWhichFunction   *ssa.Function
	inWhichPCGS       *PartialCGStruct
	PCGCallerCallSite *ssa.Call
	reachableCallee   []*ssa.Function
	allTaintResults   []ssa.Node

	canReachToReturn bool
}

type funcTaintInfo struct {
	callInstInfo    *CallInstInfo
	taintTo         []*CallInstInfo
	taintFrom       []*CallInstInfo
	allTaintResults []ssa.Node

	canReachToReturn bool
}

var GlobalsOfFunctionMap map[*ssa.Function][]*globalLocation
var allGlobalsOfTestCasePCGMap map[*ssa.Function][]*ssa.Function
var ConstOperandsOfFunctionMap map[*ssa.Function][]*constLocation      //function : [constLocs]
var allConstOperandsOfTestCasePCGMap map[*ssa.Function][]*ssa.Function //testCase : [testCase, Wrapper, ...]
var relatedGlobalList []*globalLocation
var relatedConstOperandList []*constLocation

var onceFields map[types.Type][]int //use for field-sensitive

func getSourceAllocOrGlobalOrMake(instr *ssa.Value) *ssa.Value { //需要添加一下各类Make的overtaint
	switch (*instr).(type) {
	case *ssa.FieldAddr:
		onceFields[(*instr).(*ssa.FieldAddr).X.Type().Underlying().(*types.Pointer).Elem()] =
			append(onceFields[(*instr).(*ssa.FieldAddr).X.Type().Underlying().(*types.Pointer).Elem()],
				(*instr).(*ssa.FieldAddr).Field)
		return getSourceAllocOrGlobalOrMake(&(*instr).(*ssa.FieldAddr).X)

	case *ssa.IndexAddr:
		return getSourceAllocOrGlobalOrMake(&(*instr).(*ssa.IndexAddr).X)

	case *ssa.MakeMap:
		storeOfMakeMap := findStoreOfInstr((*instr).(*ssa.MakeMap))
		if storeOfMakeMap != nil {
			return getSourceAllocOrGlobalOrMake(&storeOfMakeMap.Addr)
		} else {
			return instr
		}
	case *ssa.MakeSlice:
		storeOfMakeSlice := findStoreOfInstr((*instr).(*ssa.MakeSlice))
		if storeOfMakeSlice != nil {
			return getSourceAllocOrGlobalOrMake(&storeOfMakeSlice.Addr)
		} else {
			return instr
		}
	case *ssa.MakeInterface:
		storeOfMakeInterface := findStoreOfInstr((*instr).(*ssa.MakeInterface))
		if storeOfMakeInterface != nil {
			return getSourceAllocOrGlobalOrMake(&storeOfMakeInterface.Addr)
		} else {
			return instr
		}
	case *ssa.UnOp:
		return getSourceAllocOrGlobalOrMake(&(*instr).(*ssa.UnOp).X)
	case *ssa.Slice:
		storeOfSlice := findStoreOfInstr((*instr).(*ssa.Slice))
		if storeOfSlice != nil {
			return getSourceAllocOrGlobalOrMake(&storeOfSlice.Addr)
		} else {
			return instr
		}
	case *ssa.Alloc:
		if (*instr).(*ssa.Alloc).Heap == true {
			allocPtr := (*instr).(*ssa.Alloc)
			for _, refInstr := range *allocPtr.Referrers() { //如果refer里有make interface，这种就直接taint
				if makeInterfacePtr, toMakeInterfacePtrOk := refInstr.(*ssa.MakeInterface); toMakeInterfacePtrOk && makeInterfacePtr.X.Name() == allocPtr.Name() {
					return instr
				}
			}

			storeOfAlloc := findStoreOfInstr((*instr).(*ssa.Alloc))
			if storeOfAlloc != nil {
				return getSourceAllocOrGlobalOrMake(&storeOfAlloc.Addr)
			}
		}
		return instr
	case *ssa.Global:
		return instr
	default:
		return instr
	}
}

func getMapDefInstr(MUInst *ssa.MapUpdate) *ssa.Value {
	return getSourceAllocOrGlobalOrMake(&MUInst.Map)
}

func analyzeConstTaintInPCG(constV *constLocation, forMethod bool) { //Store IndexAddr Slice BinOp
	if debugMode {
		printDebugInfo("--------------[ok]Const Value: " + constV.constValue)
	}
	pcgS := constV.inWhichPCGS
	callSite := constV.PCGCallerCallSite
	prog := propagation.Propagation{}
	progForAlias := propagation.Propagation{}
	onceFields = make(map[types.Type][]int) //reset fields record
	switch constV.constUsedInstr.(type) {
	case *ssa.Store:
		storePtr := constV.constUsedInstr.(*ssa.Store)
		prog = propagation.TaintInPCG(storePtr, pcgS.TestCaseCG, callSite)
		progForAlias = propagation.TaintInPCG(storePtr, constV.inWhichFullCG, callSite)

		_, okFA := storePtr.Addr.(*ssa.FieldAddr)
		_, okIA := storePtr.Addr.(*ssa.IndexAddr)
		if okFA || okIA {
			sourceInst := *getSourceAllocOrGlobalOrMake(&storePtr.Addr) //over taint
			if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
				prog, onceFields = propagation.TaintWithFieldInPCG(allocInstr, onceFields, pcgS.TestCaseCG, callSite)
				progForAlias, onceFields = propagation.TaintWithFieldInPCG(allocInstr, onceFields, constV.inWhichFullCG, callSite)
			} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
				prog = propagation.TaintInPCG(globalPtr, pcgS.TestCaseCG, callSite)
			}
		}
	case *ssa.Convert:
		storeOfConvert := findStoreOfInstr(constV.constUsedInstr.(*ssa.Convert))
		if storeOfConvert != nil {
			prog = propagation.TaintInPCG(storeOfConvert, pcgS.TestCaseCG, callSite)
			progForAlias = propagation.TaintInPCG(storeOfConvert, constV.inWhichFullCG, callSite)
		} else {
			prog = propagation.TaintInPCG(constV.constUsedInstr.(*ssa.Convert), pcgS.TestCaseCG, callSite)
			progForAlias = propagation.TaintInPCG(constV.constUsedInstr.(*ssa.Convert), constV.inWhichFullCG, callSite)
		}
	case *ssa.IndexAddr:
		indexAPtr := constV.constUsedInstr.(*ssa.IndexAddr)
		prog = propagation.TaintInPCG(indexAPtr, pcgS.TestCaseCG, callSite)
		progForAlias = propagation.TaintInPCG(indexAPtr, constV.inWhichFullCG, callSite)
		sourceInst := *getSourceAllocOrGlobalOrMake(&indexAPtr.X) //over taint
		if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
			prog = propagation.TaintInPCG(allocInstr, pcgS.TestCaseCG, callSite)
			progForAlias = propagation.TaintInPCG(allocInstr, constV.inWhichFullCG, callSite)
		} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
			prog = propagation.TaintInPCG(globalPtr, pcgS.TestCaseCG, callSite)
		}
	case *ssa.Slice:
		slicePtr := constV.constUsedInstr.(*ssa.Slice)
		prog = propagation.TaintInPCG(slicePtr, pcgS.TestCaseCG, callSite)
		progForAlias = propagation.TaintInPCG(slicePtr, constV.inWhichFullCG, callSite)
	case *ssa.BinOp:
		storeOfBinOp := findStoreOfInstr(constV.constUsedInstr.(*ssa.BinOp))
		if storeOfBinOp != nil {
			prog = propagation.TaintInPCG(storeOfBinOp, pcgS.TestCaseCG, callSite)
			progForAlias = propagation.TaintInPCG(storeOfBinOp, constV.inWhichFullCG, callSite)
		} else {
			binOpPtr := constV.constUsedInstr.(*ssa.BinOp)
			prog = propagation.TaintInPCG(binOpPtr, pcgS.TestCaseCG, callSite)
			progForAlias = propagation.TaintInPCG(binOpPtr, constV.inWhichFullCG, callSite)
		}
	case *ssa.MapUpdate:
		mapUpdatePtr := constV.constUsedInstr.(*ssa.MapUpdate)
		sourceInst := *getMapDefInstr(mapUpdatePtr)
		if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
			prog = propagation.TaintInPCG(allocInstr, pcgS.TestCaseCG, callSite)
			progForAlias = propagation.TaintInPCG(allocInstr, constV.inWhichFullCG, callSite)
		} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
			prog = propagation.TaintInPCG(globalPtr, pcgS.TestCaseCG, callSite)
		}
	case *ssa.Call:
		if constV.constUsedInstr.(*ssa.Call).Call.StaticCallee() != nil {
			paraList := constV.constUsedInstr.(*ssa.Call).Call.StaticCallee().Params
			if len(paraList) == 0 {
				return
			}
			paraPtr := paraList[constV.argIndex]
			if _, ok := pcgS.TestCaseCG.Nodes[constV.constUsedInstr.(*ssa.Call).Call.StaticCallee()]; ok { //wrapper
				tmpCallSite := constV.constUsedInstr.(*ssa.Call)
				prog = propagation.TaintInPCG(paraPtr, pcgS.TestCaseCG, tmpCallSite, true)
				if prog.HaveRet() {
					prog.AddTaintInPCG(callSite, pcgS.TestCaseCG, nil)
				}
			} else {
				//prog = propagation.TaintInPCG(constV.constUsedInstr.(*ssa.Call), pcgS.TestCaseCG, callSite) //don't taint call res
				prog = propagation.Propagation{}
				prog.AddNode(constV.constUsedInstr.(*ssa.Call))
			}
			progForAlias = propagation.TaintInPCG(paraPtr, constV.inWhichFullCG, callSite)
			progForAlias.AddNode(constV.constUsedInstr.(*ssa.Call))
		} else {
			return
		}
	}

	taintedNodes := prog.GetTaintedNodes() //TODO:如果需要增加污点传播逻辑，也许到这里增加，taint到什么类型的node时增加taint

	//check if file const
	if fileStrings, ok := testcaseWithFileName[constV.inWhichFunction]; ok {
		for _, tNode := range taintedNodes {
			nodeString := tNode.String()
			if tNode.Parent() == nil {
				continue
			}
			for _, fileString := range fileStrings {
				if strings.Contains(strings.ToLower(nodeString+"|"+tNode.Parent().String()), strings.ToLower(fileString)) ||
					strings.Contains(strings.ToLower(constV.constValue+"|"+constV.inWhichFunction.String()), strings.ToLower(fileString)) { //node String is a file String
					constV.canPropagateToFileName = true
				}
			}
		}
	}
	if regexStrings, ok := testcaseWithRegexPattern[constV.inWhichFunction]; ok {
		for _, tNode := range taintedNodes {
			nodeString := tNode.String()
			if tNode.Parent() == nil {
				continue
			}
			for _, regexString := range regexStrings {
				if strings.Contains(strings.ToLower(nodeString+"|"+tNode.Parent().String()), strings.ToLower(regexString)) { //node String is a regex String
					constV.canPropagateToRegexPattern = true
				}
			}
		}
	}
	if ipStrings, ok := testcaseWithIpAddress[constV.inWhichFunction]; ok {
		for _, tNode := range taintedNodes {
			nodeString := tNode.String()
			if tNode.Parent() == nil {
				continue
			}
			for _, ipString := range ipStrings {
				if strings.Contains(strings.ToLower(nodeString+"|"+tNode.Parent().String()), strings.ToLower(ipString)) { //node String is a file String
					constV.canPropagateToIpAddress = true
				}
			}
		}
	}

	for _, tNode := range taintedNodes { //分析能taint到的所有callee
		if callPtr, toCallOk := tNode.(*ssa.Call); toCallOk {
			callee := callPtr.Call.StaticCallee()
			if callee != nil {
				constV.propagatedCallees = append(constV.propagatedCallees, callee)
			}
		}
	}

	for _, tNode := range taintedNodes { //分析能否taint到return
		if _, toReturnOk := tNode.(*ssa.Return); toReturnOk {
			constV.canPropagateToReturn = true
			break
		}
	}

	if debugMode {
		if constV.canPropagateToFileName {
			printDebugInfo("--------------[!]Const can propagate to fileName arg")
		}
		if len(constV.propagatedCallees) == 0 {
			printDebugInfo("--------------[?]Const can't propagate to any call")
		}
		if constV.canPropagateToReturn {
			printDebugInfo("--------------[-]Const can propagate to [Return]")
		}
	}
	if forMethod {
		for _, tNode := range prog.GetTaintedNodes() { //分析能否store到self
			if storePtr, toStoreOk := tNode.(*ssa.Store); toStoreOk {
				val := storePtr.Val
				if paraPtr, toParaOk := val.(*ssa.Parameter); toParaOk {
					paraName := paraPtr.Name()
					selfPara := constV.inWhichFunction.Signature.Recv()
					if selfPara != nil {
						selfParaName := selfPara.Name()
						if paraName == selfParaName {
							constV.canReachToMethodSelf = true
							break
						}
					}
				}
			}
		}
	}

	constV.allTaintResults = taintedNodes
	constV.fullTaintResultsForAlias = progForAlias.GetTaintedNodes()
}

func findStoreOfInstr(instr ssa.Instruction) *ssa.Store {
	switch instr.(type) {
	case *ssa.Alloc:
		allocPtr := instr.(*ssa.Alloc)
		for _, refInstr := range *allocPtr.Referrers() {
			if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk && storePtr.Val.Name() == allocPtr.Name() {
				return storePtr
			} else if slicePtr, toSliceOk := refInstr.(*ssa.Slice); toSliceOk {
				storeOfSlice := findStoreOfInstr(slicePtr)
				if storeOfSlice != nil {
					return storeOfSlice
				}
			}
		}
	case *ssa.Convert:
		cvtPtr := instr.(*ssa.Convert)
		for _, refInstr := range *cvtPtr.Referrers() {
			if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk && storePtr.Val.Name() == cvtPtr.Name() {
				return storePtr
			}
		}
	case *ssa.BinOp:
		binOpPtr := instr.(*ssa.BinOp)
		for _, refInstr := range *binOpPtr.Referrers() {
			if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk && storePtr.Val.Name() == binOpPtr.Name() {
				return storePtr
			}
		}
	case *ssa.Slice:
		sliceOpPtr := instr.(*ssa.Slice)
		for _, refInstr := range *sliceOpPtr.Referrers() {
			if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk && storePtr.Val.Name() == sliceOpPtr.Name() {
				return storePtr
			}
		}
	case *ssa.MakeMap:
		makeMapPtr := instr.(*ssa.MakeMap)
		for _, refInstr := range *makeMapPtr.Referrers() {
			if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk && storePtr.Val.Name() == makeMapPtr.Name() {
				return storePtr
			}
		}
	case *ssa.MakeSlice:
		makeSlicePtr := instr.(*ssa.MakeSlice)
		for _, refInstr := range *makeSlicePtr.Referrers() {
			if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk && storePtr.Val.Name() == makeSlicePtr.Name() {
				return storePtr
			}
		}
	case *ssa.MakeInterface:
		makeInterfacePtr := instr.(*ssa.MakeInterface)
		for _, refInstr := range *makeInterfacePtr.Referrers() {
			if storePtr, toStoreOk := refInstr.(*ssa.Store); toStoreOk && storePtr.Val.Name() == makeInterfacePtr.Name() {
				return storePtr
			}
		}
	}
	return nil
}

func refreshAllTestCaseRelatedInfo(cLArr []*constLocation, pcgS *PartialCGStruct, fullCG *callgraph.Graph, callSite *ssa.Call, forMethod bool) {
	for _, cst := range cLArr {
		cst.inWhichPCGS = pcgS
		cst.inWhichFullCG = fullCG
		cst.PCGCallerCallSite = callSite
		cst.IDOfAllConst = allConstId
		allConstId++

		cst.propagatedCallees = make([]*ssa.Function, 0)
		cst.allTaintResults = make([]ssa.Node, 0)
		cst.fullTaintResultsForAlias = make([]ssa.Node, 0)

		cst.canPropagateToReturn = false
		cst.canPropagateToFileName = false
		cst.canPropagateToRegexPattern = false
		cst.canPropagateToIpAddress = false
		cst.canReachToMethodSelf = false

		cst.mayAlias = make([]metainfo.AliasInfo, 0)
		cst.mustAlias = make([]metainfo.AliasInfo, 0)
		analyzeConstTaintInPCG(cst, forMethod)
	}
}

var lastPCG *PartialCGStruct

func initTheConstVarsOfFunctionInPCG(fn *ssa.Function, forMethod bool, pcgS *PartialCGStruct, callSite *ssa.Call, fullCG *callgraph.Graph) {
	cg := pcgS.TestCaseCG
	if cLArr, ok := ConstOperandsOfFunctionMap[fn]; ok {
		if debugMode {
			printDebugInfo("-----------[!]Const Values(in CG) of function had been initialized, use cache:" + fn.String())
		}

		refreshAllTestCaseRelatedInfo(cLArr, pcgS, fullCG, callSite, forMethod)
		if debugMode {
			printDebugInfo("-----------[ok]Refresh CG info ok:" + fn.String())
		}
		allConstOperandsOfTestCasePCGMap[cg.Root.Func] = append(allConstOperandsOfTestCasePCGMap[cg.Root.Func], fn)
		lastPCG = pcgS
		return
	} else {
		if debugMode {
			printDebugInfo("-----------[-]Init Const Values(in CG) of function: " + fn.String())
		}
		if ConstOperandsOfFunctionMap == nil {
			ConstOperandsOfFunctionMap = make(map[*ssa.Function][]*constLocation)
		}
		allConstOperandsOfTestCasePCGMap[cg.Root.Func] = append(allConstOperandsOfTestCasePCGMap[cg.Root.Func], fn)
		lastPCG = pcgS
	}
	for _, block := range fn.Blocks { //先找出全部的常量operand
		for instrIdx, instr := range block.Instrs {
			if _, toMIOk := instr.(*ssa.MakeInterface); instr.Pos() == 0 && !toMIOk { //IR builtin generated
				continue
			}
			/*if _, miOk := instr.(*ssa.MakeInterface); miOk {
			    var operandList []*ssa.Value
			    operandList = instr.Operands(operandList)
			    for _, operandPtr := range operandList {
			        operand := *operandPtr
			        if _, toConstOk := operand.(*ssa.Const); toConstOk {
			            fmt.Println("yes")
			        }
			    }
			}*/
			var operandList []*ssa.Value
			operandList = instr.Operands(operandList)
			for operandIdx, operandPtr := range operandList { //收集所有const operand
				operand := *operandPtr
				if constPtr, toConstOk := operand.(*ssa.Const); toConstOk {
					switch instr.(type) { //常量被用在不同的指令中，需要做不同的处理
					case *ssa.Store:
						tmpUseType := metainfo.InStore
						if strings.Contains(block.Comment, "loop") {
							tmpUseType = metainfo.InLoopComparison
						}
						constStruct := &constLocation{constSelf: constPtr,
							constPos:        instr.(*ssa.Store).Pos(), //Const itself don't have pos
							constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Pos()).Name()),
							constType:       constPtr.Type().String(),
							constValue:      constPtr.String(),
							constUseType:    tmpUseType,
							constUsedInstr:  instr.(*ssa.Store),
							inWhichFunction: fn,
							testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
								inWhichFullCG:     fullCG,
								PCGCallerCallSite: callSite,
								IDOfAllConst:      allConstId},
						}
						allConstId++
						ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
						analyzeConstTaintInPCG(constStruct, forMethod)
					case *ssa.Convert:
						constStruct := &constLocation{constSelf: constPtr,
							constPos:        instr.(*ssa.Convert).Pos(),
							constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Pos()).Name()),
							constType:       constPtr.Type().String(),
							constValue:      constPtr.String(),
							constUseType:    metainfo.InConvert,
							constUsedInstr:  instr.(*ssa.Convert),
							inWhichFunction: fn,
							testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
								inWhichFullCG:     fullCG,
								PCGCallerCallSite: callSite,
								IDOfAllConst:      allConstId},
						}
						allConstId++
						ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
						analyzeConstTaintInPCG(constStruct, forMethod)
					case *ssa.IndexAddr:
						constStruct := &constLocation{constSelf: constPtr,
							constPos:        instr.(*ssa.IndexAddr).Pos(),
							constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Pos()).Name()),
							constType:       constPtr.Type().String(),
							constValue:      constPtr.String(),
							constUseType:    metainfo.InIndexAddr,
							constUsedInstr:  instr.(*ssa.IndexAddr),
							inWhichFunction: fn,
							testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
								inWhichFullCG:     fullCG,
								PCGCallerCallSite: callSite,
								IDOfAllConst:      allConstId},
						}
						allConstId++
						ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
						analyzeConstTaintInPCG(constStruct, forMethod)
					case *ssa.Slice:
						var constStruct *constLocation
						if allocPtr, toAllocOk := block.Instrs[instrIdx-1].(*ssa.Alloc); toAllocOk && allocPtr.Comment == "makeslice" {
							constStruct = &constLocation{constSelf: constPtr,
								constPos:        token.NoPos,
								constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Parent().Pos()).Name()),
								constType:       constPtr.Type().String(),
								constValue:      constPtr.String(),
								constUseType:    metainfo.InSlice,
								constUsedInstr:  instr.(*ssa.Slice),
								inWhichFunction: fn,
								testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
									inWhichFullCG:     fullCG,
									PCGCallerCallSite: callSite,
									IDOfAllConst:      allConstId},
								callInstrPos: instr.(*ssa.Slice).Pos(),
								argIndex:     1, //make([]xxx, )的第一个坐标
							}
						} else {
							constStruct = &constLocation{constSelf: constPtr,
								constPos:        instr.(*ssa.Slice).Pos(),
								constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Pos()).Name()),
								constType:       constPtr.Type().String(),
								constValue:      constPtr.String(),
								constUseType:    metainfo.InSlice,
								constUsedInstr:  instr.(*ssa.Slice),
								inWhichFunction: fn,
								testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
									inWhichFullCG:     fullCG,
									PCGCallerCallSite: callSite,
									IDOfAllConst:      allConstId},
							}
						}
						allConstId++
						ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
						analyzeConstTaintInPCG(constStruct, forMethod)
					case *ssa.BinOp:
						tmpUseType := metainfo.InBinaryOperator
						if strings.Contains(block.Comment, "loop") {
							tmpUseType = metainfo.InLoopComparison
						}
						constStruct := &constLocation{constSelf: constPtr,
							constPos:        instr.(*ssa.BinOp).Pos(),
							constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Pos()).Name()),
							constType:       constPtr.Type().String(),
							constValue:      constPtr.String(),
							constUseType:    tmpUseType,
							constUsedInstr:  instr.(*ssa.BinOp),
							inWhichFunction: fn,
							testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
								inWhichFullCG:     fullCG,
								PCGCallerCallSite: callSite,
								IDOfAllConst:      allConstId},
						}
						allConstId++
						ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
						analyzeConstTaintInPCG(constStruct, forMethod)
					case *ssa.MapUpdate:
						if operand == instr.(*ssa.MapUpdate).Key { //ignore map key
							continue
						}
						constStruct := &constLocation{constSelf: constPtr,
							constPos:        instr.(*ssa.MapUpdate).Pos(),
							constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Pos()).Name()),
							constType:       constPtr.Type().String(),
							constValue:      constPtr.String(),
							constUsedInstr:  instr.(*ssa.MapUpdate),
							constUseType:    metainfo.InMap,
							inWhichFunction: fn,
							testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
								inWhichFullCG:     fullCG,
								PCGCallerCallSite: callSite,
								IDOfAllConst:      allConstId},
						}
						allConstId++
						ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
						analyzeConstTaintInPCG(constStruct, forMethod)
					case *ssa.MakeInterface:
						if len(*(instr.(*ssa.MakeInterface).Referrers())) == 1 {
							if callPtr, toCallOk := (*(instr.(*ssa.MakeInterface).Referrers()))[0].(*ssa.Call); toCallOk {
								var idx int
								for argIdx, arg := range callPtr.Call.Args {
									if instr.String() == arg.String() {
										idx = argIdx
									}
								}
								constStruct := &constLocation{constSelf: constPtr,
									constPos:        token.NoPos,
									constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Parent().Pos()).Name()),
									constType:       constPtr.Type().String(),
									constValue:      constPtr.String(),
									constUseType:    metainfo.InCall,
									constUsedInstr:  callPtr,
									inWhichFunction: fn,
									testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
										inWhichFullCG:     fullCG,
										PCGCallerCallSite: callSite,
										IDOfAllConst:      allConstId},
									callInstrPos: callPtr.Pos(),
									argIndex:     idx,
								}
								allConstId++
								ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
								analyzeConstTaintInPCG(constStruct, forMethod)
							} else if mapUpdatePtr, toMapUpdateOk := (*(instr.(*ssa.MakeInterface).Referrers()))[0].(*ssa.MapUpdate); toMapUpdateOk {
								if operand == mapUpdatePtr.Key { //ignore map key
									continue
								}
								constStruct := &constLocation{constSelf: constPtr,
									constPos:        mapUpdatePtr.Pos(),
									constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Parent().Pos()).Name()),
									constType:       constPtr.Type().String(),
									constValue:      constPtr.String(),
									constUsedInstr:  mapUpdatePtr,
									constUseType:    metainfo.InMap,
									inWhichFunction: fn,
									testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
										inWhichFullCG:     fullCG,
										PCGCallerCallSite: callSite,
										IDOfAllConst:      allConstId},
								}
								allConstId++
								ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
								analyzeConstTaintInPCG(constStruct, forMethod)
							}
						}
					case *ssa.Call:
						if instr.(*ssa.Call).Call.StaticCallee() == nil {
							continue
						}
						tmpArgIdx := operandIdx - 1
						if instr.(*ssa.Call).Call.StaticCallee().Signature.Recv() != nil &&
							strings.Contains(instr.(*ssa.Call).Call.Args[0].String(), "*") {
							tmpArgIdx -= 1
						}
						if tmpArgIdx < 0 { //unexpected behavior
							continue
						}
						constStruct := &constLocation{constSelf: constPtr,
							constPos:        token.NoPos,
							constFile:       trimFilePathPrefix(fn.Prog.Fset.File(instr.Pos()).Name()),
							constType:       constPtr.Type().String(),
							constValue:      constPtr.String(),
							constUsedInstr:  instr.(*ssa.Call),
							constUseType:    metainfo.InCall,
							inWhichFunction: fn,
							testCaseRelatedInfo: testCaseRelatedInfo{inWhichPCGS: pcgS,
								inWhichFullCG:     fullCG,
								PCGCallerCallSite: callSite,
								IDOfAllConst:      allConstId},
							callInstrPos:                 instr.Pos(),
							argIndex:                     tmpArgIdx, //call's operand -> CallCommon + Args
							ImmediateArgForAliasAnalysis: true,
						}
						allConstId++
						ConstOperandsOfFunctionMap[fn] = append(ConstOperandsOfFunctionMap[fn], constStruct)
						analyzeConstTaintInPCG(constStruct, forMethod)
					}
				}
			}
		}
	}

}

func getConstArgsInPCG(isForMethod bool, pcgS *PartialCGStruct, callSite *ssa.Call, fullCG *callgraph.Graph) {
	cg := pcgS.TestCaseCG
	if debugMode {
		printDebugInfo("----------Find Const Args(in CG) of callInst: " + callSite.Call.StaticCallee().String() + ". In:" + callSite.Parent().String())
	}
	if _, ok := ConstOperandsOfFunctionMap[callSite.Parent()]; ok {
		return
	} else {
		if ConstOperandsOfFunctionMap == nil {
			ConstOperandsOfFunctionMap = make(map[*ssa.Function][]*constLocation)
		}
		allConstOperandsOfTestCasePCGMap[cg.Root.Func] = append(allConstOperandsOfTestCasePCGMap[cg.Root.Func], callSite.Parent())
	}
	for idx, arg := range callSite.Call.Args {
		if constPtr, toConstOk := arg.(*ssa.Const); toConstOk {
			constStruct := &constLocation{constSelf: constPtr,
				constPos:        token.NoPos,
				constFile:       trimFilePathPrefix(callSite.Parent().Prog.Fset.File(callSite.Pos()).Name()),
				constType:       constPtr.Type().String(),
				constValue:      constPtr.String(),
				constUsedInstr:  callSite,
				constUseType:    metainfo.InCall,
				inWhichFunction: callSite.Parent(),
				callInstrPos:    callSite.Pos(),
				argIndex:        idx,
				testCaseRelatedInfo: testCaseRelatedInfo{
					inWhichPCGS:       pcgS,
					inWhichFullCG:     fullCG,
					PCGCallerCallSite: callSite,
					IDOfAllConst:      allConstId},
			}
			allConstId++
			ConstOperandsOfFunctionMap[callSite.Parent()] = append(ConstOperandsOfFunctionMap[callSite.Parent()], constStruct)
			analyzeConstTaintInPCG(constStruct, isForMethod)
		}
	}
}

func getExtraCGForAlias(testCase *ssa.Function) *callgraph.Graph {
	cgOfTestCase := callgraph.New(testCase)
	constructFCGOfTestCase(testCase, cgOfTestCase, cgOfTestCase.Root)
	return cgOfTestCase
}

func mustAliasAnalysis(allConst []*constLocation) {
	for _, constant := range allConst {
		globalRecord := make([]*ssa.Global, 0)
		fieldRecord := make([]string, 0)
		if len(constant.mayAlias) != 0 {
			for _, tNode := range constant.fullTaintResultsForAlias {
				if storePtr, toStoreOk := tNode.(*ssa.Store); toStoreOk { //store to which global/field
					switch storePtr.Addr.(type) {
					case *ssa.Global:
						globalRecord = append(globalRecord, storePtr.Addr.(*ssa.Global))
					case *ssa.FieldAddr:
						fieldString := storePtr.Addr.(*ssa.FieldAddr).X.Type().String() + ":" + strconv.Itoa(storePtr.Addr.(*ssa.FieldAddr).Field)
						fieldRecord = append(fieldRecord, fieldString)
					}
				} else if mapUpdatePtr, toMapUpOk := tNode.(*ssa.MapUpdate); toMapUpOk { //store to which map
					switch mapUpdatePtr.Map.(type) {
					case *ssa.Global:
						globalRecord = append(globalRecord, mapUpdatePtr.Map.(*ssa.Global))
					}
				} else if callPtr, toCallOk := tNode.(*ssa.Call); toCallOk { // relate to which global struct
					if callPtr.Call.Signature().Recv() != nil && len(callPtr.Call.Args) != 0 {
						selfPtr := callPtr.Call.Args[0]
						switch selfPtr.(type) {
						case *ssa.Global:
							globalRecord = append(globalRecord, selfPtr.(*ssa.Global))
						}
					}
				}
			}

			recordedMustAlias := make([]int, 0)
			for mayAliasIdx, mayAliasC := range constant.mayAlias {
				found := false
				for _, tNode := range allConst[mayAliasC.IDOfAllConst].fullTaintResultsForAlias {
					if found {
						break
					}
					if storePtr, toStoreOk := tNode.(*ssa.Store); toStoreOk { //store to the same global/field
						switch storePtr.Addr.(type) {
						case *ssa.Global:
							for _, rGlobal := range globalRecord {
								if rGlobal == storePtr.Addr.(*ssa.Global) {
									mayAliasC.AliasType = metainfo.StoreToSameGlobalVar
									testCaseHaveMustAlias = true
									constant.mustAlias = append(constant.mustAlias, mayAliasC)
									recordedMustAlias = append(recordedMustAlias, mayAliasIdx)
									if debugMode {
										printDebugInfo("-----------[ok]Must Alias:" + strconv.Itoa(constant.IDOfAllConst) + " " + strconv.Itoa(mayAliasC.IDOfAllConst))
									}
									found = true
									break
								}
							}
						case *ssa.FieldAddr:
							fieldString := storePtr.Addr.(*ssa.FieldAddr).X.Type().String() + ":" + strconv.Itoa(storePtr.Addr.(*ssa.FieldAddr).Field)
							for _, rField := range fieldRecord {
								if fieldString == rField {
									mayAliasC.AliasType = metainfo.StoreToSameStructField
									constant.mustAlias = append(constant.mustAlias, mayAliasC)
									testCaseHaveMustAlias = true
									recordedMustAlias = append(recordedMustAlias, mayAliasIdx)
									found = true
									if debugMode {
										printDebugInfo("-----------[ok]Must Alias:" + strconv.Itoa(constant.IDOfAllConst) + " " + strconv.Itoa(mayAliasC.IDOfAllConst))
									}
									break
								}
							}
						}
					} else if mapUpdatePtr, toMapUpOk := tNode.(*ssa.MapUpdate); toMapUpOk {
						switch mapUpdatePtr.Map.(type) {
						case *ssa.Global:
							for _, rGlobal := range globalRecord {
								if rGlobal == mapUpdatePtr.Map.(*ssa.Global) {
									mayAliasC.AliasType = metainfo.StoreToSameGlobalMap
									testCaseHaveMustAlias = true
									constant.mustAlias = append(constant.mustAlias, mayAliasC)
									recordedMustAlias = append(recordedMustAlias, mayAliasIdx)
									found = true
									if debugMode {
										printDebugInfo("-----------[ok]Must Alias:" + strconv.Itoa(constant.IDOfAllConst) + " " + strconv.Itoa(mayAliasC.IDOfAllConst))
									}
									break
								}
							}
						}
					} else if callPtr, toCallOk := tNode.(*ssa.Call); toCallOk { // relate to which global struct
						if callPtr.Call.Signature().Recv() != nil && len(callPtr.Call.Args) != 0 {
							selfPtr := callPtr.Call.Args[0]
							switch selfPtr.(type) {
							case *ssa.Global:
								for _, rGlobal := range globalRecord {
									if rGlobal == selfPtr.(*ssa.Global) {
										mayAliasC.AliasType = metainfo.RelateToSameGlobalStructVar
										testCaseHaveMustAlias = true
										constant.mustAlias = append(constant.mustAlias, mayAliasC)
										recordedMustAlias = append(recordedMustAlias, mayAliasIdx)
										found = true
										if debugMode {
											printDebugInfo("-----------[ok]Must Alias:" + strconv.Itoa(constant.IDOfAllConst) + " " + strconv.Itoa(mayAliasC.IDOfAllConst))
										}
										break
									}
								}
							}
						}
					}
				}
			}

			deleteCount := 0
			for _, rIdx := range recordedMustAlias { //delete must alias
				constant.mayAlias = append(constant.mayAlias[:rIdx-deleteCount], constant.mayAlias[rIdx-deleteCount+1:]...)
				deleteCount++
			}
		}
	}
}

func fillAliasForTestCase(allConst []*constLocation) {
	haveAlias := make(map[int]bool)
	for i := 0; i < len(allConst); i++ {
		for j := i + 1; j < len(allConst); j++ {
			if haveAlias[i] && haveAlias[j] {
				continue
			}
			if allConst[i].constType == allConst[j].constType && allConst[i].constValue == allConst[j].constValue { //先找到所有值一致的const
				allConst[i].mayAlias = append(allConst[i].mayAlias,
					metainfo.AliasInfo{
						AliasType:    metainfo.BaseAlias,
						IDOfAllConst: allConst[j].IDOfAllConst,
					},
				)
				allConst[j].mayAlias = append(allConst[i].mayAlias,
					metainfo.AliasInfo{
						AliasType:    metainfo.BaseAlias,
						IDOfAllConst: allConst[i].IDOfAllConst,
					},
				)
				haveAlias[i] = true
				haveAlias[j] = true
				if debugMode {
					printDebugInfo("-----------[?]May Alias idx:" + strconv.Itoa(allConst[i].IDOfAllConst) + " " + strconv.Itoa(allConst[j].IDOfAllConst))
				}
			}
		}
	}
	mustAliasAnalysis(allConst)
}

var allConstId = 0

func initTheConstVarsOfCG(pcgS *PartialCGStruct, isForMethod bool) []*constLocation {
	cg := pcgS.TestCaseCG
	allConstId = 0
	if _, ok := allConstOperandsOfTestCasePCGMap[cg.Root.Func]; ok { //PCG的常量已经初始化过了
		return nil
	} else {
		if debugMode {
			printDebugInfo("----------[-]Init Const Values of CG: " + cg.Root.Func.String())
		}
		if allConstOperandsOfTestCasePCGMap == nil {
			allConstOperandsOfTestCasePCGMap = make(map[*ssa.Function][]*ssa.Function)
		}
		allConstOperandsOfTestCasePCGMap[cg.Root.Func] = make([]*ssa.Function, 0) //第一次初始化PCG的常量
	}

	fullCG := getExtraCGForAlias(pcgS.TestCaseCG.Root.Func)
	initTheConstVarsOfFunctionInPCG(cg.Root.Func, isForMethod, pcgS, nil, fullCG) //先初始化TestCase内的常量
	callgraph.GraphVisitEdges(cg, func(e *callgraph.Edge) error {
		/*if e.Site.Value() != nil && e.Site.Value().Call.StaticCallee() != nil {
		  	getConstArgsInPCG(isForMethod, pcgS, e.Site.Value(), fullCG)
		  }
		*/
		initTheConstVarsOfFunctionInPCG(e.Callee.Func, isForMethod, pcgS, e.Site.Value(), fullCG) //todo:这里只给了一个callSite，可能会有多个callSite+callpath
		return nil
	})

	allConst := make([]*constLocation, 0)
	pcgFnList := allConstOperandsOfTestCasePCGMap[cg.Root.Func]
	for _, fn := range pcgFnList {
		allConst = append(allConst, ConstOperandsOfFunctionMap[fn]...)
	}
	sort.Sort(constsSlice(allConst)) //sort by const ID

	if debugMode {
		printDebugInfo("----------[ok]Total C in CG: " + strconv.Itoa(allConstId) + " " + strconv.Itoa(len(allConst)))
		printDebugInfo("----------[-]Start Alias analysis")
	}
	fillAliasForTestCase(allConst)
	if debugMode {
		printDebugInfo("----------[ok]Alias analysis end")
	}
	return allConst
}

func addRelatedConstOperand(relatedC *constLocation, needJudgeArg ssa.Value) {
	if relatedC.canPropagateToFileName {
		if debugMode {
			printDebugInfo("-----------[?]Reach to Arg const, but may be related to fileName :" + relatedC.constValue)
		}
		return
	} else if relatedC.canPropagateToRegexPattern {
		if debugMode {
			printDebugInfo("-----------[?]Reach to Arg const, but may be related to regex pattern :" + relatedC.constValue)
		}
		return
	} else if relatedC.canPropagateToIpAddress {
		if debugMode {
			printDebugInfo("-----------[?]Reach to Arg const, but may be related to ip address :" + relatedC.constValue)
		}
		return
	}
	if storePtr, toStoreOk := relatedC.constUsedInstr.(*ssa.Store); toStoreOk {
		if localPtr, ok := storePtr.Addr.(*ssa.Alloc); ok {
			localPtr.String()
			if localPtr.Comment == "" { // Maybe loop control variable
				return
			}
		}
	}
	if relatedC.callInstrPos == 0 {
		for _, pos := range relatedConstOperandList { //deduplication
			if pos.constPos == relatedC.constPos && pos.constUseType != metainfo.InSlice {
				return
			}
		}
	} else {
		for _, pos := range relatedConstOperandList { //deduplication
			if pos.callInstrPos == relatedC.callInstrPos && pos.argIndex == relatedC.argIndex {
				return
			}
		}
	}
	if debugMode {
		printDebugInfo("-----------[ok]Reach to Arg const :" + relatedC.constValue)
	}
	relatedConstOperandList = append(relatedConstOperandList, relatedC)
}

func analyzeArgSourceInPCG(pcgS *PartialCGStruct, callee *CallInstInfo, argIndex int) ([]metainfo.VariableConstSourceInfo, bool, bool, bool) {
	//writeTestCase(testCase)
	relatedConstOperandList = relatedConstOperandList[:0]
	allConst := initTheConstVarsOfCG(pcgS, false) //初始化testCase中的所有常量信息
	if allConst != nil {
		AllConstsOfTestCase = allConst
	}
	if debugMode {
		printDebugInfo("----------[-]Start find arg source")
	}
	for _, functionOfConstMap := range allConstOperandsOfTestCasePCGMap[pcgS.TestCaseCG.Root.Func] {
		for _, constV := range ConstOperandsOfFunctionMap[functionOfConstMap] {
			canTaintToCallee := false //找能taint到callee的常量
			for _, tmpFn := range constV.propagatedCallees {
				if tmpFn == callee.Callee {
					canTaintToCallee = true
					if debugMode {
						printDebugInfo("-----------[?]Taint: Able to reach to callee const: " + constV.constValue)
					}
					break
				}
			}

			if canTaintToCallee {
				needJudgeArg := callee.CallInstr.Call.Args[argIndex]
				/*if MIPtr, ok := needJudgeArg.(*ssa.MakeInterface); ok { //IF Arg is from MakeInterface
					needJudgeArg = MIPtr.X
				}*/
				if constV.constUseType == metainfo.InCall &&
					constV.constUsedInstr.Pos() == callee.CallInstr.Pos() {
					addRelatedConstOperand(constV, needJudgeArg)
					continue
				}
				for _, tNode := range constV.allTaintResults {
					if reflect.TypeOf(tNode) != reflect.TypeOf(needJudgeArg) {
						continue
					}
					switch tNode.(type) {
					case *ssa.Alloc:
						if tNode.(*ssa.Alloc).Pos() == needJudgeArg.(*ssa.Alloc).Pos() &&
							tNode.(*ssa.Alloc).Name() == needJudgeArg.(*ssa.Alloc).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Field:
						if tNode.(*ssa.Field).Pos() == needJudgeArg.(*ssa.Field).Pos() &&
							tNode.(*ssa.Field).Name() == needJudgeArg.(*ssa.Field).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.FieldAddr:
						if tNode.(*ssa.FieldAddr).Pos() == needJudgeArg.(*ssa.FieldAddr).Pos() &&
							tNode.(*ssa.FieldAddr).Name() == needJudgeArg.(*ssa.FieldAddr).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Index:
						if tNode.(*ssa.Index).Pos() == needJudgeArg.(*ssa.Index).Pos() &&
							tNode.(*ssa.Index).Name() == needJudgeArg.(*ssa.Index).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Lookup:
						if tNode.(*ssa.Lookup).Pos() == needJudgeArg.(*ssa.Lookup).Pos() &&
							tNode.(*ssa.Lookup).Name() == needJudgeArg.(*ssa.Lookup).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.IndexAddr:
						if tNode.(*ssa.IndexAddr).Pos() == needJudgeArg.(*ssa.IndexAddr).Pos() &&
							tNode.(*ssa.IndexAddr).Name() == needJudgeArg.(*ssa.IndexAddr).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Slice:
						if tNode.(*ssa.Slice).Pos() == needJudgeArg.(*ssa.Slice).Pos() &&
							tNode.(*ssa.Slice).Name() == needJudgeArg.(*ssa.Slice).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.BinOp:
						if tNode.(*ssa.BinOp).Pos() == needJudgeArg.(*ssa.BinOp).Pos() &&
							tNode.(*ssa.BinOp).Name() == needJudgeArg.(*ssa.BinOp).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.ChangeInterface:
						if tNode.(*ssa.ChangeInterface).Pos() == needJudgeArg.(*ssa.ChangeInterface).Pos() &&
							tNode.(*ssa.ChangeInterface).Name() == needJudgeArg.(*ssa.ChangeInterface).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.ChangeType:
						if tNode.(*ssa.ChangeType).Pos() == needJudgeArg.(*ssa.ChangeType).Pos() &&
							tNode.(*ssa.ChangeType).Name() == needJudgeArg.(*ssa.ChangeType).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Convert:
						if tNode.(*ssa.Convert).Pos() == needJudgeArg.(*ssa.Convert).Pos() &&
							tNode.(*ssa.Convert).Name() == needJudgeArg.(*ssa.Convert).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Extract:
						if tNode.(*ssa.Extract).Pos() == needJudgeArg.(*ssa.Extract).Pos() &&
							tNode.(*ssa.Extract).Name() == needJudgeArg.(*ssa.Extract).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.MakeChan:
						if tNode.(*ssa.MakeChan).Pos() == needJudgeArg.(*ssa.MakeChan).Pos() &&
							tNode.(*ssa.MakeChan).Name() == needJudgeArg.(*ssa.MakeChan).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.MakeMap:
						if tNode.(*ssa.MakeMap).Pos() == needJudgeArg.(*ssa.MakeMap).Pos() &&
							tNode.(*ssa.MakeMap).Name() == needJudgeArg.(*ssa.MakeMap).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.MakeSlice:
						if tNode.(*ssa.MakeSlice).Pos() == needJudgeArg.(*ssa.MakeSlice).Pos() &&
							tNode.(*ssa.MakeSlice).Name() == needJudgeArg.(*ssa.MakeSlice).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Phi:
						if tNode.(*ssa.Phi).Pos() == needJudgeArg.(*ssa.Phi).Pos() &&
							tNode.(*ssa.Phi).Name() == needJudgeArg.(*ssa.Phi).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Range:
						if tNode.(*ssa.Range).Pos() == needJudgeArg.(*ssa.Range).Pos() &&
							tNode.(*ssa.Range).Name() == needJudgeArg.(*ssa.Range).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.MakeInterface:
						if tNode.(*ssa.MakeInterface).Pos() == needJudgeArg.(*ssa.MakeInterface).Pos() &&
							tNode.(*ssa.MakeInterface).Name() == needJudgeArg.(*ssa.MakeInterface).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.TypeAssert:
						if tNode.(*ssa.TypeAssert).Pos() == needJudgeArg.(*ssa.TypeAssert).Pos() &&
							tNode.(*ssa.TypeAssert).Name() == needJudgeArg.(*ssa.TypeAssert).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.UnOp:
						if tNode.(*ssa.UnOp).Pos() == needJudgeArg.(*ssa.UnOp).Pos() &&
							tNode.(*ssa.UnOp).Name() == needJudgeArg.(*ssa.UnOp).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					case *ssa.Call:
						if tNode.(*ssa.Call).Pos() == needJudgeArg.(*ssa.Call).Pos() &&
							tNode.(*ssa.Call).Name() == needJudgeArg.(*ssa.Call).Name() {
							addRelatedConstOperand(constV, needJudgeArg)
						}
					default:
					}
				}
			}
		}
	}

	argMayRelatedToFileName := false
	argMayRelatedToRegex := false
	argMayRelatedToIpAddress := false
	var res []metainfo.VariableConstSourceInfo
	for _, relatedC := range relatedConstOperandList {
		if relatedC.canPropagateToFileName {
			argMayRelatedToFileName = true
		} else if relatedC.canPropagateToRegexPattern {
			argMayRelatedToRegex = true
		} else if relatedC.canPropagateToIpAddress {
			argMayRelatedToIpAddress = true
		}
		//printDebugRelated(testCase, testCase.Pos(), relatedC.constPos)

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
		res = append(res, metaI)
	}
	if doStatistics {
		if argMayRelatedToFileName {
			statisticRecode.FileArgNum++
		}
		if argMayRelatedToRegex {
			statisticRecode.RegexArgNum++
		}
		if argMayRelatedToIpAddress {
			statisticRecode.IpArgNum++
		}
	}
	return res, argMayRelatedToFileName, argMayRelatedToRegex, argMayRelatedToIpAddress
}

func analyzeFuncRetTaintByUsedInstr(usedInstr ssa.Instruction) ([]ssa.Node, bool) { //Store IndexAddr Slice BinOp
	onceFields = make(map[types.Type][]int) //reset fields record
	prog := propagation.Propagation{}
	switch usedInstr.(type) {
	case *ssa.Store:
		storePtr := usedInstr.(*ssa.Store)
		prog = propagation.Taint(storePtr)
		_, okFA := storePtr.Addr.(*ssa.FieldAddr)
		_, okIA := storePtr.Addr.(*ssa.IndexAddr)
		if okFA || okIA {
			sourceInst := *getSourceAllocOrGlobalOrMake(&storePtr.Addr) //over taint
			if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
				prog, onceFields = propagation.TaintWithField(allocInstr, onceFields)
			} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
				prog = propagation.Taint(globalPtr)
			}
		}
	case *ssa.Convert:
		storeOfConvert := findStoreOfInstr(usedInstr.(*ssa.Convert))
		if storeOfConvert != nil {
			prog = propagation.Taint(storeOfConvert)
		} else {
			prog = propagation.Taint(usedInstr.(*ssa.Convert))
		}
	case *ssa.IndexAddr:
		indexAPtr := usedInstr.(*ssa.IndexAddr)
		prog = propagation.Taint(indexAPtr)
		sourceInst := *getSourceAllocOrGlobalOrMake(&indexAPtr.X) //over taint
		if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
			prog = propagation.Taint(allocInstr)
		} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
			prog = propagation.Taint(globalPtr)
		}
	case *ssa.Slice:
		slicePtr := usedInstr.(*ssa.Slice)
		prog = propagation.Taint(slicePtr)
	case *ssa.BinOp:
		storeOfBinOp := findStoreOfInstr(usedInstr.(*ssa.BinOp))
		if storeOfBinOp != nil {
			prog = propagation.Taint(storeOfBinOp)
		} else {
			binOpPtr := usedInstr.(*ssa.BinOp)
			prog = propagation.Taint(binOpPtr)
		}
	case *ssa.MapUpdate:
		mapUpdatePtr := usedInstr.(*ssa.MapUpdate)
		sourceInst := *getMapDefInstr(mapUpdatePtr) //over taint
		if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
			prog = propagation.Taint(allocInstr)
		} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
			prog = propagation.Taint(globalPtr)
		}
	case *ssa.Call:
		callPtr := usedInstr.(*ssa.Call)
		prog = propagation.Taint(callPtr)
	}

	taintedNodes := prog.GetTaintedNodes() //TODO:如果需要增加污点传播逻辑，也许到这里增加，taint到什么类型的node时增加taint
	for _, tNode := range taintedNodes {
		if _, toReturnOk := tNode.(*ssa.Return); toReturnOk {
			return taintedNodes, true
		}
	}
	return taintedNodes, false
}

func analyzeFuncRetTaintByUsedInstrPCG(pcg *callgraph.Graph, usedInstr ssa.Instruction, callSite *ssa.Call) ([]ssa.Node, bool) { //Store IndexAddr Slice BinOp
	onceFields = make(map[types.Type][]int) //reset fields record
	prog := propagation.Propagation{}
	switch usedInstr.(type) {
	case *ssa.Store:
		storePtr := usedInstr.(*ssa.Store)
		prog = propagation.TaintInPCG(storePtr, pcg, callSite)
		_, okFA := storePtr.Addr.(*ssa.FieldAddr)
		_, okIA := storePtr.Addr.(*ssa.IndexAddr)
		if okFA || okIA {
			sourceInst := *getSourceAllocOrGlobalOrMake(&storePtr.Addr) //over taint
			if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
				prog, onceFields = propagation.TaintWithFieldInPCG(allocInstr, onceFields, pcg, callSite)
			} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
				prog = propagation.TaintInPCG(globalPtr, pcg, callSite)
			}
		}
	case *ssa.Convert:
		storeOfConvert := findStoreOfInstr(usedInstr.(*ssa.Convert))
		if storeOfConvert != nil {
			prog = propagation.TaintInPCG(storeOfConvert, pcg, callSite)
		} else {
			prog = propagation.TaintInPCG(usedInstr.(*ssa.Convert), pcg, callSite)
		}
	case *ssa.IndexAddr:
		indexAPtr := usedInstr.(*ssa.IndexAddr)
		prog = propagation.TaintInPCG(indexAPtr, pcg, callSite)
		sourceInst := *getSourceAllocOrGlobalOrMake(&indexAPtr.X) //over taint
		if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
			prog = propagation.TaintInPCG(allocInstr, pcg, callSite)
		} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
			prog = propagation.TaintInPCG(globalPtr, pcg, callSite)
		}
	case *ssa.Slice:
		slicePtr := usedInstr.(*ssa.Slice)
		prog = propagation.TaintInPCG(slicePtr, pcg, callSite)
	case *ssa.BinOp:
		storeOfBinOp := findStoreOfInstr(usedInstr.(*ssa.BinOp))
		if storeOfBinOp != nil {
			prog = propagation.TaintInPCG(storeOfBinOp, pcg, callSite)
		} else {
			binOpPtr := usedInstr.(*ssa.BinOp)
			prog = propagation.TaintInPCG(binOpPtr, pcg, callSite)
		}
	case *ssa.MapUpdate:
		mapUpdatePtr := usedInstr.(*ssa.MapUpdate)
		sourceInst := *getMapDefInstr(mapUpdatePtr) //over taint
		if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
			prog = propagation.TaintInPCG(allocInstr, pcg, callSite)
		} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
			prog = propagation.TaintInPCG(globalPtr, pcg, callSite)
		}
	}

	taintedNodes := prog.GetTaintedNodes() //TODO:如果需要增加污点传播逻辑，也许到这里增加，taint到什么类型的node时增加taint
	for _, tNode := range taintedNodes {
		if _, toReturnOk := tNode.(*ssa.Return); toReturnOk {
			return taintedNodes, true
		}
	}
	return taintedNodes, false
}

func analyzeFunRetUse(callInstr *ssa.Call) []ssa.Instruction {
	usedInstr := *callInstr.Referrers()
	fixedUsedInstr := *callInstr.Referrers()

	for _, instr := range usedInstr {
		if extPtr, toExtOk := instr.(*ssa.Extract); toExtOk {
			fixedUsedInstr = append(fixedUsedInstr, *extPtr.Referrers()...)
		}
	}

	return fixedUsedInstr
}

func deduplicationNodeAppend(nodeArray []ssa.Node, appendNodeArray []ssa.Node) []ssa.Node {
	for _, appendNode := range appendNodeArray {

		haveRecorded := false
		for _, originNode := range nodeArray {
			if originNode == appendNode {
				haveRecorded = true
				break
			}
		}
		if !haveRecorded {
			nodeArray = append(nodeArray, appendNode)
		}
	}
	return nodeArray
}

/*todo: 先disable new function，未来需要再分析
const depthMax = 4

func analyzeFuncBodyConst(callInst *ssa.Call, depth int) (isFileRelatedFunction bool) { //先递归再分析const,自底向上
    if debugMode {
        fmt.Println("----------[FuncBodyAnalysis]depth: ", depth)
    }
    calledFunc := callInst.Call.StaticCallee()              //在之前已经保证能分析function Body了
    isFRF := initTheInternalFuncTaintMap(calledFunc, false) //看被调用函数内是否有能reach return的嵌套调用, 同时如果此函数返回值与文件相关，直接放弃分析
    if isFRF {
        //todo:这里判断了FRF的都可以更新File Related List
        relatedConstOperandList = relatedConstOperandList[:0]
        return true
    }
    if depth != depthMax {
        for _, funcTaintI := range functionInternalFuncTaintMap[calledFunc] {
            if funcTaintI.callInstInfo.CallInstr.Call.StaticCallee() == calledFunc { //prevent direct recursion
                continue
            }
            if funcTaintI.canPropagateToReturn {
                if debugMode {
                    fmt.Println("----------[?]Can reach to return call: ", funcTaintI.callInstInfo.CallInstr.Call.String())
                }
                if funcTaintI.callInstInfo.CallInstr.Call.StaticCallee() != nil {
                    isFRFr := analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, depth+1) //嵌套分析下一层，深度递归
                    if isFRFr {
                        return true //callee既能reach return又是FRF，直接return，会停止此new函数的分析+递归分析
                    }
                }
                for idx, arg := range funcTaintI.callInstInfo.CallInstr.Call.Args { //看嵌套调用的函数有没有const参数
                    if constPtr, toConstOk := arg.(*ssa.Const); toConstOk {

                        constStruct := &constLocation{constSelf: constPtr,
                            constPos:        token.NoPos, //Arg const no pos
                            constFile:       trimFilePathPrefix(calledFunc.Prog.Fset.File(funcTaintI.callInstInfo.CallInstr.Pos()).Name()),
                            constType:       constPtr.Type().String(),
                            constValue:      constPtr.String(),
                            constUseType:    metainfo.InCall,
                            constUsedInstr:  funcTaintI.callInstInfo.CallInstr,
                            inWhichFunction: calledFunc,

                            callInstrPos: funcTaintI.callInstInfo.CallInstr.Pos(),
                            argIndex:     idx,
                        }
                        addRelatedConstOperand(constStruct, nil)
                    }
                }
            }
        }
    } else {
        initTheConstVarsOfFunctionInPCG(calledFunc, calledFunc.Signature.Recv() == nil)
        for _, constV := range allConstOperandsOfTestCaseMap[calledFunc] {
            if constV.canPropagateToReturn && !constV.canPropagateToFileName {
                if debugMode {
                    fmt.Println("----------[ok]Taint: Able to taint return Const in newFunc: ", constV.constValue)
                }
                addRelatedConstOperand(constV, nil)
            }
        }
    }
    return false
}
*/
/*
func analyzeArgFuncSource(testCase *ssa.Function, callee *CallInstInfo, argIndex int) []metainfo.VariableConstSourceInfo {
    //writeTestCase(testCase)
    relatedConstOperandList = relatedConstOperandList[:0]
    initTheInternalFuncTaintMap(testCase, false)
    for _, funcTaintI := range functionInternalFuncTaintMap[testCase] {
        canTaintToCallee := false //找能taint到callee的func
        for _, taintedCall := range funcTaintI.taintTo {
            if taintedCall.CallInstr.Name() == callee.CallInstr.Name() { //这里只是taint call指令不是function指针，用寄存器来判断
                canTaintToCallee = true
                if debugMode {
                    fmt.Println("----------[?]Taint: Able to taint callee func: ", funcTaintI.callInstInfo.CallInstr.Call.StaticCallee().String())
                }
                break
            }
        }

        if canTaintToCallee {
            needJudgeArg := callee.CallInstr.Call.Args[argIndex]
            for _, tNode := range funcTaintI.allTaintResults {
                if reflect.TypeOf(tNode) != reflect.TypeOf(needJudgeArg) {
                    continue
                }
                switch tNode.(type) {
                case *ssa.Alloc:
                    if tNode.(*ssa.Alloc).Name() == needJudgeArg.(*ssa.Alloc).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Field:
                    if tNode.(*ssa.Field).Name() == needJudgeArg.(*ssa.Field).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.FieldAddr:
                    if tNode.(*ssa.FieldAddr).Name() == needJudgeArg.(*ssa.FieldAddr).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Index:
                    if tNode.(*ssa.Index).Name() == needJudgeArg.(*ssa.Index).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Lookup:
                    if tNode.(*ssa.Lookup).Name() == needJudgeArg.(*ssa.Lookup).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.IndexAddr:
                    if tNode.(*ssa.IndexAddr).Name() == needJudgeArg.(*ssa.IndexAddr).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Slice:
                    if tNode.(*ssa.Slice).Name() == needJudgeArg.(*ssa.Slice).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.BinOp:
                    if tNode.(*ssa.BinOp).Name() == needJudgeArg.(*ssa.BinOp).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.ChangeInterface:
                    if tNode.(*ssa.ChangeInterface).Name() == needJudgeArg.(*ssa.ChangeInterface).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.ChangeType:
                    if tNode.(*ssa.ChangeType).Name() == needJudgeArg.(*ssa.ChangeType).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Convert:
                    if tNode.(*ssa.Convert).Name() == needJudgeArg.(*ssa.Convert).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Extract:
                    if tNode.(*ssa.Extract).Name() == needJudgeArg.(*ssa.Extract).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.MakeChan:
                    if tNode.(*ssa.MakeChan).Name() == needJudgeArg.(*ssa.MakeChan).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.MakeMap:
                    if tNode.(*ssa.MakeMap).Name() == needJudgeArg.(*ssa.MakeMap).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.MakeSlice:
                    if tNode.(*ssa.MakeSlice).Name() == needJudgeArg.(*ssa.MakeSlice).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Phi:
                    if tNode.(*ssa.Phi).Name() == needJudgeArg.(*ssa.Phi).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.Range:
                    if tNode.(*ssa.Range).Name() == needJudgeArg.(*ssa.Range).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.MakeInterface:
                    if tNode.(*ssa.MakeInterface).Name() == needJudgeArg.(*ssa.MakeInterface).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.TypeAssert:
                    if tNode.(*ssa.TypeAssert).Name() == needJudgeArg.(*ssa.TypeAssert).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                case *ssa.UnOp:
                    if tNode.(*ssa.UnOp).Name() == needJudgeArg.(*ssa.UnOp).Name() {
                        analyzeFuncBodyConst(funcTaintI.callInstInfo.CallInstr, 1)
                    }
                default:
                }
            }
        }
    }
    var res []metainfo.VariableConstSourceInfo
    for _, relatedC := range relatedConstOperandList {
        //printDebugRelated(testCase, testCase.Pos(), relatedC.constPos)
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
                IsNewFunc:           true,
                InWhichFunc:         relatedC.inWhichFunction.String(),
                IsImmediateVariable: true,
                ArgIndex:            relatedC.argIndex,
                CallLine:            testCase.Prog.Fset.Position(relatedC.callInstrPos).Line,
                CallColum:           testCase.Prog.Fset.Position(relatedC.callInstrPos).Column,
                CallPos:             int(relatedC.callInstrPos),
            }
        } else {
            functionInterOffset := relatedC.constPos - relatedC.inWhichFunction.Pos()
            metaI = metainfo.VariableConstSourceInfo{
                VariableSrcPath:    relatedC.constFile,
                SourceLine:         testCase.Prog.Fset.Position(relatedC.constPos).Line,
                SourceColumn:       testCase.Prog.Fset.Position(relatedC.constPos).Column,
                ConstValue:         relatedC.constValue,
                ConstType:          parameterutils.SwitchType(relatedC.constType),
                ConstUseType:       relatedC.constUseType,
                IsNewFunc:          true,
                InWhichFunc:        relatedC.inWhichFunction.String(),
                FuncInternalOffset: int(functionInterOffset),
            }
        }
        res = append(res, metaI)
    }
    return res
}
*/

/*
func analyzeFuncInternalSourceForStruct(PCG *PartialCGStruct, callee *CallInstInfo, argIndex int) []metainfo.VariableConstSourceInfo {
    relatedConstOperandList = relatedConstOperandList[:0]
    initTheConstVarsOfFunctionInPCG(callee.Callee, callee.IsMethod)
    for _, constV := range allConstOperandsOfTestCaseMap[callee.Callee] {
        if constV.canReachToMethodSelf && !constV.canPropagateToFileName {
            addRelatedConstOperand(constV, callee.CallInstr.Call.Args[argIndex])
        }
    }

    var res []metainfo.VariableConstSourceInfo
    for _, relatedC := range relatedConstOperandList {
        functionInterOffset := relatedC.constPos - relatedC.inWhichFunction.Pos()
        res = append(res, metainfo.VariableConstSourceInfo{
            VariableSrcPath:    relatedC.constFile,
            SourceLine:         testCase.Prog.Fset.Position(relatedC.constPos).Line,
            SourceColumn:       testCase.Prog.Fset.Position(relatedC.constPos).Column,
            ConstValue:         relatedC.constValue,
            ConstType:          parameterutils.SwitchType(relatedC.constType),
            ConstUseType:       relatedC.constUseType,
            IsNewFunc:          false,
            InWhichFunc:        relatedC.inWhichFunction.String(),
            FuncInternalOffset: int(functionInterOffset),
        })
    }
    return res
}
*/

func getArrayIndexIfGlobalIsMapped(fn *ssa.Function, global *ssa.Global) (int, bool) {
	for idx, globalV := range GlobalsOfFunctionMap[fn] {
		if globalV.globalSelf == global {
			return idx, true
		}
	}
	return -1, false
}

func analyzeGlobalTaint(globalV *globalLocation, analyzePropagatableCallee bool, analyzePropagatedReturn bool, pcgS *PartialCGStruct) { //Store UnOp BinOp
	cg := pcgS.TestCaseCG
	callSite := globalV.PCGCallerCallSite
	onceFields = make(map[types.Type][]int)              //reset fields record
	for _, usedInstr := range globalV.globalUsedInstrs { //目前处理global的使用指令只有这几类
		prog := propagation.Propagation{}
		switch usedInstr.(type) {
		case *ssa.Store:
			storePtr := usedInstr.(*ssa.Store)
			prog = propagation.TaintInPCG(storePtr, cg, globalV.PCGCallerCallSite)
			_, okFA := storePtr.Addr.(*ssa.FieldAddr)
			_, okIA := storePtr.Addr.(*ssa.IndexAddr)
			if okFA || okIA {
				sourceInst := *getSourceAllocOrGlobalOrMake(&storePtr.Addr) //over taint
				if allocInstr, ok := sourceInst.(*ssa.Alloc); ok {
					prog, onceFields = propagation.TaintWithFieldInPCG(allocInstr, onceFields, pcgS.TestCaseCG, callSite)
				} else if globalPtr, ok := sourceInst.(*ssa.Global); ok {
					prog = propagation.TaintInPCG(globalPtr, cg, globalV.PCGCallerCallSite)
				}
			}
		case *ssa.BinOp:
			binOpPtr := usedInstr.(*ssa.BinOp)
			prog = propagation.TaintInPCG(binOpPtr, cg, globalV.PCGCallerCallSite)
		case *ssa.UnOp:
			UnOpPtr := usedInstr.(*ssa.UnOp)
			prog = propagation.TaintInPCG(UnOpPtr, cg, globalV.PCGCallerCallSite)
		}

		onceTaintedNodes := prog.GetTaintedNodes()
		if analyzePropagatableCallee {
			for _, tNode := range onceTaintedNodes {
				if callPtr, toCallOk := tNode.(*ssa.Call); toCallOk {
					callee := callPtr.Call.StaticCallee()
					if callee != nil {
						globalV.reachableCallee = append(globalV.reachableCallee, callee)
					}
				}
			}
		}
		if analyzePropagatedReturn {
			for _, tNode := range prog.GetTaintedNodes() {
				if _, toReturnOk := tNode.(*ssa.Return); toReturnOk {
					globalV.canReachToReturn = true
					break
				}
			}
		}
		globalV.allTaintResults = append(globalV.allTaintResults, onceTaintedNodes...)
	}
}

func initTheGlobalsFunctionUsedInPCG(fn *ssa.Function, analyzePropagatableCallee bool, analyzePropagatedReturn bool, pcgS *PartialCGStruct, callSite *ssa.Call) {
	if _, ok := GlobalsOfFunctionMap[fn]; ok {
		return
	} else {
		if debugMode {
			printDebugInfo("-----------Init Used Globals of function: " + fn.String())
		}
		if GlobalsOfFunctionMap == nil {
			GlobalsOfFunctionMap = make(map[*ssa.Function][]*globalLocation)
		}
		GlobalsOfFunctionMap[fn] = make([]*globalLocation, 0)
		allCallees := allGlobalsOfTestCasePCGMap[pcgS.TestCaseCG.Root.Func]
		allGlobalsOfTestCasePCGMap[pcgS.TestCaseCG.Root.Func] = append(allCallees, fn)
	}
	for _, block := range fn.Blocks { //先找出全部的global operand
		for _, instr := range block.Instrs {
			var operandList []*ssa.Value
			operandList = instr.Operands(operandList)
			for _, operandPtr := range operandList { //收集所有global operand
				operand := *operandPtr
				if globalPtr, toGlobalOk := operand.(*ssa.Global); toGlobalOk {
					switch instr.(type) { //global被用在不同的指令中，可能需要做不同的处理,目前只处理store UnOp BinOp
					case *ssa.Store, *ssa.UnOp, *ssa.BinOp:

						if idx, mapped := getArrayIndexIfGlobalIsMapped(fn, globalPtr); mapped { //这个global在TestCase中已经出现过
							GlobalsOfFunctionMap[fn][idx].globalUsedInstrs =
								append(GlobalsOfFunctionMap[fn][idx].globalUsedInstrs, instr)
						} else { //这个global没有出现过
							globalLocPtr := &globalLocation{
								globalSelf:        globalPtr,
								globalPos:         globalPtr.Pos(),
								globalFile:        trimFilePathPrefix(fn.Prog.Fset.File(globalPtr.Pos()).Name()),
								globalType:        globalPtr.Type().String(),
								globalUsedInstrs:  []ssa.Instruction{instr},
								inWhichFunction:   fn,
								inWhichPCGS:       pcgS,
								PCGCallerCallSite: callSite,
							}
							GlobalsOfFunctionMap[fn] = append(GlobalsOfFunctionMap[fn], globalLocPtr)
						}
					}

				}
			}
		}
	}

	for _, globalV := range GlobalsOfFunctionMap[fn] {
		analyzeGlobalTaint(globalV, analyzePropagatableCallee, analyzePropagatedReturn, pcgS)
	}
	if debugMode {
		for _, globalV := range GlobalsOfFunctionMap[fn] {
			printDebugInfo("------------[ok]Global Name: " + globalV.globalSelf.String())
		}
	}
}

func initTheGlobalsPCGUsed(pcgS *PartialCGStruct, analyzePropagatableCallee bool, analyzePropagatedReturn bool) {
	cg := pcgS.TestCaseCG
	if _, ok := allGlobalsOfTestCasePCGMap[cg.Root.Func]; ok {
		return
	} else {
		if debugMode {
			printDebugInfo("----------Init Global Variables of CG: " + cg.Root.Func.String())
		}
		if allGlobalsOfTestCasePCGMap == nil {
			allGlobalsOfTestCasePCGMap = make(map[*ssa.Function][]*ssa.Function)
		}
		allGlobalsOfTestCasePCGMap[cg.Root.Func] = make([]*ssa.Function, 0)
	}

	initTheGlobalsFunctionUsedInPCG(cg.Root.Func, analyzePropagatableCallee, analyzePropagatedReturn, pcgS, nil) //先初始化TestCase内的常量
	allGlobalsOfTestCasePCGMap[cg.Root.Func] = append(allGlobalsOfTestCasePCGMap[cg.Root.Func], cg.Root.Func)
	callgraph.GraphVisitEdges(cg, func(e *callgraph.Edge) error {
		initTheGlobalsFunctionUsedInPCG(e.Callee.Func, analyzePropagatableCallee, analyzePropagatedReturn, pcgS, e.Site.Value()) //todo:这里只给了一个callSite，可能会有多个callSite+callpath
		allGlobalsOfTestCasePCGMap[cg.Root.Func] = append(allGlobalsOfTestCasePCGMap[cg.Root.Func], e.Callee.Func)
		return nil
	})

}

func addRelatedGlobal(relatedG *globalLocation) {
	for _, globalV := range relatedGlobalList { //deduplication
		if globalV.globalPos == relatedG.globalPos {
			return
		}
	}
	if debugMode {
		printDebugInfo("----------[ok]Reach to Arg global :" + relatedG.globalSelf.Name())
	}
	relatedGlobalList = append(relatedGlobalList, relatedG)
}

func analyzeArgGlobalSource(pcgS *PartialCGStruct, callee *CallInstInfo, argIndex int) []metainfo.VariableGlobalSourceInfo {
	//writeTestCase(testCase)
	relatedGlobalList = relatedGlobalList[:0]
	initTheGlobalsPCGUsed(pcgS, true, false)
	for _, functionOfGlobalMap := range allConstOperandsOfTestCasePCGMap[pcgS.TestCaseCG.Root.Func] {
		for _, globalV := range GlobalsOfFunctionMap[functionOfGlobalMap] {
			canTaintToCallee := false //找能taint到callee的global
			for _, taintedCall := range globalV.reachableCallee {
				if taintedCall == callee.Callee {
					canTaintToCallee = true
					if debugMode {
						printDebugInfo("----------[?]Taint: Able to taint callee global: " + globalV.globalSelf.String())
					}
					break
				}
			}

			if canTaintToCallee {
				needJudgeArg := callee.CallInstr.Call.Args[argIndex]
				for _, tNode := range globalV.allTaintResults {
					if reflect.TypeOf(tNode) != reflect.TypeOf(needJudgeArg) {
						continue
					}
					switch tNode.(type) {
					case *ssa.Alloc:
						if tNode.(*ssa.Alloc).Pos() == needJudgeArg.(*ssa.Alloc).Pos() &&
							tNode.(*ssa.Alloc).Name() == needJudgeArg.(*ssa.Alloc).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Field:
						if tNode.(*ssa.Field).Pos() == needJudgeArg.(*ssa.Field).Pos() &&
							tNode.(*ssa.Field).Name() == needJudgeArg.(*ssa.Field).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.FieldAddr:
						if tNode.(*ssa.FieldAddr).Pos() == needJudgeArg.(*ssa.FieldAddr).Pos() &&
							tNode.(*ssa.FieldAddr).Name() == needJudgeArg.(*ssa.FieldAddr).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Index:
						if tNode.(*ssa.Index).Pos() == needJudgeArg.(*ssa.Index).Pos() &&
							tNode.(*ssa.Index).Name() == needJudgeArg.(*ssa.Index).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Lookup:
						if tNode.(*ssa.Lookup).Pos() == needJudgeArg.(*ssa.Lookup).Pos() &&
							tNode.(*ssa.Lookup).Name() == needJudgeArg.(*ssa.Lookup).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.IndexAddr:
						if tNode.(*ssa.IndexAddr).Pos() == needJudgeArg.(*ssa.IndexAddr).Pos() &&
							tNode.(*ssa.IndexAddr).Name() == needJudgeArg.(*ssa.IndexAddr).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Slice:
						if tNode.(*ssa.Slice).Pos() == needJudgeArg.(*ssa.Slice).Pos() &&
							tNode.(*ssa.Slice).Name() == needJudgeArg.(*ssa.Slice).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.BinOp:
						if tNode.(*ssa.BinOp).Pos() == needJudgeArg.(*ssa.BinOp).Pos() &&
							tNode.(*ssa.BinOp).Name() == needJudgeArg.(*ssa.BinOp).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.ChangeInterface:
						if tNode.(*ssa.ChangeInterface).Pos() == needJudgeArg.(*ssa.ChangeInterface).Pos() &&
							tNode.(*ssa.ChangeInterface).Name() == needJudgeArg.(*ssa.ChangeInterface).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.ChangeType:
						if tNode.(*ssa.ChangeType).Pos() == needJudgeArg.(*ssa.ChangeType).Pos() &&
							tNode.(*ssa.ChangeType).Name() == needJudgeArg.(*ssa.ChangeType).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Convert:
						if tNode.(*ssa.Convert).Pos() == needJudgeArg.(*ssa.Convert).Pos() &&
							tNode.(*ssa.Convert).Name() == needJudgeArg.(*ssa.Convert).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Extract:
						if tNode.(*ssa.Extract).Pos() == needJudgeArg.(*ssa.Extract).Pos() &&
							tNode.(*ssa.Extract).Name() == needJudgeArg.(*ssa.Extract).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.MakeChan:
						if tNode.(*ssa.MakeChan).Pos() == needJudgeArg.(*ssa.MakeChan).Pos() &&
							tNode.(*ssa.MakeChan).Name() == needJudgeArg.(*ssa.MakeChan).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.MakeMap:
						if tNode.(*ssa.MakeMap).Pos() == needJudgeArg.(*ssa.MakeMap).Pos() &&
							tNode.(*ssa.MakeMap).Name() == needJudgeArg.(*ssa.MakeMap).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.MakeSlice:
						if tNode.(*ssa.MakeSlice).Pos() == needJudgeArg.(*ssa.MakeSlice).Pos() &&
							tNode.(*ssa.MakeSlice).Name() == needJudgeArg.(*ssa.MakeSlice).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Phi:
						if tNode.(*ssa.Phi).Pos() == needJudgeArg.(*ssa.Phi).Pos() &&
							tNode.(*ssa.Phi).Name() == needJudgeArg.(*ssa.Phi).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Range:
						if tNode.(*ssa.Range).Pos() == needJudgeArg.(*ssa.Range).Pos() &&
							tNode.(*ssa.Range).Name() == needJudgeArg.(*ssa.Range).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.MakeInterface:
						if tNode.(*ssa.MakeInterface).Pos() == needJudgeArg.(*ssa.MakeInterface).Pos() &&
							tNode.(*ssa.MakeInterface).Name() == needJudgeArg.(*ssa.MakeInterface).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.TypeAssert:
						if tNode.(*ssa.TypeAssert).Pos() == needJudgeArg.(*ssa.TypeAssert).Pos() &&
							tNode.(*ssa.TypeAssert).Name() == needJudgeArg.(*ssa.TypeAssert).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.UnOp:
						if tNode.(*ssa.UnOp).Pos() == needJudgeArg.(*ssa.UnOp).Pos() &&
							tNode.(*ssa.UnOp).Name() == needJudgeArg.(*ssa.UnOp).Name() {
							addRelatedGlobal(globalV)
						}
					case *ssa.Call:
						if tNode.(*ssa.Call).Pos() == needJudgeArg.(*ssa.Call).Pos() &&
							tNode.(*ssa.Call).Name() == needJudgeArg.(*ssa.Call).Name() {
							addRelatedGlobal(globalV)
						}
					default:
					}
				}
			}
		}
	}
	var res []metainfo.VariableGlobalSourceInfo
	for _, relatedG := range relatedGlobalList {
		//printDebugRelated(testCase, testCase.Pos(), relatedC.constPos)
		res = append(res, metainfo.VariableGlobalSourceInfo{
			GlobalSrcPath: relatedG.globalFile,
			SourceLine:    pcgS.TestCaseCG.Root.Func.Prog.Fset.Position(relatedG.globalPos).Line,
			SourceColumn:  pcgS.TestCaseCG.Root.Func.Prog.Fset.Position(relatedG.globalPos).Column,
			GlobalName:    relatedG.globalSelf.String(),
			GlobalType:    relatedG.globalType,
		})
	}
	return res
}

func printDebugRelated(fn *ssa.Function, funcPos token.Pos, constVPos token.Pos) {
	functionInterOffset := constVPos - funcPos
	funcLine := fn.Prog.Fset.Position(funcPos).Line
	funcColumn := fn.Prog.Fset.Position(funcPos).Column
	constLine := fn.Prog.Fset.Position(constVPos).Line
	constColumn := fn.Prog.Fset.Position(constVPos).Column
	printInfo := fmt.Sprintf("func line: %d, func column: %d\n", funcLine, funcColumn)
	printInfo += fmt.Sprintf("constV line: %d, constV column: %d\n", constLine, constColumn)
	printInfo += fmt.Sprintf("Internal offset: %d", functionInterOffset)
	fmt.Println(printInfo)
}

func writeTestCase(fn *ssa.Function) {
	fn.WriteTo(os.Stdout)
	fmt.Println("[!]Instr Type:")
	//print instr&type
	for _, block := range fn.Blocks {
		for _, inst := range block.Instrs {
			//inst.(*ssa.FieldAddr).X.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct).Field(Field)

			fmt.Println(inst)
			fmt.Println(reflect.TypeOf(inst), fn.Prog.Fset.Position(inst.Pos()).Line, fn.Prog.Fset.Position(inst.Pos()).Column, "[end]")
		}
	}

}
