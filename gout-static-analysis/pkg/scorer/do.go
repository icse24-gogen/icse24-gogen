package scorer

import (
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/propagation"
	//"xyz.asd.qwe/gout-static-analysis/pkg/pkgutils"
)

func scoringByTaintedInstructions(taintedInstructions []ssa.Node) int {
	result := 0
	for _, node := range taintedInstructions {
		switch node.(type) {
		//case *ssa.Store:
		//	result += 5
		case *ssa.Phi:
			result += 10
		case *ssa.If:
			result += 10
			//default:
			//	result += 1
		}
	}
	return result
}

type callSiteInfo struct {
	Callee          *ssa.Function
	TaintedArgument int //TODO: multiple tainted arguments
}

var knownNameMap map[string]bool

func collectTaintedFuntions(fn *ssa.Function, prop propagation.Propagation) []callSiteInfo {
	result := make([]callSiteInfo, 0)
	for _, b := range fn.Blocks {
		for instrIndex, instr := range b.Instrs {
			switch v := instr.(type) {
			case *ssa.Call:
				for argIdx, av := range v.Call.Args {
					switch av.(type) {
					case ssa.Instruction: //Arg may still be expressed by Instruction
						argNode := av.(ssa.Instruction)
						if _, ok := av.(*ssa.Slice); ok {
							//skip call of function whose parameters are slice
							continue
						}
						if prop.IsTainted(argNode.(ssa.Node)) {
							if v.Call.StaticCallee() != nil {
								if _, ok := knownNameMap[v.Call.StaticCallee().Name()]; !ok {
									result = append(result, callSiteInfo{Callee: v.Call.StaticCallee(), TaintedArgument: argIdx})
									knownNameMap[v.Call.StaticCallee().Name()] = true
								}
							}
						}
					case ssa.Value:
						argNode := av.(ssa.Node)
						if _, ok := av.(*ssa.Slice); ok {
							//skip call of function whose parameters are slice
							continue
						}
						if prop.IsTainted(argNode) {
							if v.Call.StaticCallee() != nil {
								if _, ok := knownNameMap[v.Call.StaticCallee().Name()]; !ok {
									result = append(result, callSiteInfo{Callee: v.Call.StaticCallee(), TaintedArgument: argIdx})
									knownNameMap[v.Call.StaticCallee().Name()] = true
								}
							}
						}
					}
				}
			//sth special for variable parameters
			case *ssa.Alloc:
				allocNode := instr.(ssa.Node)
				if strings.Contains(allocNode.String(), "varargs") {
					argStr := allocNode.String()
					leftBlanket := strings.Index(argStr, "[")
					rightBlanket := strings.Index(argStr, "]")
					indexStr := argStr[leftBlanket+1 : rightBlanket]
					argumentIdx, atoiErr := strconv.Atoi(indexStr)
					if atoiErr != nil {
						continue
						panic("Atoi error is not tolerantable")
					}

					if prop.IsTainted(v) {
						callsiteOffset := prop.InferArguementCallSite(instr, b.Instrs[instrIndex:])
						if instrIndex+callsiteOffset <= len(b.Instrs) { //TODO:may not a format string
							continue
						}
						callsite := b.Instrs[instrIndex+callsiteOffset]

						v := callsite.(*ssa.Call)
						callee := v.Call.StaticCallee()

						if v.Call.StaticCallee() != nil {
							if _, ok := knownNameMap[v.Call.StaticCallee().Name()]; !ok {
								result = append(result, callSiteInfo{Callee: callee, TaintedArgument: argumentIdx})
								knownNameMap[v.Call.StaticCallee().Name()] = true
							}
						}
					}
				}
			}
		}
	}
	return result
}

var gPackages *([]*ssa.Package)

/*
func recoverMissedFunction(fn *ssa.Function) *ssa.Function{//maybe useless
    defer func() {
        if err := recover(); err != nil {
			fmt.Println("sth wrong at ", fn)
        }
    }()
	pkg := fn.Package()
	var result *ssa.Function



	pkgs := pkgutils.LoadProjPackages([]string{pkg.Pkg.Path()})
	for _, pkg := range pkgs{
		if pkg != nil {
			for _, member := range pkg.Members {
				if member.Name() == fn.Name() {
					return pkg.Func(fn.Name())
				}
			}
		}
	}

	return result
}*/
func recoverMissedFunction(fn *ssa.Function) *ssa.Function { //maybe useless
	var result *ssa.Function
	for _, pkg := range *gPackages {
		if pkg != nil {
			for _, member := range pkg.Members {
				if member.Name() == fn.Name() {
					return pkg.Func(fn.Name())
				}
			}
		}
	}

	return result
}

func doScoreParam(fn *ssa.Function, param *ssa.Parameter) int {
	//generate map[function][]branch (map whose key is function and value is branches)
	//io.WriteString(os.Stderr, fmt.Sprintf("[+]scoring %s at %s\n", param.Name(), fn.Name()))
	result := make(map[*ssa.Function]([]ssa.Node), 0)
	knownNameMap = make(map[string]bool, 0)

	res := DirectCalleeInfo{}
	res.calleeSelf = fn
	//suppressedNodes := pass.ResultOf[suppression.Analyzer].(suppression.ResultType)
	//var curSource *source.Source

	funcProp2Score := func(fn *ssa.Function, prop propagation.Propagation) int {
		res := 0
		taintedInstructions := make([]ssa.Node, 0)
		taintedBranches := make([]ssa.Node, 0)
		taintedBranches = append(taintedBranches, prop.GetTaintedBranches(fn)...)
		taintedInstructions = append(taintedInstructions, prop.GetTaintedNodes()...)
		res += scoringByTaintedInstructions(taintedInstructions)
		return res
	}

	score := 0
	dfsStack := make([]callSiteInfo, 0)
	prop := propagation.Taint(param)
	funcProp2Score(fn, prop)
	taintedFunctions := collectTaintedFuntions(fn, prop)
	dfsStack = append(dfsStack, taintedFunctions...)

	for {
		if len(dfsStack) == 0 {
			break
		}
		//pop stack
		curFn := dfsStack[0].Callee
		paramIdx := dfsStack[0].TaintedArgument
		dfsStack = append(dfsStack[:0], dfsStack[1:]...)

		if curFn == nil || curFn.Params == nil || len(curFn.Params) <= paramIdx {
			if curFn != nil {
				emptyTaintedBranches := make([]ssa.Node, 0)
				result[curFn] = emptyTaintedBranches
				newFn := recoverMissedFunction(curFn)
				if newFn != nil {
					if newFn.Params != nil && paramIdx < len(newFn.Params) {
						curFn = newFn
					}
				} else {
					continue
				}

			} else {
				continue
			}
		}

		if len(curFn.Params) <= paramIdx { //wtf
			continue
		}
		curSource := curFn.Params[paramIdx]
		taintedBranches := make([]ssa.Node, 0)
		taintedInstructions := make([]ssa.Node, 0)
		prop = propagation.Taint(curSource)

		taintedBranches = append(taintedBranches, prop.GetTaintedBranches(curFn)...)
		taintedInstructions = append(taintedInstructions, prop.GetTaintedNodes()...)
		//prop.PrintTainted(pass)
		//if strings.Contains(curFn.Name(), "Valid") {
		//}

		result[curFn] = taintedBranches

		score += funcProp2Score(curFn, prop)

		taintedFunctions := collectTaintedFuntions(curFn, prop)
		dfsStack = append(taintedFunctions, dfsStack...)
	}
	//io.WriteString(os.Stderr, fmt.Sprintf("[+]score: %d\n", score))
	return score

}
