// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package levee

import (
	"encoding/json"
	"fmt"
	"go/ast"
//	"go/importer"
	"go/token"
	"go/types"
	"io/ioutil"
	"strconv"
	"strings"

	"xyz.asd.qwe/gout-static-analysis/internal/pkg/config"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/earpointer"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/fieldtags"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/propagation"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/source"
	//"xyz.asd.qwe/gout-static-analysis/internal/pkg/newsource"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/suppression"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/utils"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/utils/goutdefs"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/packages"
)

var Analyzer = &analysis.Analyzer{
	Name:  "levee",
	Run:   run,
	Flags: config.FlagSet,
	Doc:   "reports attempts to source data to sinks",
	Requires: []*analysis.Analyzer{
		fieldtags.Analyzer,
		source.Analyzer,
		suppression.Analyzer,
		earpointer.Analyzer,
	},
}


func run(pass *analysis.Pass) (interface{}, error) {
	conf, err := config.ReadConfig()
	if err != nil {
		return nil, err
	}
	if conf.UseEAR {
		return runEAR(pass, conf) // Use the EAR-pointer based taint analysis
	}
	return runNewPropagation(pass, conf) // Use the propagation based taint analysis
}

func runPropagation(pass *analysis.Pass, conf *config.Config) (interface{}, error) {
	funcSources := pass.ResultOf[source.Analyzer].(source.ResultType)
	taggedFields := pass.ResultOf[fieldtags.Analyzer].(fieldtags.ResultType)
	suppressedNodes := pass.ResultOf[suppression.Analyzer].(suppression.ResultType)

	for fn, sources := range funcSources {
		propagations := make(map[*source.Source]propagation.Propagation, len(sources))
		for _, s := range sources {
			propagations[s] = propagation.Taint(s.Node, conf, taggedFields)
		}

		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				switch v := instr.(type) {
				case *ssa.Call:
					// TODO(#317): use more advanced call graph.
					if callee := v.Call.StaticCallee(); callee != nil && conf.IsSink(utils.DecomposeFunction(callee)) {
						reportSourcesReachingSink(conf, pass, suppressedNodes, propagations, instr)
					}
				case *ssa.Panic:
					if conf.AllowPanicOnTaintedValues {
						continue
					}
					reportSourcesReachingSink(conf, pass, suppressedNodes, propagations, instr)
				}
			}
		}
	}

	return nil, nil
}
type callSiteInfo struct{
	Callee *ssa.Function
	TaintedArgument int//TODO: multiple tainted arguments
}

func collectTaintedFuntions(fn *ssa.Function, propagations map[*source.Source]propagation.Propagation)[]callSiteInfo{
	result := make([] callSiteInfo, 0)
	for _, b := range fn.Blocks {
		for instrIndex, instr := range b.Instrs {
			switch v := instr.(type) {
			case *ssa.Call:
				fmt.Println(v.Call.StaticCallee(), "called at", fn.Name())
				for argIdx, av := range v.Call.Args{
					switch av.(type){
					case ssa.Instruction:
						for _, prop := range propagations{
							argNode := av.(ssa.Instruction)
							if _, ok := av.(*ssa.Slice); ok {
								//skip call of function whose parameters are slice
								continue
							}
							if prop.IsTainted(argNode.(ssa.Node)){
								if v.Call.StaticCallee() != nil {
									if _, ok := knownNameMap[v.Call.StaticCallee().Name()]; !ok {
										result = append(result, callSiteInfo{Callee: v.Call.StaticCallee(), TaintedArgument: argIdx})
										knownNameMap[v.Call.StaticCallee().Name()] = true
									}
								}
							}
						}
					case ssa.Value:
						for _, prop := range propagations{
							argNode := av.(ssa.Node)
							if _, ok := av.(*ssa.Slice); ok {
								//skip call of function whose parameters are slice
								continue
							}
							if prop.IsTainted(argNode){
								if v.Call.StaticCallee() != nil {
									if _, ok := knownNameMap[v.Call.StaticCallee().Name()]; !ok {
										result = append(result, callSiteInfo{Callee: v.Call.StaticCallee(), TaintedArgument: argIdx})
										knownNameMap[v.Call.StaticCallee().Name()] = true
									}
								}
							}
						}
					}
				}
			//sth special for variable parameters
			case *ssa.Alloc:
				allocNode := instr.(ssa.Node)
				if strings.Contains(allocNode.String(), "varargs"){
					argStr := allocNode.String()
					leftBlanket := strings.Index(argStr, "[")
					rightBlanket := strings.Index(argStr, "]")
					indexStr := argStr[leftBlanket + 1: rightBlanket]
					argumentIdx, atoiErr := strconv.Atoi(indexStr)
					if atoiErr != nil{
						panic("Atoi error is not tolerantable")
					}
					
					for _, prop := range propagations{
						if prop.IsTainted(v) {
							callsiteOffset := prop.InferArguementCallSite(instr, b.Instrs[instrIndex:])
							callsite := b.Instrs[instrIndex + callsiteOffset]
							
							v := callsite.(*ssa.Call)
							callee := v.Call.StaticCallee();
							
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
	}
	return result
}

func writePropagationToFile(pass *analysis.Pass, result map[*ssa.Function]([]ssa.Node), filepath string){
	formatMap := make(map[string][]string, 0)
	
	for fn, branchList := range result{
		fnPosition := pass.Fset.Position(fn.Pos()).String()
		formatMap[fnPosition] = make([]string, 0)
		for _, branch := range branchList{
			formatMap[fnPosition] = append(formatMap[fnPosition], pass.Fset.Position(branch.Pos()).String())
		}
	}
	
	if len(filepath) == 0 {
		//fmt.Println(result)
	} else {
		s, err := json.Marshal(formatMap)
		if err == nil{
			ioutil.WriteFile(filepath, s, 0666)
		} else {
			panic("Marshal error is not telorent")
		}
		
	}

}
/*
func recoverMissedFunction(fn *ssa.Function) *ssa.Function{
	pkg := fn.Package()
	files := pkg.Files()
	fmt.Println(pkg, files)

	tmpPkg, _, err := ssautil.BuildPackage(
		&types.Config{Importer: importer.Default()}, pkg.Prog.Fset, pkg.Pkg, files, ssa.SanityCheckFunctions)
	if err != nil {
		panic("something wrong in RecoverMissedFunction")
	}
	
	result := tmpPkg.Func(fn.Name())
	return result
}
*/
func recoverMissedFunction(fn *ssa.Function) *ssa.Function{
	pkg := fn.Package()
	var result *ssa.Function
	
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Tests: true,
	}
	initial, err := packages.Load(cfg, pkg.Pkg.Path())
	if err != nil {
		panic(err)
	}
	//prog, pkgs := ssautil.AllPackages(initial, 0)
	prog, pkgs := ssautil.Packages(initial, 0)
	prog.Build()
	for _, pkg := range pkgs{
		for _, member := range pkg.Members{
			if member.Name() == fn.Name(){
				return pkg.Func(fn.Name())
			}
		}
	}
	if result == nil && fn.Name() == "Valid"{
		panic("not found")
	}
	
	return result
}

func scoringByTaintedInstructions(taintedInstructions []ssa.Node) int{
	result := 0
	for _, node := range taintedInstructions{
		switch node.(type){
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

func writeResult(md goutdefs.Metadata, filepath string){
	
	if len(filepath) == 0 {
		fmt.Println(md)
	} else {
		s, err := json.Marshal(md)
		if err == nil{
			ioutil.WriteFile(filepath, s, 0666)
		} else {
			panic("Marshal error is not telorent")
		}
		
	}

}

var knownNameMap = make(map[string]bool, 0)

func runNewPropagation(pass *analysis.Pass, conf *config.Config) (interface{}, error) {
	//generate map[function][]branch (map whose key is function and value is branches)
	result := make(map[*ssa.Function]([]ssa.Node), 0)
	score := 0
	funcSources := pass.ResultOf[source.Analyzer].(source.ResultType)
	taggedFields := pass.ResultOf[fieldtags.Analyzer].(fieldtags.ResultType)
	//suppressedNodes := pass.ResultOf[suppression.Analyzer].(suppression.ResultType)
	//var curSource *source.Source
	var rootFunctionName string
	dfsStack := make([] callSiteInfo, 0)

	funcProp2Score := func(fn *ssa.Function, propagations map[*source.Source]propagation.Propagation) int {
		res := 0
		taintedInstructions := make([]ssa.Node, 0)
		taintedBranches := make([]ssa.Node, 0)
		for _, prop := range propagations{
			taintedBranches = append(taintedBranches, prop.GetTaintedBranches(fn)...)
			taintedInstructions = append(taintedInstructions, prop.GetTaintedNodes()...)
			prop.PrintTainted(pass)
		}
		res += scoringByTaintedInstructions(taintedInstructions)
		return res
	}
	
	
	for fn, sources := range funcSources {//the root function is non-trival i.e. TestFunction 
		propagations := make(map[*source.Source]propagation.Propagation, len(sources))
		for _, s := range sources {
			propagations[s] = propagation.Taint(s.Node, conf, taggedFields)
		}
		rootFunctionName = fn.Name()

		fmt.Println("rootFunctionName", rootFunctionName)
		score += funcProp2Score(fn, propagations)
		//taintedInstructions := make([]ssa.Node, 0)
		//taintedBranches := make([]ssa.Node, 0)
		for _, prop := range propagations{
			prop.PrintTainted(pass)
		}
		//score += scoringByTaintedInstructions(taintedInstructions)

		taintedFunctions := collectTaintedFuntions(fn, propagations)
		dfsStack = append(dfsStack, taintedFunctions...)
		
	}
	for {
		if len(dfsStack) == 0{
			break
		}
		//pop stack
		curFn := dfsStack[0].Callee
		fmt.Println("traversing ", curFn)
		paramIdx := dfsStack[0].TaintedArgument
		dfsStack = append(dfsStack[:0], dfsStack[1:]...)
		
		if curFn == nil ||  curFn.Params == nil || len(curFn.Params) <= paramIdx{
			if curFn != nil{
				fmt.Println("[+]Recovering", curFn)
				emptyTaintedBranches := make([]ssa.Node, 0)
				result[curFn] = emptyTaintedBranches
				newFn := recoverMissedFunction(curFn)
				if newFn != nil{
					if newFn.Params != nil && paramIdx < len(newFn.Params){
						fmt.Println(newFn.Params)
						curFn = newFn
					}
				} else{
					fmt.Println("[-]Recover failed", curFn)
					continue
				}

			} else{
				continue
			}
		}

		curSource := &source.Source{Node:curFn.Params[paramIdx]}
		propagations := make(map[*source.Source]propagation.Propagation, 0)
		taintedBranches := make([]ssa.Node, 0)
		taintedInstructions := make([]ssa.Node, 0)
		propagations[curSource] = propagation.Taint(curSource.Node, conf, taggedFields)
		
		for _, prop := range propagations{
			taintedBranches = append(taintedBranches, prop.GetTaintedBranches(curFn)...)
			taintedInstructions = append(taintedInstructions, prop.GetTaintedNodes()...)
			prop.PrintTainted(pass)
		}
		//if strings.Contains(curFn.Name(), "Valid") {
		//}

		result[curFn] = taintedBranches

		score += funcProp2Score(curFn, propagations)
		
		taintedFunctions := collectTaintedFuntions(curFn, propagations)
		dfsStack = append(taintedFunctions, dfsStack...)
		
	}
	if len(result) != 0 {
		writePropagationToFile(pass, result, rootFunctionName + "_" + "output.json")
		writeResult(goutdefs.Metadata{rootFunctionName, score}, rootFunctionName + "_" + "score.json")
	}

	return nil, nil
}

// Use the EAR pointer analysis as the propagation engine
func runEAR(pass *analysis.Pass, conf *config.Config) (interface{}, error) {
	heap := pass.ResultOf[earpointer.Analyzer].(*earpointer.Partitions)
	if heap == nil {
		return nil, fmt.Errorf("no valid EAR partitions")
	}
	funcSources := pass.ResultOf[source.Analyzer].(source.ResultType)
	taggedFields := pass.ResultOf[fieldtags.Analyzer].(fieldtags.ResultType)
	suppressedNodes := pass.ResultOf[suppression.Analyzer].(suppression.ResultType)
	// Return whether a field is tainted.
	isTaintField := func(named *types.Named, index int) bool {
		if tt, ok := named.Underlying().(*types.Struct); ok {
			return conf.IsSourceField(utils.DecomposeField(named, index)) || taggedFields.IsSourceField(tt, index)
		}
		return false
	}
	for _, trace := range earpointer.SourcesToSinks(funcSources, isTaintField, heap, conf) {
		sink := trace.Sink
		if !isSuppressed(sink.Pos(), suppressedNodes, pass) {
			report(conf, pass, trace.Src, sink.(ssa.Node))
		}
	}
	return nil, nil
}

func reportSourcesReachingSink(conf *config.Config, pass *analysis.Pass, suppressedNodes suppression.ResultType, propagations map[*source.Source]propagation.Propagation, sink ssa.Instruction) {
	for src, prop := range propagations {
		if prop.IsTainted(sink.(ssa.Node)) && !isSuppressed(sink.Pos(), suppressedNodes, pass) {
			report(conf, pass, src, sink.(ssa.Node))
			break
		}
	}
}
func reportSourcesReachingFunction(conf *config.Config, pass *analysis.Pass, suppressedNodes suppression.ResultType, propagations map[*source.Source]propagation.Propagation, function ssa.Instruction) {
	for src, prop := range propagations {
		if prop.IsTainted(function.(ssa.Node)) && !isSuppressed(function.Pos(), suppressedNodes, pass) {
			reportFuncReach(conf, pass, src, function.(ssa.Node))
			break
		}
	}
}

func isSuppressed(pos token.Pos, suppressedNodes suppression.ResultType, pass *analysis.Pass) bool {
	for _, f := range pass.Files {
		if pos < f.Pos() || f.End() < pos {
			continue
		}
		// astutil.PathEnclosingInterval produces the list of nodes that enclose the provided
		// position, from the leaf node that directly contains it up to the ast.File node
		path, _ := astutil.PathEnclosingInterval(f, pos, pos)
		if len(path) < 2 {
			return false
		}
		// Given the position of a call, path[0] holds the ast.CallExpr and
		// path[1] holds the ast.ExprStmt. A suppressing comment may be associated
		// with the name of the function being called (Ident, SelectorExpr), with the
		// call itself (CallExpr), or with the entire expression (ExprStmt).
		if ce, ok := path[0].(*ast.CallExpr); ok {
			switch t := ce.Fun.(type) {
			case *ast.Ident:
				/*
					Sink( // levee.DoNotReport
				*/
				if suppressedNodes.IsSuppressed(t) {
					return true
				}
			case *ast.SelectorExpr:
				/*
					core.Sink( // levee.DoNotReport
				*/
				if suppressedNodes.IsSuppressed(t.Sel) {
					return true
				}
			}
		} else {
			fmt.Printf("unexpected node received: %v (type %T); please report this issue\n", path[0], path[0])
		}
		return suppressedNodes.IsSuppressed(path[0]) || suppressedNodes.IsSuppressed(path[1])
	}
	return false
}

func report(conf *config.Config, pass *analysis.Pass, source *source.Source, sink ssa.Node) {
	var b strings.Builder
	b.WriteString("a source has reached a sink")
	fmt.Fprintf(&b, "\n source: %v", pass.Fset.Position(source.Pos()))
	if conf.ReportMessage != "" {
		fmt.Fprintf(&b, "\n %v", conf.ReportMessage)
	}
	pass.Reportf(sink.Pos(), b.String())
}

func reportFuncReach(conf *config.Config, pass *analysis.Pass, source *source.Source, function ssa.Node) {
	var b strings.Builder
	b.WriteString("a source has reached a function")
	fmt.Fprintf(&b, "\n source: %v, function site: %v", pass.Fset.Position(source.Pos()), function.String())
	if conf.ReportMessage != "" {
		fmt.Fprintf(&b, "\n %v", conf.ReportMessage)
	}
	pass.Reportf(function.Pos(), b.String())
}
