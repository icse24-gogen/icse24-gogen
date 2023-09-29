// Copyright 2020 Google LLC
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

// Package propagation implements the core taint propagation analysis that
// can be used to determine what ssa Nodes are tainted if a given Node is a source.
package propagation

import (
	"fmt"
	"go/types"
	"golang.org/x/tools/go/callgraph"
	"log"

	//"os"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/sanitizer"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/utils"
)

var fieldSensitive = false
var pcgOn = false
var taintCallRes = true

var pcgPtr *callgraph.Graph
var recursiveRecord map[*ssa.Function]bool

type sFields struct {
	sFieldsList map[types.Type][]int
}

func (p *sFields) IsSourceField(t types.Type, field int) bool {
	for _, taggedField := range p.sFieldsList[t] {
		if taggedField == field {
			return true // not source field
		}
	}
	return false
}

// Propagation represents the information that is used by, and collected
// during, a taint propagation analysis.
type Propagation struct {
	root         ssa.Node
	tainted      map[ssa.Node]bool
	preOrder     []ssa.Node
	sanitizers   []*sanitizer.Sanitizer
	taggedFields sFields
}

// Taint performs a depth-first search of the graph formed by SSA Referrers and
// Operands relationships, beginning at the given root node.
func Taint(n ssa.Node) Propagation {
	prop := Propagation{
		root:         n,
		tainted:      make(map[ssa.Node]bool),
		taggedFields: sFields{sFieldsList: make(map[types.Type][]int)},
	}
	maxInstrReached := map[*ssa.BasicBlock]int{}

	prop.taint(n, maxInstrReached, nil, false)
	// ensure immediate referrers are visited
	prop.taintReferrers(n, maxInstrReached, nil)

	return prop
}

func TaintWithoutCallRes(n ssa.Node) Propagation {
	taintCallRes = false
	defer func() {
		taintCallRes = true
	}()
	prop := Propagation{
		root:         n,
		tainted:      make(map[ssa.Node]bool),
		taggedFields: sFields{sFieldsList: make(map[types.Type][]int)},
	}
	maxInstrReached := map[*ssa.BasicBlock]int{}

	prop.taint(n, maxInstrReached, nil, false)
	// ensure immediate referrers are visited
	prop.taintReferrers(n, maxInstrReached, nil)

	return prop
}

func (prop *Propagation) AddTaintInPCG(n ssa.Node, pcg *callgraph.Graph, callSite *ssa.Call) {
	setForPCG(true, pcg, callSite)
	defer setForPCG(false, pcg, callSite)
	maxInstrReached := map[*ssa.BasicBlock]int{}
	prop.taint(n, maxInstrReached, nil, false)
	// ensure immediate referrers are visited
	prop.taintReferrers(n, maxInstrReached, nil)

	if callSite != nil {
		fmt.Println(callSite.String())
		maxInstrReached = map[*ssa.BasicBlock]int{}
		for node, _ := range prop.tainted {
			if _, toRetOk := node.(*ssa.Return); toRetOk {
				prop.taint(callSite, maxInstrReached, nil, false)
				prop.taintReferrers(n, maxInstrReached, nil)
				break //暂时只分析一层,可能需要多层分析
			}
		}
	}
}

func (prop *Propagation) HaveRet() (haveRet bool) {
	for node, _ := range prop.tainted {
		if _, toRetOk := node.(*ssa.Return); toRetOk {
			haveRet = true
			break
		}
	}
	return false
}

func PCGTaintBody(n ssa.Node, pcg *callgraph.Graph, callSite *ssa.Call, deleteRetControl ...bool) *Propagation {
	prop := &Propagation{
		root:    n,
		tainted: make(map[ssa.Node]bool),
	}
	maxInstrReached := map[*ssa.BasicBlock]int{}

	setForPCG(true, pcg, callSite)
	defer setForPCG(false, pcg, callSite)

	prop.taint(n, maxInstrReached, nil, false)
	// ensure immediate referrers are visited
	prop.taintReferrers(n, maxInstrReached, nil)

	if callSite != nil {
		maxInstrReached = map[*ssa.BasicBlock]int{}
		for node, _ := range prop.tainted {
			if _, toRetOk := node.(*ssa.Return); toRetOk {
				prop.taint(callSite, maxInstrReached, nil, false)
				prop.taintReferrers(callSite, maxInstrReached, nil)
				if len(deleteRetControl) != 0 && deleteRetControl[0] {
					delete(prop.tainted, node)
				}
				break //暂时只分析一层,可能需要多层分析
			}
		}
	}
	return prop
}

func TaintInPCG(n ssa.Node, pcg *callgraph.Graph, callSite *ssa.Call, deleteRetControl ...bool) Propagation {
	dControl := false
	if len(deleteRetControl) != 0 {
		dControl = true
	}
	prop := PCGTaintBody(n, pcg, callSite, dControl)

	recursiveRecord = nil
	fnParaInPCGVisited = nil
	fnFreeVarsInPCGVisited = nil
	return *prop
}

func TaintInPCG_R(n ssa.Node, pcg *callgraph.Graph, callSite *ssa.Call) Propagation {
	prop := PCGTaintBody(n, pcg, callSite)
	return *prop
}

func setFieldSensitive(v bool) {
	fieldSensitive = v
}

func setForPCG(v bool, pcg *callgraph.Graph, callSite ssa.CallInstruction) {
	pcgOn = v
	if v {
		pcgPtr = pcg
		if recursiveRecord == nil {
			recursiveRecord = make(map[*ssa.Function]bool)
		}
	} else {
		pcgPtr = nil
	}
}

func TaintWithField(n ssa.Node, fields map[types.Type][]int) (Propagation, map[types.Type][]int) {
	prop := Propagation{
		root:         n,
		tainted:      make(map[ssa.Node]bool),
		taggedFields: sFields{sFieldsList: make(map[types.Type][]int)},
	}
	maxInstrReached := map[*ssa.BasicBlock]int{}
	setFieldSensitive(true)
	defer setFieldSensitive(false)
	for key, value := range fields {
		prop.taggedFields.sFieldsList[key] = value
	}
	prop.taint(n, maxInstrReached, nil, false)
	// ensure immediate referrers are visited
	prop.taintReferrers(n, maxInstrReached, nil)

	fields = prop.taggedFields.sFieldsList
	return prop, fields
}

func TaintInPCGWithFieldBody(n ssa.Node, fields map[types.Type][]int, pcg *callgraph.Graph, callSite ssa.CallInstruction) (*Propagation, map[types.Type][]int) {
	prop := &Propagation{
		root:         n,
		tainted:      make(map[ssa.Node]bool),
		taggedFields: sFields{sFieldsList: make(map[types.Type][]int)},
	}
	maxInstrReached := map[*ssa.BasicBlock]int{}
	setFieldSensitive(true)
	defer setFieldSensitive(false)
	setForPCG(true, pcg, callSite)
	defer setForPCG(false, pcg, callSite)
	for key, value := range fields {
		prop.taggedFields.sFieldsList[key] = value
	}
	prop.taint(n, maxInstrReached, nil, false)
	// ensure immediate referrers are visited
	prop.taintReferrers(n, maxInstrReached, nil)
	fields = prop.taggedFields.sFieldsList
	return prop, fields
}
func TaintWithFieldInPCG_R(n ssa.Node, fields map[types.Type][]int, pcg *callgraph.Graph, callSite ssa.CallInstruction) (Propagation, map[types.Type][]int) {
	prop, fieldsRes := TaintInPCGWithFieldBody(n, fields, pcg, callSite)
	return *prop, fieldsRes
}

func TaintWithFieldInPCG(n ssa.Node, fields map[types.Type][]int, pcg *callgraph.Graph, callSite ssa.CallInstruction) (Propagation, map[types.Type][]int) {
	prop, fieldsRes := TaintInPCGWithFieldBody(n, fields, pcg, callSite)
	recursiveRecord = nil
	fnParaInPCGVisited = nil
	fnFreeVarsInPCGVisited = nil
	return *prop, fieldsRes
}

func (prop *Propagation) AddNode(n ssa.Node) {
	if prop.tainted == nil {
		prop.root = n
		prop.tainted = make(map[ssa.Node]bool)
	}
	prop.tainted[n] = true
}

// taint performs a depth-first search of the graph formed by SSA Referrers and
// Operands relationships. Along the way, visited nodes are marked and stored
// in a slice which captures the visitation order. Sanitizers are also recorded.
// maxInstrReached and lastBlockVisited are used to give the traversal some
// degree of flow sensitivity. Specifically:
// - maxInstrReached records the highest index of an instruction visited
//   in each block. This is used to avoid visiting past instructions, e.g.
//   a call to a sink where the argument was tainted after the call happened.
// - lastBlockVisited is used to determine whether the next instruction to visit
//   can be reached from the current instruction.
func (prop *Propagation) taint(n ssa.Node, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock, isReferrer bool) {
	if prop.shouldNotTaint(n, maxInstrReached, lastBlockVisited, isReferrer) {
		return
	}
	prop.preOrder = append(prop.preOrder, n)
	prop.tainted[n] = true

	mirCopy := map[*ssa.BasicBlock]int{}
	for m, i := range maxInstrReached {
		mirCopy[m] = i
	}

	if instr, ok := n.(ssa.Instruction); ok {
		instrIndex, ok := indexInBlock(instr)
		if !ok {
			return
		}

		if mirCopy[instr.Block()] < instrIndex {
			mirCopy[instr.Block()] = instrIndex
		}

		lastBlockVisited = instr.Block()
	}

	prop.taintNeighbors(n, mirCopy, lastBlockVisited)
}

func (prop *Propagation) shouldNotTaint(n ssa.Node, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock, isReferrer bool) bool {
	if prop.tainted[n] {
		return true
	}

	if instr, ok := n.(ssa.Instruction); ok {
		instrIndex, ok := indexInBlock(instr)
		if !ok {
			return true
		}

		// If the referrer is in a different block from the one we last visited,
		// and it can't be reached from the block we are visiting, then stop visiting.
		if lastBlockVisited != nil && instr.Block() != lastBlockVisited && !prop.canReach(lastBlockVisited, instr.Block()) {
			return true
		}

		// If this call's index is lower than the highest seen so far in its block,
		// then this call is "in the past". If this call is a referrer,
		// then we would be propagating taint backwards in time, so stop traversing.
		// (If the call is an operand, then it is being used as a value, so it does
		// not matter when the call occurred.)
		if _, ok := instr.(*ssa.Call); ok && instrIndex < maxInstrReached[instr.Block()] && isReferrer {
			return true
		}
	}

	return false
}

func (prop *Propagation) taintNeighbors(n ssa.Node, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock) {
	switch t := n.(type) {
	case *ssa.Alloc:
		// An Alloc represents the allocation of space for a variable. If a Node is an Alloc,
		// and the thing being allocated is not an array, then either:
		// a) it is a Source value, in which case it will get its own traversal when sourcesFromBlocks
		//    finds this Alloc
		// b) it is not a Source value, in which case we should not visit it.
		// However, if the Alloc is an array, then that means the source that we are visiting from
		// is being placed into an array, slice or varargs, so we do need to keep visiting.
		if _, isArray := utils.Dereference(t.Type()).(*types.Array); isArray {
			prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
		}

	case *ssa.Call:
		if pcgOn {
			if _, mapOk := recursiveRecord[n.(*ssa.Call).Call.StaticCallee()]; n.(*ssa.Call).Call.StaticCallee() != nil && !mapOk {
				recursiveRecord[n.(*ssa.Call).Call.StaticCallee()] = true
				canReachSubReturn := prop.taintIfPCGCall(t)
				if canReachSubReturn {
					prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
				}
			}
		} else {
			if taintCallRes {
				prop.taintReferrers(n, maxInstrReached, lastBlockVisited) // maybe overtaint
			}
		}
		prop.taintCall(t, maxInstrReached, lastBlockVisited)

	// The Go instruction is a wrapper around an implicit Call instruction.
	case *ssa.Go:
		prop.taintStdlibCall(t, maxInstrReached, lastBlockVisited)

	case *ssa.Field:
		prop.taintField(n, maxInstrReached, lastBlockVisited, t.X.Type().Underlying(), t.Field)

	case *ssa.FieldAddr:
		prop.taintField(n, maxInstrReached, lastBlockVisited, t.X.Type().Underlying().(*types.Pointer).Elem(), t.Field)

	// Everything but the actual integer Index should be visited.
	case *ssa.Index:
		prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
		prop.taint(t.X.(ssa.Node), maxInstrReached, lastBlockVisited, false)

	case *ssa.Lookup:
		prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
		prop.taint(t.X.(ssa.Node), maxInstrReached, lastBlockVisited, false)

	// Everything but the actual integer Index should be visited.
	case *ssa.IndexAddr:
		prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
		prop.taint(t.X.(ssa.Node), maxInstrReached, lastBlockVisited, false)

	// Only the Addr (the Value that is being written to) should be visited.
	case *ssa.Store:
		if FA, toFieldAOk := t.Addr.(*ssa.FieldAddr); toFieldAOk && fieldSensitive {
			prop.taggedFields.sFieldsList[FA.X.Type().Underlying().(*types.Pointer).Elem()] =
				append(prop.taggedFields.sFieldsList[FA.X.Type().Underlying().(*types.Pointer).Elem()], FA.Field)
		}
		prop.taint(t.Addr.(ssa.Node), maxInstrReached, lastBlockVisited, false)
		var rands []*ssa.Value
		rands = n.Operands(rands)
		for _, rand := range rands {
			//node := (*rand).(*ssa.Node)
			value := *rand
			node := value.(ssa.Node)
			prop.taintReferrers(node, maxInstrReached, lastBlockVisited)
		}

	// Only the Map itself can be tainted by an Update.
	// The Key can't be tainted.
	// The Value can propagate taint to the Map, but not receive it.
	// MapUpdate has no referrers, it is only an Instruction, not a Value.
	case *ssa.MapUpdate:
		prop.taint(t.Map.(ssa.Node), maxInstrReached, lastBlockVisited, false)

	case *ssa.Select:
		prop.taintSelect(t, maxInstrReached, lastBlockVisited)

	// The only Operand that can be tainted by a Send is the Chan.
	// The Value can propagate taint to the Chan, but not receive it.
	// Send has no referrers, it is only an Instruction, not a Value.
	case *ssa.Send:
		prop.taint(t.Chan.(ssa.Node), maxInstrReached, lastBlockVisited, false)

	case *ssa.Slice:
		prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
		// This allows taint to propagate backwards into the sliced value
		// when the resulting value is tainted
		prop.taint(t.X.(ssa.Node), maxInstrReached, lastBlockVisited, false)

	// These nodes' operands should not be visited, because they can only receive
	// taint from their operands, not propagate taint to them.
	case *ssa.BinOp, *ssa.ChangeInterface, *ssa.ChangeType, *ssa.Convert, *ssa.Extract, *ssa.MakeChan, *ssa.MakeMap, *ssa.MakeSlice, *ssa.Phi, *ssa.Range:
		prop.taintReferrers(n, maxInstrReached, lastBlockVisited)

	// These nodes don't have operands; they are Values, not Instructions.
	case *ssa.Const, *ssa.FreeVar, *ssa.Global, *ssa.Parameter:
		prop.taintReferrers(n, maxInstrReached, lastBlockVisited)

	// These nodes are both Instructions and Values, and currently have no special restrictions.
	case *ssa.MakeInterface, *ssa.TypeAssert, *ssa.UnOp:
		prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
		prop.taintOperands(n, maxInstrReached, lastBlockVisited)
	case *ssa.Return:
		if pcgOn {

		}
	case *ssa.MakeClosure:
		if fnPtr, toFnOk := n.(*ssa.MakeClosure).Fn.(*ssa.Function); toFnOk {
			//(store to alloc) Or (not store to alloc)
			if pcgOn {
				if _, mapOk := recursiveRecord[fnPtr]; fnPtr != nil && !mapOk {
					recursiveRecord[fnPtr] = true
					canReachSubReturn := prop.taintIfPCGClosure(t)
					if canReachSubReturn {
						prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
					}
				}
			} else {
				prop.taintReferrers(n, maxInstrReached, lastBlockVisited) // maybe overtaint
			}
		}
	// These nodes cannot propagate taint.
	case *ssa.Builtin, *ssa.DebugRef, *ssa.Defer, *ssa.Function, *ssa.If, *ssa.Jump, *ssa.Next, *ssa.Panic, *ssa.RunDefers:

	default:
		fmt.Printf("unexpected node received: %T %v; please report this issue\n", n, n)
	}
}

func (prop *Propagation) taintField(n ssa.Node, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock, t types.Type, field int) {
	//if !prop.config.IsSourceField(utils.DecomposeField(t, field)) && !prop.taggedFields.IsSourceField(t, field) {
	if fieldSensitive && !prop.taggedFields.IsSourceField(t, field) {
		return
	}
	prop.taintReferrers(n, maxInstrReached, lastBlockVisited)
	prop.taintOperands(n, maxInstrReached, lastBlockVisited)
}

var referFrom ssa.Node

func (prop *Propagation) taintReferrers(n ssa.Node, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock) {
	referFrom = n //先用简单的写着
	if !hasTaintableType(n) {
		referFrom = nil
		return
	}
	if n.Referrers() == nil {
		referFrom = nil
		return
	}
	for _, r := range *n.Referrers() {
		prop.taint(r.(ssa.Node), maxInstrReached, lastBlockVisited, true)
	}
	referFrom = nil
}

func (prop *Propagation) taintOperands(n ssa.Node, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock) {
	for _, o := range n.Operands(nil) {
		if *o == nil {
			continue
		}
		prop.taint((*o).(ssa.Node), maxInstrReached, lastBlockVisited, false)
	}
}

type taintState struct {
	fieldSensitive bool
	pcgOn          bool
	PcgPtr         *callgraph.Graph
	referFrom      ssa.Node
}

func recordAndResetTaintState() *taintState {
	rState := &taintState{
		fieldSensitive: fieldSensitive,
		pcgOn:          pcgOn,
		PcgPtr:         pcgPtr,
		referFrom:      referFrom,
	}
	fieldSensitive = false
	pcgOn = false
	pcgPtr = nil
	referFrom = nil
	return rState
}

func recoverTaintState(rState *taintState) {
	fieldSensitive = rState.fieldSensitive
	pcgOn = rState.pcgOn
	pcgPtr = rState.PcgPtr
	referFrom = rState.referFrom
}

func (prop *Propagation) judgeArgReachReturn() bool {
	for node, _ := range prop.tainted {
		if _, toRetOk := node.(*ssa.Return); toRetOk {
			return true
		}
	}
	return false
}

var fnParaInPCGVisited map[*ssa.Function][]int

func judgeParaVisited(fn *ssa.Function, paraIdx int) bool {
	if fnParaInPCGVisited == nil {
		fnParaInPCGVisited = make(map[*ssa.Function][]int)
	}
	for _, rIdx := range fnParaInPCGVisited[fn] {
		if paraIdx == rIdx {
			return true
		}
	}
	return false
}

func (prop *Propagation) taintIfPCGCall(call *ssa.Call) (canReachReturn bool) {
	callee := call.Call.StaticCallee()
	if callee == nil {
		canReachReturn = false
	} else if len(callee.Params) == 0 {
		return true
	} else {
		if _, ok := pcgPtr.Nodes[callee]; ok && referFrom != nil { //if is call in PCG
			//find param index
			argindex := -1
			for index, arg := range call.Call.Args {
				if arg == referFrom.(ssa.Value) {
					argindex = index
					break
				}
			}
			if argindex == -1 || judgeParaVisited(callee, argindex) { //not found or visited
				return false
			}

			oldState := recordAndResetTaintState()
			var interProg Propagation
			if oldState.fieldSensitive == true {
				fieldSensitive = true
				interProg, _ = TaintWithFieldInPCG_R(callee.Params[argindex], prop.taggedFields.sFieldsList, oldState.PcgPtr, nil)
			} else {
				interProg = TaintInPCG_R(callee.Params[argindex], oldState.PcgPtr, nil)
			}
			fnParaInPCGVisited[callee] = append(fnParaInPCGVisited[callee], argindex)

			for node, _ := range interProg.tainted {
				if _, toRetOk := node.(*ssa.Return); toRetOk {
					canReachReturn = true
					delete(interProg.tainted, node) //delete other function's return
				}
			}
			for node, b := range interProg.tainted {
				if b {
					prop.tainted[node] = true
				}
			}
			recoverTaintState(oldState)
		} else {
			return false //if not a PCG call, don't taint res
		}
	}
	return canReachReturn
}

var fnFreeVarsInPCGVisited map[*ssa.Function][]int

func judgeFreeVarVisited(fn *ssa.Function, freeVarIdx int) bool {
	if fnFreeVarsInPCGVisited == nil {
		fnFreeVarsInPCGVisited = make(map[*ssa.Function][]int)
	}
	for _, rIdx := range fnFreeVarsInPCGVisited[fn] {
		if freeVarIdx == rIdx {
			return true
		}
	}
	return false
}

func (prop *Propagation) taintIfPCGClosure(cfn *ssa.MakeClosure) (canReachReturn bool) {
	callee := cfn.Fn.(*ssa.Function)
	bindings := cfn.Bindings

	if _, ok := pcgPtr.Nodes[callee]; ok && referFrom != nil { //if is call in PCG
		//find param index
		bindIndex := -1
		for index, bd := range bindings {
			if bd == referFrom.(ssa.Value) {
				bindIndex = index
				break
			}
		}
		if bindIndex == -1 || judgeFreeVarVisited(callee, bindIndex) { //not found or visited
			return false
		}

		oldState := recordAndResetTaintState()
		var interProg Propagation
		if oldState.fieldSensitive == true {
			fieldSensitive = true
			interProg, _ = TaintWithFieldInPCG_R(callee.FreeVars[bindIndex], prop.taggedFields.sFieldsList, oldState.PcgPtr, nil)
		} else {
			interProg = TaintInPCG_R(callee.FreeVars[bindIndex], oldState.PcgPtr, nil)
		}
		fnFreeVarsInPCGVisited[callee] = append(fnFreeVarsInPCGVisited[callee], bindIndex)

		for node, _ := range interProg.tainted {
			if _, toRetOk := node.(*ssa.Return); toRetOk {
				canReachReturn = true
				delete(interProg.tainted, node) //delete other function's return
			}
		}
		for node, b := range interProg.tainted {
			if b {
				prop.tainted[node] = true
			}
		}
		recoverTaintState(oldState)
	} else if _, ok := pcgPtr.Nodes[callee]; !ok && referFrom != nil {
		return true
	}

	return canReachReturn
}

func (prop *Propagation) taintCall(call *ssa.Call, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock) {
	//if callee := call.Call.StaticCallee(); callee != nil && prop.config.IsSanitizer(utils.DecomposeFunction(callee)) {
	if callee := call.Call.StaticCallee(); callee != nil {
		prop.sanitizers = append(prop.sanitizers, &sanitizer.Sanitizer{Call: call})
		return
	}

	// Some builtins require special handling
	if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
		prop.taintBuiltin(call, builtin.Name(), maxInstrReached, lastBlockVisited)
		return
	}

	prop.taintStdlibCall(call, maxInstrReached, lastBlockVisited)
}

func (prop *Propagation) taintBuiltin(call *ssa.Call, builtinName string, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock) {
	switch builtinName {
	// The values being appended cannot be tainted.
	case "append":
		// The slice argument needs to be tainted because if its underlying array has
		// enough remaining capacity, the appended values will be written to it.
		prop.taintCallArg(call.Call.Args[0], maxInstrReached, lastBlockVisited)
		// The returned slice is tainted if either the slice argument or the values
		// are tainted, so we need to visit the referrers.
		prop.taintReferrers(call, maxInstrReached, lastBlockVisited)
	// Only the first argument (dst) can be tainted. (The src cannot be tainted.)
	case "copy":
		prop.taintCallArg(call.Call.Args[0], maxInstrReached, lastBlockVisited)
	// The builtin delete(m map[Type]Type1, key Type) func does not propagate taint.
	case "delete":
	}
}

func (prop *Propagation) taintCallArg(arg ssa.Value, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock) {
	if canBeTaintedByCall(arg.Type()) {
		prop.taint(arg.(ssa.Node), maxInstrReached, lastBlockVisited, false)
	}
}

func (prop *Propagation) taintSelect(sel *ssa.Select, maxInstrReached map[*ssa.BasicBlock]int, lastBlockVisited *ssa.BasicBlock) {
	// Select returns a tuple whose first 2 elements are irrelevant for our
	// analysis. Subsequent elements correspond to Recv states, which map
	// 1:1 with Extracts.
	// See the ssa package code for more details.
	recvIndex := 0
	extractIndex := map[*ssa.SelectState]int{}
	for _, ss := range sel.States {
		if ss.Dir == types.RecvOnly {
			extractIndex[ss] = recvIndex + 2
			recvIndex++
		}
	}

	for _, s := range sel.States {
		switch {
		// If the sent value (Send) is tainted, propagate taint to the channel
		case s.Dir == types.SendOnly && prop.tainted[s.Send.(ssa.Node)]:
			prop.taint(s.Chan.(ssa.Node), maxInstrReached, lastBlockVisited, false)

		// If the channel is tainted, propagate taint to the appropriate Extract
		case s.Dir == types.RecvOnly && prop.tainted[s.Chan.(ssa.Node)]:
			if sel.Referrers() == nil {
				continue
			}
			for _, r := range *sel.Referrers() {
				e, ok := r.(*ssa.Extract)
				if !ok || e.Index != extractIndex[s] {
					continue
				}
				prop.taint(e, maxInstrReached, lastBlockVisited, false)
			}
		}
	}
}

func (prop *Propagation) canReach(start *ssa.BasicBlock, dest *ssa.BasicBlock) bool {
	if start.Dominates(dest) {
		return true
	}

	stack := stack([]*ssa.BasicBlock{start})
	seen := map[*ssa.BasicBlock]bool{start: true}
	for len(stack) > 0 {
		current := stack.pop()
		if current == dest {
			return true
		}
		for _, s := range current.Succs {
			if seen[s] {
				continue
			}
			seen[s] = true
			stack.push(s)
		}
	}
	return false
}

// IsTainted determines whether an instruction is tainted by the Propagation.
//func (prop Propagation) IsTainted(instr ssa.Instruction) bool {
//	return prop.tainted[instr.(ssa.Node)] && !prop.isSanitizedAt(instr)
//}
func (prop Propagation) IsTainted(instr ssa.Node) bool {
	return prop.tainted[instr]
}

func (prop Propagation) InferArguementCallSite(instrAlloc ssa.Instruction, restInstr []ssa.Instruction) int {
	//TODO: Handle target(tainted, not_target(not_taintied), normal_arg) or target(normal_arg , not_target(not_taintied), tainted)
	res := 0
	for _, instr := range restInstr {
		switch instr.(type) {
		case *ssa.Call:
			return res
		}
		res += 1
	}
	return res
}

func (prop Propagation) PrintTainted(pass *analysis.Pass) {
	for node, taintedFlag := range prop.tainted {
		if taintedFlag {
			fmt.Println(node, pass.Fset.Position(node.Pos()))
		}
	}
}

func (prop Propagation) GetTaintedBranches(fn *ssa.Function) []ssa.Node {
	res := make([]ssa.Node, 0)
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			switch v := instr.(type) {
			case *ssa.If:
				condNode := v.Cond.(ssa.Node)
				if prop.tainted[condNode] {
					res = append(res, condNode)
				}
			}
		}
	}
	return res
}

func (prop Propagation) ExtractCallSiteInfo(callinstr ssa.Instruction) []uint8 {
	//deprecated
	result := []uint8{}
	callNode := callinstr.(ssa.Node)
	if !prop.tainted[callNode] {
		return nil
	}
	fmt.Println("[+]ExtractCallSiteInfo")

	for node, b := range prop.tainted {
		if strings.Contains(node.String(), "varargs") {
			argStr := node.String()
			leftBlanket := strings.Index(argStr, "[")
			rightBlanket := strings.Index(argStr, "]")
			indexStr := argStr[leftBlanket+1 : rightBlanket]
			argumentIdx, atoiErr := strconv.Atoi(indexStr)
			if atoiErr != nil {
				panic("Atoi error is not tolerantable")
			}

			result = append(result, uint8(argumentIdx))

			fmt.Println(callNode.String(), node.String(), b)
		}
	}
	return result
}

// isSanitizedAt determines whether the taint propagated from the Propagation's root
// is sanitized when it reaches the target instruction.
func (prop Propagation) isSanitizedAt(instr ssa.Instruction) bool {
	for _, san := range prop.sanitizers {
		if san.Dominates(instr) {
			return true
		}
	}

	return false
}

type stack []*ssa.BasicBlock

func (s *stack) pop() *ssa.BasicBlock {
	if len(*s) == 0 {
		log.Println("tried to pop from empty stack")
	}
	popped := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]
	return popped
}

func (s *stack) push(b *ssa.BasicBlock) {
	*s = append(*s, b)
}

// indexInBlock returns this instruction's index in its parent block.
func indexInBlock(target ssa.Instruction) (int, bool) {
	for i, instr := range target.Block().Instrs {
		if instr == target {
			return i, true
		}
	}
	// we can only hit this return if there is a bug in the ssa package
	// i.e. an instruction does not appear within its parent block
	return 0, false
}

func hasTaintableType(n ssa.Node) bool {
	if v, ok := n.(ssa.Value); ok {
		if _, ok := v.Type().(*types.Signature); ok { //remove restrict on non-string basic types
			return false
		}
	}
	return true
}

// A type can be tainted by a call if it is itself a pointer or pointer-like type (according to
// pointer.CanPoint), or it is an array/struct that holds an element that can be tainted by
// a call.
func canBeTaintedByCall(t types.Type) bool {
	if pointer.CanPoint(t) {
		return true
	}

	switch tt := t.(type) {
	case *types.Array:
		return canBeTaintedByCall(tt.Elem())

	case *types.Struct:
		for i := 0; i < tt.NumFields(); i++ {
			// this cannot cause an infinite loop, because a struct
			// type cannot refer to itself except through a pointer
			if canBeTaintedByCall(tt.Field(i).Type()) {
				return true
			}
		}
		return false
	}

	return false
}

func (prop Propagation) GetTaintedNodes() []ssa.Node {
	result := make([]ssa.Node, 0)
	for node, b := range prop.tainted {
		if b {
			result = append(result, node)
		}
	}
	return result
}
