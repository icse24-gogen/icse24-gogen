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

package newsource

import (
	"go/token"
	"reflect"
	"strings"

	//"os"
	"fmt"

	"xyz.asd.qwe/gout-static-analysis/internal/pkg/config"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/fieldpropagator"
	"xyz.asd.qwe/gout-static-analysis/internal/pkg/fieldtags"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

type ResultType = map[*ssa.Function][]*Source

var Analyzer = &analysis.Analyzer{
	Name:       "source",
	Doc:        "This analyzer identifies ssa.Values that are sources.",
	Flags:      config.FlagSet,
	Run:        run,
	Requires:   []*analysis.Analyzer{buildssa.Analyzer, fieldtags.Analyzer, fieldpropagator.Analyzer},
	ResultType: reflect.TypeOf(new(ResultType)).Elem(),
}

func run(pass *analysis.Pass) (interface{}, error) {
	ssaInput := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	sourceMap := make(map[*ssa.Function][]*Source, 0)

	conf, err := config.ReadConfig()
	if err != nil {
		return nil, err
	}

	for _, fn := range ssaInput.SrcFuncs {
		if strings.Contains(pass.Fset.Position(fn.Pos()).Filename, conf.NewSourceTags[0].File) && strings.Contains(fn.Name(), conf.NewSourceTags[0].Func) {
			fmt.Println("function", fn.Name(), pass.Fset.Position(fn.Pos()))
		} else{
			continue
		}
		
		for _, b := range fn.Blocks {
			for instrIdx, instr := range b.Instrs {
				fmt.Println("function", fn.Name(), instrIdx, pass.Fset.Position(instr.Pos()))
				if pass.Fset.Position(instr.Pos()).Line == conf.NewSourceTags[0].Line{
					if n, ok := instr.(ssa.Node); ok {
						sourceMap[fn] = make([]*Source, 0)
						sourceMap[fn] = append(sourceMap[fn], New(n))
						break
					}
					//switch instr.(type){
					//case ssa.Value:
					//	value := instr.(ssa.Value)
					//	sourceMap[fn] = make([]*Source, 0)
					//	if n, ok := value.(ssa.Node); ok {
					//		sourceMap[fn] = append(sourceMap[fn], New(n))
					//	}
					//}
				}
			}
		}
	}

	for _, srcs := range sourceMap {
		for _, s := range srcs {
			report(pass, s.Pos())
		}
	}

	return sourceMap, nil
}

func report(pass *analysis.Pass, pos token.Pos) {
	pass.Reportf(pos, "source identified at %s", pass.Fset.Position(pos))
}
