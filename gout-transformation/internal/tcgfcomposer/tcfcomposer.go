package tcgfcomposer

import (
	"bytes"
	"flag"
	"path/filepath"
	"regexp"

	//"reflect"

	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io/ioutil"

	"strconv"
	"strings"

	"math/rand"

	"io"
	"os"
	"text/template"

	yaml "gopkg.in/yaml.v2"
	"xyz.asd.qwe/gout-transformation/internal/models"
	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

// a button to decide whether to fuzz global vars or not
var flagFuzzGlobalVar = flag.Bool("global", true, "if fuzz global variable")
var flagConstAlias = flag.Bool("const", true, "if add feature of const alias into gen")

// Composer can parse Go files.
type Composer struct {
	// The importer to resolve packages from import paths.
	IsSrcParsed         bool
	Importer            types.Importer
	filepath            string
	metapath            string
	parseResult         *Result
	metainfo            *(metainfo.TestCaseMetaInfo)
	globalModifiedFiles []string
	mutatedGlobalVars   map[interface{}]bool
	constNeedsToAliad   map[interface{}]bool
}

var fdg_globalFuncName = "FDG_FuzzGlobal"
var mainSrc = template.Must(template.New("main").Parse(`
package main

import (
	target "{{.Pkg}}"
	dep "go-fuzz-dep"
)

func main() {
	fns := []func([]byte)int {
		{{range .AllFuncs}}
			target.{{.}},
		{{end}}
	}
	dep.Main(fns)
}
`))

var fuzzSrc = template.Must(template.New("main").Parse(`
func Fuzz{{.TestName}} ({{.FuzzDataName}} []byte) int {
	t := &testing.T{}
	_ = t
	var skippingTableDriven bool
	_, skippingTableDriven = os.LookupEnv("SKIPPING_TABLE_DRIVEN")
	_ = skippingTableDriven
	transstruct.SetFuzzData({{.FuzzDataName}})
	{{.globalFuncName}}()
	{{.Body}}
	return 1
}

func {{.globalFuncName}}(){
	{{.globalFuncBody}}
}
`))

func (p *Composer) GenerateOneFunc() []byte {
	t := fuzzSrc
	result := p.parseResult
	//dot := map[string]interface{}{"PkgName": result.Header.Package, "Imported": result.Header.Imports[0].Path, "TestName": result.Funcs[0].Name, "Body": string(result.Funcs[0].Body)}

	dot := map[string]interface{}{"TestName": result.Funcs[0].Name, "Body": string(result.Funcs[0].Body), "globalFuncName": fdg_globalFuncName}
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, dot); err != nil {
		panic("GenerateOneFunc")
	}
	return buf.Bytes()
}

func isBasicType(t string) bool {
	switch t {
	case "bool", "string", "int", "int8", "int16", "int32", "int64", "uint",
		"uint8", "uint16", "uint32", "uint64", "uintptr", "byte", "rune",
		"float32", "float64", "complex64", "complex128":
		return true
	default:
		return false
	}
}

func (p *Composer) GenerateByName(targetName string) ([]byte, error) {
	t := fuzzSrc
	result := p.parseResult
	//dot := map[string]interface{}{"PkgName": result.Header.Package, "Imported": result.Header.Imports[0].Path, "TestName": result.Funcs[0].Name, "Body": string(result.Funcs[0].Body)}
	targetIdx := -1
	for funcIdx, fun := range result.Funcs {
		if fun.Name == targetName {
			targetIdx = funcIdx
		}
	}
	if targetIdx == -1 {
		return nil, errors.New("Func not found")
	}
	dot := map[string]interface{}{"TestName": result.Funcs[targetIdx].Name, "Body": string(result.Funcs[targetIdx].Body), "globalFuncName": fdg_globalFuncName}
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, dot); err != nil {
		panic("GenerateOneFunc")
	}
	return buf.Bytes(), nil
}

func GenerateArgString(tcmi *(metainfo.TestCaseMetaInfo)) string {
	//deprecated
	res := ""
	for _, curvar := range tcmi.VariableList {
		switch curvar.VarType {
		case metainfo.FuzzableString:
			res += fmt.Sprintf(", %s string", curvar.VarName)
		}
	}
	return res
}

func (p *Composer) GenerateByTestCaseInfo(tcmi *(metainfo.TestCaseMetaInfo)) ([]byte, error) {
	//text based
	t := fuzzSrc
	result := p.parseResult
	targetIdx := -1

	for funcIdx, fun := range result.Funcs {
		if fun.Name == tcmi.Name {
			targetIdx = funcIdx
		}
	}
	if targetIdx == -1 {
		return nil, errors.New("Func not found")
	}

	generateRandomString := func(n int) string {
		var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		b := make([]rune, n)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		return string(b)
	}

	dot := map[string]interface{}{"TestName": result.Funcs[targetIdx].Name, "Body": string(result.Funcs[targetIdx].Body), "FuzzDataName": generateRandomString(3), "globalFuncName": fdg_globalFuncName}
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, dot); err != nil {
		panic("GenerateOneFunc")
	}
	return buf.Bytes(), nil
}

func appendFuzzParam(fl *ast.FuncLit, v *metainfo.VariableMetaInfo) {
	//fmt.Println("[+]appending fuzztype for", v.VarName)
	switch v.VarType {
	case metainfo.FuzzableString:
		appendingVariable := &ast.Field{
			Names: []*ast.Ident{{Name: v.VarName}},
			Type:  &ast.Ident{Name: "string"},
		}
		fl.Type.Params.List = append(fl.Type.Params.List, appendingVariable)
	case metainfo.FuzzableBytes:
		//key of supporting new fuzzable argument
		appendingVariable := &ast.Field{
			Names: []*ast.Ident{{Name: v.VarName}},
			Type:  &ast.Ident{Name: "[]byte"},
		}
		fl.Type.Params.List = append(fl.Type.Params.List, appendingVariable)
	}
}

func generateDataInterfaceASTNode(pv *models.Variable) *ast.CallExpr {
	var res *ast.CallExpr
	//fmt.Println("[+]Printing type", pv.Type) //nil?
	//fmt.Println(reflect.TypeOf(pv.Value))
	if bl, ok := pv.Value.(*ast.BasicLit); ok {
		res = &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("transstruct")}}
		switch bl.Kind {
		case token.FLOAT:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat64")}
			res.Args = []ast.Expr{bl}
		case token.INT:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt")}
			res.Args = []ast.Expr{bl}
		case token.STRING:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetString")}
			//refact it later
			res.Args = []ast.Expr{bl}
		}

	} else {
		res = &ast.CallExpr{}
		//fmt.Println("[-]Unknown type", pv.Value) //nil?
		//fmt.Println(reflect.TypeOf(pv.Value))
		res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFuzzData")}
		res.Args = []ast.Expr{pv.Value.(ast.Expr)}
	}
	return res
}

func appendNonImmediateFuzzParams(fl *ast.FuncLit, mi *metainfo.TestCaseMetaInfo) {
	for _, v := range mi.VariableList {
		if v.IsImmediateVariable {
			continue
		}
		appendFuzzParam(fl, &v)
	}
}

func renderAST(w io.Writer, fset *token.FileSet, astFile *ast.File) {
	cfg := printer.Config{
		Mode:     printer.TabIndent,
		Tabwidth: 8,
		Indent:   0,
	}
	cfg.Fprint(w, fset, astFile)
}

func removeOrigAssignment(fl *ast.FuncLit, metainfo *metainfo.TestCaseMetaInfo) {
	//deprecated
	newList := fl.Body.List
	curIndex := len(newList)
	for {
		curIndex -= 1
		if curIndex < 0 {
			break
		}
		st := newList[curIndex]
		if as, ok := st.(*ast.AssignStmt); ok {
			if as != nil {
				lhs := as.Lhs[0]
				val := types.ExprString(lhs)
				for _, v := range metainfo.VariableList {
					if v.VarName == val {
						newList = append(newList[0:curIndex], newList[curIndex+1:]...)
					}
				}
			}
		}
	}
	fl.Body.List = newList
}

func transformFuzzCallBack(fDeclFuzz *ast.FuncDecl, mi *metainfo.TestCaseMetaInfo) {
	var flFuzz *ast.FuncLit
	if fDeclFuzz == nil {
		return
	}
	for _, stmt := range fDeclFuzz.Body.List { //debut case: get fl of fuzz core callback in simple way
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			if ce, ok := s.X.(*ast.CallExpr); ok {
				for _, arg := range ce.Args {
					if fl, ok := arg.(*ast.FuncLit); ok {
						flFuzz = fl
					}
				}
			}
		}
		break
	}
	generateRandomString := func(n int) string {
		var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		b := make([]rune, n)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		return string(b)
	}

	//For single assignment cases
	appendNonImmediateFuzzParams(flFuzz, mi)
	removeOrigAssignment(flFuzz, mi)

	var ceFinder func(ce *ast.CallExpr, pos token.Pos, calleeName string) *ast.CallExpr
	ceFinder = func(ce *ast.CallExpr, pos token.Pos, calleeName string) *ast.CallExpr {
		switch callee := ce.Fun.(type) {
		case *ast.SelectorExpr:
			if callee.Sel.Name == calleeName {
				return ce
			}
		case *ast.Ident:
			if callee.Name == calleeName {
				return ce
			}
		}
		for _, arg := range ce.Args {
			switch ae := arg.(type) {
			case *ast.CallExpr:
				return ceFinder(ae, pos, calleeName)
			default:
				if arg.Pos() == pos {
					return ce
				}
			}
		}
		return nil
	}

	//For Immediate case
	for _, v := range mi.VariableList {
		if v.IsImmediateVariable {
			for _, stmt := range flFuzz.Body.List {
				switch s := stmt.(type) {
				case *ast.DeclStmt:
					//fmt.Println(s)
				case *ast.AssignStmt:
					//fmt.Println(s)
				case *ast.ExprStmt:
					if ce, ok := s.X.(*ast.CallExpr); ok {
						curCallee := v.Callee[strings.LastIndex(v.Callee, ".")+1:]
						handleCe := ceFinder(ce, token.Pos(v.VarPos), curCallee)
						if handleCe != nil {
							//fmt.Println(reflect.TypeOf(handleCe))
							v.VarName = generateRandomString(3)
							handleCe.Args[v.ArgIndex] = ast.NewIdent(v.VarName)
							appendFuzzParam(flFuzz, &v)
						}
					}
				}
			}
		}
	}
}

func (p *Composer) clearComment(fAst *ast.File) {
	fAst.Comments = nil
}

func (p *Composer) constAlias(fDeclFuzz *ast.FuncDecl, fset *token.FileSet) []string {
	// it returns the paths of modified files in const alias
	// and they should be recovered when the generation is finished
	/*
		读VariableList[x].VarRelatedConstSources的时候里面有一个MustAlias []AliasInfo，
		AliasInfo里面有一个IDOfAllConst int，
		这个代表常量的alias常量在TestCaseMetaInfo.AllConstArray []VariableConstSourceInfo中的下标
	*/
	modifiedFiles := make([]string, 0)
	aliasAConst := func() {}
	aliasAConst()

	return modifiedFiles

}

func (p *Composer) handleTableDrivenV2(fDeclFuzz *ast.FuncDecl, fset *token.FileSet) bool {
	maybeTables := make(map[int]int)
	// load potential tables
	for _, api := range p.metainfo.APISequence {
		if api.TableInfo.IsFromGlobalVarTable && api.TableInfo.GlobalTable.SourceLine != 0 {
			// table var is a global
			// TODO
		} else if api.TableInfo.LocalTableLine != 0 {
			maybeTables[api.TableInfo.LocalTableLine] = api.TableInfo.LocalTableColumn
		}
	}
	if len(maybeTables) == 0 {
		return false
	}

	instrumentTableDrivenHandler := func(rangeStmt *ast.RangeStmt) {
		selectExpr := new(ast.SelectorExpr)
		selectExpr.X = &ast.Ident{Name: "transstruct"}
		selectExpr.Sel = &ast.Ident{Name: "LableTableDrivenLoopEnd"}

		callexpr := &ast.CallExpr{Fun: selectExpr}

		ifbody := new(ast.BlockStmt)
		ifbody.List = append(ifbody.List, &ast.BranchStmt{Tok: token.BREAK})

		ifstmt := new(ast.IfStmt)
		ifstmt.Cond = callexpr
		ifstmt.Body = ifbody
		rangeStmt.Body.List = append(rangeStmt.Body.List, ifstmt)
	}
	hasAddHandler := false
	ast.Inspect(fDeclFuzz, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.RangeStmt:
			validPoses := make([]token.Position, 0)
			switch x := n.X.(type) {
			case *ast.CompositeLit:
				tPos := fset.Position(x.Lbrace)
				if tPos.IsValid() {
					validPoses = append(validPoses, tPos)
				}
			case *ast.Ident:
				if asnPtr, ok := x.Obj.Decl.(*ast.AssignStmt); ok {
					if len(asnPtr.Lhs) == 0 {
						break
					}
					if asnPtr.Lhs[0].Pos().IsValid() {
						validPoses = append(validPoses, fset.Position(asnPtr.Lhs[0].Pos()))
					}
				}
			default:
				fmt.Println("[-] Unsupport range object")
			}
			for _, pos := range validPoses {
				if hasAddHandler {
					break
				}
				if expectCol, ok := maybeTables[pos.Line]; ok && expectCol == pos.Column {
					instrumentTableDrivenHandler(n)
					hasAddHandler = true
				}
			}
		}
		return true

	})
	return hasAddHandler
}

func (p *Composer) handleTableDriven(f *ast.File) bool {
	l_res := false
	hash := ""
	mi := p.metainfo
	for _, f := range p.parseResult.Funcs {
		if f.Name == mi.Name {
			hash = f.TableDataName
		}
	}
	if hash != "" {
		// fmt.Fprintf(os.Stderr, "[+]%s, a table driven test case\n", mi.Name)
	} else {
		return l_res
	}

	var fDeclFuzz *ast.FuncDecl
	fDeclFuzz = nil
	for _, decl := range f.Decls {
		if fdecl, ok := decl.(*ast.FuncDecl); ok {
			if strings.HasPrefix(fdecl.Name.Name, "Fuzz") {
				fDeclFuzz = fdecl
			}
		}
	}
	if fDeclFuzz == nil {
		return l_res
	}

	instrumentHandlerToRange := func(rangeStmt *ast.RangeStmt) {
		body := &ast.BlockStmt{List: []ast.Stmt{}}
		body.List = append(body.List, &ast.BranchStmt{Tok: token.BREAK})

		ifStmt := &ast.IfStmt{Cond: ast.NewIdent("skippingTableDriven"), Body: body}
		rangeStmt.Body.List = append(rangeStmt.Body.List, ifStmt)
	}
	ast.Inspect(fDeclFuzz, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.RangeStmt:
			curHash := fmt.Sprintf("%v", n.X)
			if curHash == hash {
				instrumentHandlerToRange(n)
				l_res = true
			}
		}
		return true
	})
	return l_res
}

func (p *Composer) transformTestBodyV2(f *ast.File, fDeclFuzz *ast.FuncDecl, testInputs []*models.Variable, fset *token.FileSet) {
	// modifyingFilePool := make(map[string][]*metainfo.VariableGlobalSourceInfo, 0)
	// varCandidate := make(map[string]*metainfo.VariableConstSourceInfo)
	mi := p.metainfo
	varCandidate := make(map[string]interface{})
	globalCandidate := make(map[string]*metainfo.VariableGlobalSourceInfo)

	getLocKey := func(obj interface{}) string {
		var key string
		switch v := obj.(type) {
		// case from metainfo
		case metainfo.VariableMetaInfo:
			// an immediate arg of call
			// use the location of call instead of arg as key
			varsrcpath := mi.SrcPath
			key = fmt.Sprintf("%s:%d:%d", filepath.Base(varsrcpath), v.CallLine, v.CallColum)
		case *metainfo.VariableConstSourceInfo:
			if v.IsImmediateVariable {
				varsrcpath := v.VariableSrcPath
				key = fmt.Sprintf("%s:%d:%d", filepath.Base(varsrcpath), v.CallLine, v.CallColum)
			} else {
				varsrcpath := v.VariableSrcPath
				key = fmt.Sprintf("%s:%d:%d", filepath.Base(varsrcpath), v.SourceLine, v.SourceColumn)
			}
		case *metainfo.VariableGlobalSourceInfo:
			//TODO(jx): global var from other pkg, it is hard to handle
			varsrcpath := v.GlobalSrcPath
			key = fmt.Sprintf("%s:%d:%d", filepath.Base(varsrcpath), v.SourceLine, v.SourceColumn)

		}
		return key
	}
	checkNodeShouldFuzz := func(node ast.Node) (metainfo interface{}, ok bool) {
		if node == nil || node == (*ast.File)(nil) || !node.Pos().IsValid() {
			return nil, false
		}

		var pos token.Position
		switch realn := node.(type) {
		case *ast.KeyValueExpr:
			pos = fset.Position(realn.Colon)
		case *ast.AssignStmt:
			if lselector, ok := realn.Lhs[0].(*ast.SelectorExpr); ok {
				pos = fset.Position(lselector.Sel.Pos())
			} else {
				pos = fset.Position(realn.TokPos)
			}

		case *ast.CallExpr:
			pos = fset.Position(realn.Lparen)
		default:
			pos = fset.Position(node.Pos())
		}

		origFilename := strings.Split(filepath.Base(pos.Filename), "test.go")[0] + "test.go"
		key := fmt.Sprintf("%s:%d:%d", origFilename, pos.Line, pos.Column)
		obj, ok := varCandidate[key]
		if ok {
			return obj, ok
		}

		obj, ok = globalCandidate[key]
		return obj, ok
	}

	generateGetFuzzDataNode := func(targetNode ast.Node, varInfo interface{}) (res *ast.CallExpr) {
		// TODO(jx): targetVar should be an interface to support more types
		generateGetFuzzDataForGeneralCoreNeo := func(vcsi *metainfo.VariableConstSourceInfo) *ast.CallExpr {
			var res *ast.CallExpr
			//fmt.Println("[+]Printing type", pv.Type) //nil?
			//fmt.Println(reflect.TypeOf(pv.Value))
			res = &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("transstruct")}}
			list := strings.Split(vcsi.ConstValue, ":")
			typeName := list[len(list)-1]
			switch typeName {
			case "bool":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetBool")}
			case "byte":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint8")}
			case "bytes":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetBytes")}
			case "int8":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt8")}
			case "int16":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt16")}
			case "int32":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt32")}
			case "int64":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt64")}
			case "string":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetStringWithAlias")}
			case "uint8":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint8")}
			case "uint16":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint16")}
			case "uint32":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint32")}
			case "uint64":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint64")}
			case "int":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt")}
			case "uint":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint")}
			case "float64":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat64")}
			case "float32":
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat32")}
			default:
				fmt.Println("[-]Exception: unknown fuzz type", typeName)
				return nil
			}
			return res
		}
		generateGetFuzzDataForGeneralCore := func(ft metainfo.FuzzType) *ast.CallExpr {
			var res *ast.CallExpr
			//fmt.Println("[+]Printing type", pv.Type) //nil?
			//fmt.Println(reflect.TypeOf(pv.Value))

			res = &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("transstruct")}}
			switch ft {
			case metainfo.FuzzableBool:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetBool")}
			case metainfo.FuzzableBytes:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetBytes")}
			case metainfo.FuzzableInt8:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt8")}
			case metainfo.FuzzableInt16:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt16")}
			case metainfo.FuzzableInt32:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt32")}
			case metainfo.FuzzableInt64:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt64")}
			case metainfo.FuzzableString:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetString")}
			case metainfo.FuzzableUint8:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint8")}
			case metainfo.FuzzableUint16:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint16")}
			case metainfo.FuzzableUint32:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint32")}
			case metainfo.FuzzableUint64:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint64")}
			case metainfo.FuzzableInt:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt")}
			case metainfo.FuzzableUint:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint")}
			case metainfo.FuzzableFloat64:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat64")}
			case metainfo.FuzzableFloat32:
				res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat32")}
			default:
				fmt.Println("[-]Exception: unknown fuzz type", ft)
				return nil
			}
			return res
		}

		switch node := targetNode.(type) {
		case *ast.BasicLit:
			switch info := varInfo.(type) {
			case metainfo.VariableConstSourceInfo:
				if res = generateGetFuzzDataForGeneralCoreNeo(&info); res != nil {
					if res.Fun.(*ast.SelectorExpr).Sel.Name == "GetStringWithAlias" {
						if len(info.MustAlias) > 0 {
							res.Args = []ast.Expr{node, ast.NewIdent("true")}
						} else {
							res.Args = []ast.Expr{node, ast.NewIdent("false")}
						}
					} else {
						res.Args = []ast.Expr{node}
					}

				}
			}
		case *ast.CallExpr:
			switch info := varInfo.(type) {
			case metainfo.VariableMetaInfo:
				fuzztype := info.VarType
				if fuzztype == metainfo.UnKnown {
					return nil
				}
				if res = generateGetFuzzDataForGeneralCore(info.VarType); res != nil {
					res.Args = []ast.Expr{node.Args[info.ArgIndex]}
				}

			case metainfo.VariableConstSourceInfo:
				if res = generateGetFuzzDataForGeneralCoreNeo(&info); res != nil {
					if res.Fun.(*ast.SelectorExpr).Sel.Name == "GetStringWithAlias" {
						if len(info.MustAlias) > 0 {
							res.Args = []ast.Expr{node.Args[info.ArgIndex], ast.NewIdent("true")}
						} else {
							res.Args = []ast.Expr{node.Args[info.ArgIndex], ast.NewIdent("false")}
						}
					} else {
						res.Args = []ast.Expr{node.Args[info.ArgIndex]}
					}
				}
			}
		}
		return res

	}

	for _, argVar := range mi.VariableList {
		// collect all vars need to be fuzzed, and store them with key generated from the location of the variable

		// if IsImmediateVariable, loc is the loc of call
		// else if not IsImmediateVariable, loc is the loc of  :/:=/call
		if argVar.IsImmediateVariable {
			//TODO(jx): if call has more than 1 immediate variable, it will be overwriten
			key := getLocKey(argVar)
			varCandidate[key] = argVar
		} else {
			for _, relatedVar := range argVar.VarRelatedConstSources {
				key := getLocKey(&relatedVar)
				varCandidate[key] = relatedVar
			}
			// TODO(jx): global var
			if *flagFuzzGlobalVar {
				// TODO(jx): collect key for global var
				for _, globalVar := range argVar.VarRelatedGlobalSources {
					key := getLocKey(&globalVar)
					globalCandidate[key] = &globalVar
				}
			}
		}
	}
	var stack []ast.Node

	ast.Inspect(fDeclFuzz, func(node ast.Node) bool {
		//key:value	*ast.KeyValueExpr
		//:=		*ast.AssignStmt
		//return	*ast.ReturnStmt
		//callsite	*ast.CallExpr
		//field:	*ast.KeyValueExpr
		switch n := node.(type) {
		// targetInfo has 3 cases:
		//1. immediate arg of a call, targetInfo is the call itself
		//2. related var of an arg in call, but the related var is also a call, like []byte(), the targetInfo is that call
		//3. related var of an arg in call, and the related var is a normal var, the targetInfo is basiclit
		//4. related var of an arg in call, and the related var is a member of struct, the targetInfo is the last selecorExpr, like a.b.c = 10, its loc is c' loc
		case *ast.BasicLit:
			if targetInfo, ok := checkNodeShouldFuzz(n); ok {
				if getFuzzDataNode := generateGetFuzzDataNode(n, targetInfo); getFuzzDataNode != nil {
					parentNode := stack[len(stack)-1]
					switch p := parentNode.(type) {
					case *ast.CompositeLit:
						//"0403060130" in : marshalTest{		{[]byte("\x06\x01\x30"), "0403060130"},
						for idx, elt := range p.Elts {
							if elt == n {
								p.Elts[idx] = getFuzzDataNode
								break
							}
						}

					case *ast.KeyValueExpr:
						if n == p.Value {
							p.Value = getFuzzDataNode
						}
					case *ast.AssignStmt:
						for rhIdx, rh := range p.Rhs {
							if rh == n {
								p.Rhs[rhIdx] = getFuzzDataNode
								break
							}
						}
					case *ast.BinaryExpr:
						// judge n is left node or right node
						if x, ok := p.X.(*ast.BasicLit); ok && x == n {
							p.X = getFuzzDataNode
						} else if y, ok := p.Y.(*ast.BasicLit); ok && y == n {
							p.Y = getFuzzDataNode
						}

					}
				}
			}
		case *ast.KeyValueExpr:
			// field or a map
			if targetInfo, ok := checkNodeShouldFuzz(n); ok {
				getFuzzDataNode := generateGetFuzzDataNode(n.Value, targetInfo)
				if getFuzzDataNode != nil {
					n.Value = getFuzzDataNode
				}
			}
		case *ast.AssignStmt:
			// TODO(jx): find right rhIdx
			if targetInfo, ok := checkNodeShouldFuzz(n); ok {
				getFuzzDataNode := generateGetFuzzDataNode(n.Rhs[0], targetInfo)
				if getFuzzDataNode != nil {
					n.Rhs[0] = getFuzzDataNode
				}
			}
		case *ast.CallExpr:
			if targetInfo, ok := checkNodeShouldFuzz(n); ok {
				switch info := targetInfo.(type) {
				case metainfo.VariableMetaInfo:
					// immediate arg of a call
					getFuzzDataNode := generateGetFuzzDataNode(n, targetInfo)
					if getFuzzDataNode != nil {
						n.Args[info.ArgIndex] = getFuzzDataNode
					}
				case metainfo.VariableConstSourceInfo:
					// arg of a call, but the arg is also a call
					getFuzzDataNode := generateGetFuzzDataNode(n, targetInfo)
					if getFuzzDataNode != nil {
						n.Args[info.ArgIndex] = getFuzzDataNode
					}
				}
			}
		}
		if node == nil {
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, node)
		}
		return true
	})

	// fuzz global vars in many other test.go files,even from other packages
	// ~~if exists, copy it bak and rewrite it with fuzz data recover them when compiling is finished~~
	// new solution: collect all global var name and assign them in a new function

	collectGlobal := func(candidateGlobals map[string]*metainfo.VariableGlobalSourceInfo) map[string]*ast.Ident {
		globalVars := make(map[string]*ast.Ident)
		for key, globalmeta := range candidateGlobals {
			relatedFile := globalmeta.GlobalSrcPath
			globalF, err := parser.ParseFile(fset, relatedFile, nil, parser.ParseComments)
			if err != nil {
				continue
			}

			ast.Inspect(globalF, func(node ast.Node) bool {
				if _, ok := checkNodeShouldFuzz(node); ok {
					switch n := node.(type) {
					// TODO(jx): is this the only type?
					case *ast.Ident:
						globalVars[key] = n
					default:
						fmt.Println("other type for global var", n)

					}
				}

				return true
			})
		}

		return globalVars
	}

	if *flagFuzzGlobalVar {
		// for global vars declared in p.filepath, inspect it just in p.filepath and needn't rewrite test.go
		// setGlobalVariableV2(f)
		// collect vars objects
		// TODO(jx): only self global var can be fuzzed tmply
		globalvars := collectGlobal(globalCandidate)
		_ = globalvars
		// generate assign statement for each var in a new function template
		addedFunc := new(ast.FuncDecl)

		addedFunc.Name = &ast.Ident{Name: fdg_globalFuncName}
		addedFunc.Type = &ast.FuncType{Params: &ast.FieldList{}, Results: &ast.FieldList{}}
		addedFunc.Body = &ast.BlockStmt{List: make([]ast.Stmt, 0)}
		// DONE(jx): fixme
		for key, globalIdent := range globalvars {
			// lhs := &ast.Ident{Name: node.(*ast.Ident).Name}
			if getFuzzDataNode := generateGetFuzzDataCall(globalCandidate[key]); getFuzzDataNode != nil {
				getFuzzDataNode.Args = append(getFuzzDataNode.Args, globalIdent)
				addedFunc.Body.List = append(addedFunc.Body.List, &ast.AssignStmt{
					Lhs: []ast.Expr{globalIdent},
					Rhs: []ast.Expr{getFuzzDataNode},
					Tok: token.ASSIGN,
				})
			}

		}

		f.Decls = append(f.Decls, addedFunc)

	}

}

func generateGetFuzzDataCall(info interface{}) *ast.CallExpr {
	res := &ast.CallExpr{}
	typeStr2FuzzAPIstr := make(map[string]string)
	fuzzType2FuzzAPIstr := make(map[metainfo.FuzzType]string)

	switch realinfo := info.(type) {
	case *metainfo.VariableConstSourceInfo:
		list := strings.Split(realinfo.ConstValue, ":")
		typename := list[len(list)-1]
		if apistr, ok := typeStr2FuzzAPIstr[typename]; ok {
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent(apistr)}
		} else {
			fmt.Println(fmt.Println("[-]Exception: unknown fuzz type:", typename))
		}

	case metainfo.FuzzType:
		if apistr, ok := fuzzType2FuzzAPIstr[realinfo]; ok {
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent(apistr)}
		} else {
			fmt.Println(fmt.Println("[-]Exception: unknown fuzz type:", realinfo))
		}
	case *metainfo.VariableGlobalSourceInfo:
		typename := realinfo.GlobalType
		if apistr, ok := typeStr2FuzzAPIstr[typename]; ok {
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent(apistr)}
		} else {
			fmt.Println(fmt.Println("[-]Exception: unknown fuzz type:", typename))
		}
	}
	if res.Fun == nil {
		return nil
	}
	return res

}

func transformTestBody(fDeclFuzz *ast.FuncDecl, testInputs []*models.Variable, mi *metainfo.TestCaseMetaInfo, fset *token.FileSet) {
	transformAssignstmtInput := func(fDeclFuzz *ast.FuncDecl, testInput *models.Variable) {
		//fmt.Println("transformAssignstmtInput", testInput.Name, testInput.Value)
		var handleStmtList func(stmts []ast.Stmt)
		handleStmtList = func(stmts []ast.Stmt) { //till now transforming not modify stmt
			for _, stmt := range stmts {
				switch s := stmt.(type) {
				case *ast.AssignStmt:
					if idt, ok := s.Lhs[0].(*ast.Ident); ok {
						if idt.Name == testInput.Name {
							node := generateDataInterfaceASTNode(testInput)
							if node != nil {
								s.Rhs = []ast.Expr{node}
							}
						}
					}
				case *ast.BlockStmt:
					handleStmtList(s.List)
				}
			}
		}
		handleStmtList(fDeclFuzz.Body.List)
	}
	_ = transformAssignstmtInput
	transformImmediateInput := func(fDeclFuzz *ast.FuncDecl, testInput *models.Variable, mi *metainfo.TestCaseMetaInfo) {
		//fmt.Println("transformImmediateInput", testInput.Name, testInput.Value)
		interfaceAnalysisAgree := func(curCallee string, argIndex int, mi *metainfo.TestCaseMetaInfo) bool { //TODO
			_ = curCallee
			_ = argIndex
			for _, v := range mi.VariableList {
				if v.ArgIndex == argIndex && v.Callee == curCallee {
					return true
				}
			}
			return false
		}
		var handleStmtList func(stmts []ast.Stmt)
		handleStmtList = func(stmts []ast.Stmt) { //till now transforming not modify stmt

			var ceFinder func(ce *ast.CallExpr, calleeName string) *ast.CallExpr
			ceFinder = func(ce *ast.CallExpr, calleeName string) *ast.CallExpr {
				switch callee := ce.Fun.(type) {
				case *ast.SelectorExpr:
					if callee.Sel.Name == calleeName {
						return ce
					}
				case *ast.Ident:
					if callee.Name == calleeName {
						return ce
					}
				}
				for _, arg := range ce.Args {
					switch ae := arg.(type) {
					case *ast.CallExpr:
						return ceFinder(ae, calleeName)
					}
				}
				return nil
			}

			for _, stmt := range stmts { //if funcdecl has more stmt than funclit?
				switch s := stmt.(type) {
				case *ast.ExprStmt:
					if ce, ok := s.X.(*ast.CallExpr); ok {
						inputInfo := testInput.Name[1:]
						curCallee := inputInfo[0:strings.LastIndex(inputInfo, "$")]
						argIndex := inputInfo[strings.LastIndex(inputInfo, "$")+1:]
						ai, err := strconv.Atoi(argIndex)
						if err != nil {
							panic(err)
						}
						//fmt.Println("curCallee", curCallee)
						handleCe := ceFinder(ce, curCallee)
						if handleCe != nil {
							//fmt.Println(reflect.TypeOf(handleCe))
							if !interfaceAnalysisAgree(curCallee, ai, mi) {
								continue
							}
							dataInterfaceNode := generateDataInterfaceASTNode(testInput)
							if dataInterfaceNode != nil {
								handleCe.Args[ai] = dataInterfaceNode
							}
						}
					}
				case *ast.BlockStmt:
					handleStmtList(s.List)
				}
			}
		}
		handleStmtList(fDeclFuzz.Body.List)
	}
	_ = transformImmediateInput
	generateGetFuzzDataForGeneralCore := func(ft metainfo.FuzzType) *ast.CallExpr {
		var res *ast.CallExpr
		//fmt.Println("[+]Printing type", pv.Type) //nil?
		//fmt.Println(reflect.TypeOf(pv.Value))
		res = &ast.CallExpr{}
		res = &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("transstruct")}}
		switch ft {
		case metainfo.FuzzableBytes:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetBytes")}
		case metainfo.FuzzableInt8:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt8")}
		case metainfo.FuzzableInt16:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt16")}
		case metainfo.FuzzableInt32:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt32")}
		case metainfo.FuzzableInt64:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt64")}
		case metainfo.FuzzableString:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetString")}
		case metainfo.FuzzableUint8:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint8")}
		case metainfo.FuzzableUint16:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint16")}
		case metainfo.FuzzableUint32:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint32")}
		case metainfo.FuzzableUint64:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint64")}
		case metainfo.FuzzableInt:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt")}
		case metainfo.FuzzableUint:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint")}
		case metainfo.FuzzableFloat64:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat64")}
		case metainfo.FuzzableFloat32:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat32")}
		default:
			panic("[-]Exception: unknown fuzz type")
		}
		return res
	}
	generateGetFuzzDataForGeneralCoreNeo := func(vcsi *metainfo.VariableConstSourceInfo) *ast.CallExpr {
		var res *ast.CallExpr
		//fmt.Println("[+]Printing type", pv.Type) //nil?
		//fmt.Println(reflect.TypeOf(pv.Value))
		res = &ast.CallExpr{}
		res = &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("transstruct")}}
		list := strings.Split(vcsi.ConstValue, ":")
		typeName := list[len(list)-1]
		switch typeName {
		case "byte":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint8")}
		case "bytes":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetBytes")}
		case "int8":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt8")}
		case "int16":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt16")}
		case "int32":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt32")}
		case "int64":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt64")}
		case "string":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetString")}
		case "uint8":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint8")}
		case "uint16":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint16")}
		case "uint32":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint32")}
		case "uint64":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint64")}
		case "int":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt")}
		case "uint":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint")}
		case "float64":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat64")}
		case "float32":
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat32")}
		default:
			fmt.Println("[-]Exception: unknown fuzz type", typeName)
			return nil
		}
		return res
	}

	generateGetFuzzDataForGeneralCase := func(bl *ast.BasicLit, ft metainfo.FuzzType) *ast.CallExpr {
		if ft == metainfo.UnKnown {
			return nil
		}
		res := generateGetFuzzDataForGeneralCore(ft)
		if res == nil {
			return res
		}
		res.Args = []ast.Expr{bl}
		return res
	}
	_ = generateGetFuzzDataForGeneralCase
	generateGetFuzzDataForGeneralCaseNeo := func(bl *ast.BasicLit, ft metainfo.FuzzType, vcsi *metainfo.VariableConstSourceInfo) *ast.CallExpr {
		//if ft == metainfo.UnKnown{//in neo ft is useless
		//	return nil
		//}
		//res := generateGetFuzzDataForGeneralCore(ft)
		res := generateGetFuzzDataForGeneralCoreNeo(vcsi)
		if res == nil {
			return res
		}
		res.Args = []ast.Expr{bl}
		return res
	}
	generateGetFuzzDataForImmediateValueCase := func(expr *ast.Expr, ft metainfo.FuzzType) *ast.CallExpr {
		if ft == metainfo.UnKnown {
			return nil
		}
		res := generateGetFuzzDataForGeneralCore(ft)
		res.Args = []ast.Expr{*expr}
		return res
	}

	var stack []ast.Node
	ast.Inspect(fDeclFuzz, func(node ast.Node) bool {
		//key:value	*ast.KeyValueExpr
		//:=		*ast.AssignStmt
		//return	*ast.ReturnStmt
		//callsite	*ast.CallExpr
		//field:	*ast.KeyValueExpr
		relatedVariableInfo := func(stack []ast.Node, vms []metainfo.VariableMetaInfo) (int, int) {
			res := 0
			subtype := 0
			for vmIndex, vm := range vms {
				for _, node := range stack {
					if vm.IsImmediateVariable {
						if ce, ok := node.(*ast.CallExpr); ok {
							foundCallee := false
							curCallee := ""

							vmCallee := vm.Callee[strings.LastIndex(vm.Callee, ".")+1:]
							ast.Inspect(ce.Fun, func(nn ast.Node) bool {
								if ident, ok := nn.(*ast.Ident); ok {
									curCallee = ident.String()
									if curCallee == vmCallee {
										foundCallee = true
									}
								}
								return true
							})
							if foundCallee {
								return vmIndex, subtype
							}
						}
					} else {
						fixPos := func(fixingNode ast.Node) token.Pos {
							switch n := fixingNode.(type) {
							case *ast.KeyValueExpr:
								return n.Colon
							case *ast.AssignStmt:
								return n.Lhs[0].Pos()
							}
							return fixingNode.Pos()
						}
						fixedPos := fixPos(node)

						//curPos := fset.Position(node.Pos())
						curPosition := fset.Position(fixedPos)
						//fmt.Println("fixing Position", fset.Position(node.Pos()))
						//fmt.Println("fixed Position", curPosition)
						column := curPosition.Column
						line := curPosition.Line
						for sourceIdx, source := range vm.VarRelatedConstSources {
							if column == source.SourceColumn && line == source.SourceLine {
								return vmIndex, sourceIdx
							}
						}
					}
				}
				res += 1
			}
			return res, subtype
		}

		//core
		variableCount := len(mi.VariableList)
		if len(stack) != 0 {
			parentNode := stack[len(stack)-1]
			remove := func(s []metainfo.VariableMetaInfo, i int) []metainfo.VariableMetaInfo {
				s[i] = s[len(s)-1]
				return s[:len(s)-1]
			}
			_ = remove
			switch n := node.(type) {
			case *ast.BasicLit:
				variableIndex, sourceIdx := relatedVariableInfo(stack, mi.VariableList)
				if variableIndex < variableCount {
					switch pn := parentNode.(type) {
					case *ast.KeyValueExpr:
						//bl of key or bl of value
						//field is simple
						//map is complex
						if n == pn.Value {
							//getFuzzDataNode := generateGetFuzzDataForGeneralCase(n, mi.VariableList[variableIndex].VarType)
							getFuzzDataNode := generateGetFuzzDataForGeneralCaseNeo(n, mi.VariableList[variableIndex].VarType, &mi.VariableList[variableIndex].VarRelatedConstSources[sourceIdx])
							if getFuzzDataNode != nil {
								pn.Value = getFuzzDataNode
							}
						}
					case *ast.AssignStmt:
						for rhIdx, rh := range pn.Rhs {
							if rh == n {
								//getFuzzDataNode := generateGetFuzzDataForGeneralCase(n, mi.VariableList[variableIndex].VarType)
								getFuzzDataNode := generateGetFuzzDataForGeneralCaseNeo(n, mi.VariableList[variableIndex].VarType, &mi.VariableList[variableIndex].VarRelatedConstSources[sourceIdx])
								if getFuzzDataNode != nil {
									pn.Rhs[rhIdx] = getFuzzDataNode
								}
							}
						}
					}
					remove(mi.VariableList, variableIndex)
				}

			case *ast.CallExpr:
				variableIndex, _ := relatedVariableInfo([]ast.Node{n}, mi.VariableList)
				if f, ok := n.Fun.(*ast.Ident); ok {
					if isBasicType(f.String()) { //temp solution
						parentNode := stack[len(stack)-1]
						variableIndex, sourceIdx := relatedVariableInfo(stack, mi.VariableList)

						if variableIndex < variableCount {
							switch pn := parentNode.(type) {
							case *ast.KeyValueExpr:
								//bl of key or bl of value
								//field is simple
								//map is complex
								if n == pn.Value {
									//getFuzzDataNode := generateGetFuzzDataForGeneralCase(n, mi.VariableList[variableIndex].VarType)
									getFuzzDataNode := generateGetFuzzDataForGeneralCaseNeo(n.Args[0].(*ast.BasicLit), mi.VariableList[variableIndex].VarType, &mi.VariableList[variableIndex].VarRelatedConstSources[sourceIdx])
									if getFuzzDataNode != nil {
										pn.Value = getFuzzDataNode
									}
								}
							case *ast.AssignStmt:
								for rhIdx, rh := range pn.Rhs {
									if rh == n {
										//getFuzzDataNode := generateGetFuzzDataForGeneralCase(n, mi.VariableList[variableIndex].VarType)
										getFuzzDataNode := generateGetFuzzDataForGeneralCaseNeo(n.Args[0].(*ast.BasicLit), mi.VariableList[variableIndex].VarType, &mi.VariableList[variableIndex].VarRelatedConstSources[sourceIdx])
										if getFuzzDataNode != nil {
											pn.Rhs[rhIdx] = getFuzzDataNode
										}
									}
								}
							}
							remove(mi.VariableList, variableIndex)
							variableCount = -1
						}
					}
				}
				if variableIndex < variableCount {
					variable := mi.VariableList[variableIndex]
					for argIdx, arg := range n.Args {
						if argIdx == variable.ArgIndex {
							getFuzzDataNode := generateGetFuzzDataForImmediateValueCase(&arg, mi.VariableList[variableIndex].VarType)
							if getFuzzDataNode != nil {
								n.Args[argIdx] = getFuzzDataNode
							}
						}
					}
					remove(mi.VariableList, variableIndex)
				}
				//remove(mi.VariableList, variableIndex)
			}

		}
		if node == nil {
			// Done with node's children. Pop.
			stack = stack[:len(stack)-1]
		} else {
			// Push the current node for children.
			stack = append(stack, node)
		}
		return true
	})
	//for _, v := range testInputs{
	//	//fmt.Println("testing input", v.Name)
	//	if strings.Contains(v.Name, "$"){//case immediate value
	//		transformImmediateInput(fDeclFuzz, v, mi)
	//	} else{//case assignment
	//		transformAssignstmtInput(fDeclFuzz, v)
	//	}
	//}
}

func generateArgsForAdd(addIndex int, mi *metainfo.TestCaseMetaInfo) []ast.Expr {
	res := []ast.Expr{}

	for _, v := range mi.VariableList {
		bl := new(ast.BasicLit)
		switch v.VarType {
		case metainfo.FuzzableString:
			//key of add new fuzzable argument
			bl.Kind = token.STRING
			//bl.Value = "\"" + v.VarValue[addIndex] + "\""
			bl.Value = "\"" + v.VarName + "\""
		}
		res = append(res, bl) //why we can append instance to pointer array?
	}

	return res
}

func appendAdd(fuzzFunc *ast.FuncDecl, mi *metainfo.TestCaseMetaInfo) {
	//for 1.18
	//for _, stmt := range fuzzFunc.Body.List{
	//	switch s := stmt.(type){
	//	case *ast.ExprStmt:
	//		if ce, ok := s.X.(*ast.CallExpr); ok {
	//			fmt.Println(ce.Args)
	//			for _, arg := range ce.Args{
	//				fmt.Println(reflect.TypeOf(arg))
	//				switch av := arg.(type) {
	//				case *ast.BasicLit:
	//					fmt.Println(av.Kind, av.Value)
	//				}
	//			}
	//		}
	//	}
	//}
	es := new(ast.ExprStmt)

	es.X = &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("f"), Sel: ast.NewIdent("Add")}, Args: generateArgsForAdd(0, mi)} //TODO literating multiple value
	fuzzFunc.Body.List = append([]ast.Stmt{es}, fuzzFunc.Body.List...)
}

func (p *Composer) TransformV2(f *ast.File, tmpFuzzFile string, fset *token.FileSet) ([]byte, error) {
	testFunctionName := p.metainfo.Name
	var targetFuzzFunction *ast.FuncDecl
	for _, d := range f.Decls {
		fDecl, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fDecl.Name.String() == testFunctionName {
			targetFuzzFunction = fDecl
		}
	}
	p.clearComment(f)
	_ = p.constAlias(targetFuzzFunction, fset)
	hasHandleTableDriven := p.handleTableDrivenV2(targetFuzzFunction, fset)
	if hasHandleTableDriven {
		fmt.Println("[+] Has add a table driven handler")
	}

	p.transformTestBodyV2(f, targetFuzzFunction, nil, fset)
	// removeFatalAPI(targetFuzzFunction)

	buf := new(bytes.Buffer)
	renderAST(buf, fset, f)
	ioutil.WriteFile(tmpFuzzFile, buf.Bytes(), 0666)
	defer os.Remove(tmpFuzzFile)

	newFuzzFuncBytes := GetDockToGoFuzz(testFunctionName, tmpFuzzFile)

	return newFuzzFuncBytes, nil

}

func (p *Composer) Transform(f *ast.File, mi *metainfo.TestCaseMetaInfo, fset *token.FileSet) ([]byte, error) {

	stripRedundantCode := func(f *ast.File, fuzzFunc *ast.FuncDecl, mi *metainfo.TestCaseMetaInfo) {
		//fuzzFunctionName := "Fuzz" + mi.Name
		fuzzFunctionName := mi.Name
		keptDecl := []ast.Decl{}
		for _, d := range f.Decls {
			fDecl, ok := d.(*ast.FuncDecl)
			if !ok {
				keptDecl = append(keptDecl, d)
			} else if fDecl.Name.String() == fuzzFunctionName {
				keptDecl = append(keptDecl, fDecl)
			}
		}
		f.Decls = keptDecl

		Xs := map[string]bool{}
		ast.Inspect(fuzzFunc, func(node ast.Node) bool {

			switch n := node.(type) {
			case *ast.SelectorExpr:
				switch x := n.X.(type) {
				case *ast.Ident:
					Xs[x.String()] = true
				}
			}
			return true
		})
		for idx, imp := range f.Imports {
			impPath := imp.Path.Value
			impPath = strings.ReplaceAll(impPath, "\"", "")
			pkg := impPath[strings.LastIndex(impPath, "/")+1:]
			//fmt.Println(Xs, pkg)
			if _, ok := Xs[pkg]; ok {
				//fmt.Println("importing", imp.Path.Value)
			} else {
				f.Imports[idx].Name = ast.NewIdent("_")
			}
		}

		//impDecl := &ast.GenDecl{
		//	Lparen: af.Name.End(),
		//	Tok:    token.IMPORT,
		//	Specs: []ast.Spec{
		//		newImport,
		//	},
		//	Rparen: af.Name.End(),
		//}

	}

	removeNonReturningOracle := func(fuzzFunc *ast.FuncDecl) {
		SelBlackList := map[string]bool{"Fatal": true, "FatalF": true, "FailNow": true}
		XBlackList := map[string]bool{"assert": true}
		newStmts := []ast.Stmt{}

		for _, stmt := range fuzzFunc.Body.List {
			switch s := stmt.(type) {
			case *ast.ExprStmt:
				if ce, ok := s.X.(*ast.CallExpr); ok {
					if selector, sok := ce.Fun.(*ast.SelectorExpr); sok {
						if _, ok := SelBlackList[selector.Sel.String()]; ok {
							continue
						}
						switch x := selector.X.(type) {
						case *ast.Ident:
							if _, ok := XBlackList[x.String()]; ok {
								continue
							}
						}
					}
				}
			}
			newStmts = append(newStmts, stmt)
		}
		fuzzFunc.Body.List = newStmts
	}
	//fuzzFunctionName := "Fuzz" + mi.Name
	fuzzFunctionName := mi.Name
	//fmt.Fprintln(os.Stderr, "[+]Transforming fuzz driver", fuzzFunctionName)
	var targetFuzzFunction *ast.FuncDecl
	//var origTestCaseFunction *ast.FuncDecl
	for _, d := range f.Decls {
		fDecl, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fDecl.Name.String() == fuzzFunctionName {
			targetFuzzFunction = fDecl
		}
	}
	getCurrentFuncTestInputs := func(p *Composer, mi *metainfo.TestCaseMetaInfo) []*models.Variable {
		for _, f := range p.parseResult.Funcs {
			if f.Name == mi.Name {
				return f.TestInputs
			}
		}
		return nil
	}
	curTestInputs := getCurrentFuncTestInputs(p, mi)
	//transform for Fuzz call back
	//transformFuzzCallBack(targetFuzzFunction, mi)
	transformTestBody(targetFuzzFunction, curTestInputs, mi, fset)
	//stripRedundantCode(f, targetFuzzFunction, mi)

	_ = stripRedundantCode
	_ = removeNonReturningOracle
	//removeNonReturningOracle(targetFuzzFunction)

	//transform for add init corpus
	//appendAdd(targetFuzzFunction, mi)

	// /*DONE(jx): force the package name not end with _test*/
	// DONE(jx)2: ignore potential package error here, and fix it when copying test
	// f.Name.Name = strings.TrimSuffix(f.Name.Name, "_test")
	return nil, nil
}

func GetDockToGoFuzz(testName, filepath string) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}
	var targetFuzzFunction *ast.FuncDecl
	var globalFunction *ast.FuncDecl
	for _, d := range f.Decls {
		if fDecl, ok := d.(*ast.FuncDecl); ok {
			if fDecl.Name.String() == testName {
				targetFuzzFunction = fDecl
			}
			if fDecl.Name.String() == fdg_globalFuncName {
				globalFunction = fDecl
			}
		}
	}
	newBody := parseFuncBody(targetFuzzFunction, filepath)
	globalFuncBody := make([]byte, 0)
	if *flagFuzzGlobalVar {
		if globalFunction == nil {
			panic("the global flag is set but global func not found")
		}
		globalFuncBody = parseFuncBody(globalFunction, filepath)

	}

	generateRandomString := func(n int) string {
		var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		b := make([]rune, n)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		return string(b)
	}

	t := fuzzSrc
	dot := map[string]interface{}{"TestName": testName,
		"Body":           string(newBody),
		"FuzzDataName":   generateRandomString(3),
		"globalFuncName": fdg_globalFuncName,
		"globalFuncBody": string(globalFuncBody),
	}
	// buf is the fuzz driver body
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, dot); err != nil {
		panic("GenerateOneFunc")
	}

	return buf.Bytes()
}

func fixReturn(file *ast.File) {
	for _, decl := range file.Decls {
		if targetF, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(targetF.Name.String(), "Fuzz") {
			for _, stmt := range targetF.Body.List {
				ast.Inspect(stmt, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.FuncLit: //TODO(jx): may add more cases
						return false
					case *ast.ReturnStmt:
						if len(x.Results) == 0 {
							// fmt.Println("[-] Return value not found")
							x.Results = append(x.Results, &ast.BasicLit{
								Kind:  token.INT,
								Value: "0",
							})
						}
						return false
					}
					return true
				})
			}
		}
	}
}

func fixImport(testF, newFuzzF *ast.File) {

	addImport := func(astFile *ast.File, path, name string) {
		var impDecl *ast.GenDecl
		if _, ok := astFile.Decls[0].(*ast.GenDecl); ok {
			// exist import
		} else {
			// add a new import
			newDecl := &ast.GenDecl{
				Lparen: astFile.Name.End(),
				Tok:    token.IMPORT,
				Specs:  []ast.Spec{},
				Rparen: astFile.Name.End(),
			}
			astFile.Decls = append([]ast.Decl{newDecl}, astFile.Decls...)
		}
		newImport := &ast.ImportSpec{
			Name: ast.NewIdent(name),
			Path: &ast.BasicLit{
				Kind:  token.STRING,
				Value: fmt.Sprintf("%q", path),
			},
		}
		impDecl = astFile.Decls[0].(*ast.GenDecl)
		impDecl.Specs = append(impDecl.Specs, newImport)
		astFile.Imports = append(astFile.Imports, newImport)

		astFile.Decls[0] = impDecl
	}

	allImports := make(map[string]*ast.ImportSpec)
	for idx, im := range testF.Imports {
		importName := ""
		if im.Name != nil {
			importName = im.Name.Name
		} else {
			// take attention as
			// import abc.com/xxx.v1
			// import abc.com/xxx/v2
			terms := strings.Split(im.Path.Value[1:len(im.Path.Value)-1], "/")
			for i := len(terms) - 1; i >= 0; i-- {
				imname := terms[i]
				if strings.Contains(imname, ".") {
					// import abc.com/xxx.v1
					importName = strings.Split(imname, ".")[0]
					break
				}
				if regexp.MustCompile(`v[0-9]+`).MatchString(imname) {
					// import abc.com/xxx/v2
					continue
				}
				importName = imname
				break
			}
		}
		allImports[importName] = testF.Imports[idx]
	}
	added := make(map[string]bool)
	for _, decl := range newFuzzF.Decls {
		if targetF, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(targetF.Name.String(), "Fuzz") {
			ast.Inspect(targetF, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if isimport, ok := sel.X.(*ast.Ident); ok {
						impname := isimport.Name
						if imp, ok := allImports[impname]; ok && !added[impname] {
							var name string
							if imp.Name != nil {
								name = imp.Name.Name
							}
							addImport(newFuzzF, strings.Trim(imp.Path.Value, "\""), name)
							added[impname] = true

						}
					}
				}
				return true
			})
		}
	}
	if !added["os"] {
		addImport(newFuzzF, "os", "")
	}
	addImport(newFuzzF, "jkl/gout-transformation/pkg/transstruct", "")
}

func fixTRun(file *ast.File) {
	for _, decl := range file.Decls {
		if targetF, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(targetF.Name.String(), "Fuzz") {
			var tcname ast.Expr
			var callbackF *ast.FuncLit
			var t *ast.Ident
			var targetStmtIdx int

			for stmtIdx, stmt := range targetF.Body.List {
				ast.Inspect(stmt, func(n ast.Node) bool {
					switch fCall := n.(type) {
					case *ast.CallExpr:
						if selectF, ok := fCall.Fun.(*ast.SelectorExpr); ok {
							if tFun, ok1 := selectF.X.(*ast.Ident); ok1 {
								if tFun.Name == "t" && selectF.Sel.Name == "Run" {
									t = tFun
									tcname = fCall.Args[0]
									callbackF = fCall.Args[1].(*ast.FuncLit)
									targetStmtIdx = stmtIdx
									return false
									// sfmt.Println(tcname, callbackF)
								}
							}
						}

					}
					return true
				})

			}
			if rage, ok := targetF.Body.List[targetStmtIdx].(*ast.RangeStmt); ok {
				rage.Body.List = make([]ast.Stmt, 0)
				assTcname := &ast.AssignStmt{}
				assTcname.Lhs = append(assTcname.Lhs, &ast.Ident{Name: "_"})
				assTcname.Rhs = append(assTcname.Rhs, tcname)
				assTcname.Tok = token.ASSIGN

				assFunc := &ast.AssignStmt{}
				tarFname := &ast.Ident{Name: "extractTRun"}
				assFunc.Lhs = append(assFunc.Lhs, tarFname)
				assFunc.Rhs = append(assFunc.Rhs, callbackF)
				assFunc.Tok = token.DEFINE

				callstmt := &ast.ExprStmt{}
				callF := &ast.CallExpr{}
				callstmt.X = callF
				callF.Fun = tarFname
				callF.Args = append(callF.Args, t)

				rage.Body.List = append(rage.Body.List, assTcname)
				rage.Body.List = append(rage.Body.List, assFunc)
				rage.Body.List = append(rage.Body.List, callstmt)
			}
		}
	}
}

func removeFatalAPI(fast *ast.FuncDecl) {
	hasfatal := false
	blackList := make(map[string]bool)
	blackList["Fatal"] = true
	blackList["Fatalf"] = true
	blackList["FailNow"] = true
	blackList["Parallel"] = true

	ast.Inspect(fast, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			if selector, ok := n.Fun.(*ast.SelectorExpr); ok {
				if x, ok := selector.X.(*ast.Ident); ok && x.Name == "t" {
					sel := selector.Sel
					if _, ok := blackList[sel.Name]; ok {
						x.Name = "// " + x.Name
						hasfatal = true
					}
				}
			}

		}
		return true
	})
	if hasfatal {
		fmt.Fprintf(os.Stderr, "[*] This case has fatal call\n")
	}

}

func setGlobalVariable(filepath string, vgsis []*metainfo.VariableGlobalSourceInfo) bool {
	res := false

	generateGetFuzzDataForGeneralCoreNeo := func(vcsi *metainfo.VariableGlobalSourceInfo, ft token.Token) *ast.CallExpr {
		var res *ast.CallExpr
		//fmt.Println("[+]Printing type", pv.Type) //nil?
		//fmt.Println(reflect.TypeOf(pv.Value))
		res = &ast.CallExpr{}
		res = &ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent("transstruct")}}
		switch ft {
		case token.STRING:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetString")}
		default:
			panic("[-]Exception: unknown fuzz type")
		}
		return res
	}

	generateGetFuzzDataForGeneralCaseNeo := func(bl *ast.BasicLit, ft token.Token, vgsi *metainfo.VariableGlobalSourceInfo) *ast.CallExpr {
		if ft != token.STRING {
			return nil
		}
		//res := generateGetFuzzDataForGeneralCore(ft)
		res := generateGetFuzzDataForGeneralCoreNeo(vgsi, ft)
		res.Args = []ast.Expr{bl}
		return res
	}

	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, filepath, nil, parser.ParseComments)
	nameVgsiMap := make(map[string]*metainfo.VariableGlobalSourceInfo, 0)

	for _, vgsi := range vgsis {
		globalName := vgsi.GlobalName[strings.LastIndex(vgsi.GlobalName, ".")+1:]
		fmt.Println("globalName!", globalName)
		nameVgsiMap[globalName] = vgsi
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					for _, name := range s.Names {
						fmt.Println(name)
						if vgsi, ok := nameVgsiMap[name.String()]; ok {
							for valueIdx, value := range s.Values {
								var gRes *ast.CallExpr = nil
								ast.Inspect(value, func(n ast.Node) bool {
									switch x := n.(type) {
									case *ast.BasicLit: //TODO(jx): may add more cases
										gRes = generateGetFuzzDataForGeneralCaseNeo(x, x.Kind, vgsi)
									}
									return true
								})
								if gRes != nil {
									s.Values[valueIdx] = gRes
									res = true
								}
							}
						}
					}
				}
			}
		}
	}
	if res {
		buf := new(bytes.Buffer)
		renderAST(buf, fset, f)
		ioutil.WriteFile("FuzzGenTemp_"+filepath, buf.Bytes(), 0666)
		os.Rename(filepath, filepath+".go.bak")
	}
	return res
}

func (p *Composer) SetGlobalVariable(mi *metainfo.TestCaseMetaInfo) {
	modifyingFilePool := make(map[string][]*metainfo.VariableGlobalSourceInfo, 0)
	for _, variable := range mi.VariableList {
		for gVarIdx, gVar := range variable.VarRelatedGlobalSources {
			if _, ok := modifyingFilePool[gVar.GlobalSrcPath]; !ok {
				modifyingFilePool[gVar.GlobalSrcPath] = make([]*metainfo.VariableGlobalSourceInfo, 0)
			}
			modifyingFilePool[gVar.GlobalSrcPath] = append(modifyingFilePool[gVar.GlobalSrcPath], &(variable.VarRelatedGlobalSources[gVarIdx]))
		}
	}
	for filepath, vgsis := range modifyingFilePool {
		if setGlobalVariable(filepath, vgsis) {
			p.globalModifiedFiles = append(p.globalModifiedFiles, filepath)
		}
	}
}

func setGLobalFuncName() {
	if !*flagFuzzGlobalVar {
		fdg_globalFuncName = "//" + fdg_globalFuncName
	}
}

func (p *Composer) Generate() (string, error) {
	defer func() {
		err := recover()
		if err != nil {
			fmt.Println(err)
		}
	}()
	setGLobalFuncName()

	outputFile := p.filepath + "_" + p.metainfo.Name + "_test.go"
	tmpFuzzFile := p.filepath + "_" + p.metainfo.Name + "_fuzz.go"

	origBytes, rderr := ioutil.ReadFile(p.filepath)
	if rderr != nil {
		panic(rderr)
	}
	ioutil.WriteFile(tmpFuzzFile, origBytes, 0666)

	fset := token.NewFileSet()
	tmpTestFileAst, err := parser.ParseFile(fset, tmpFuzzFile, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	newfuzzBody, _ := p.TransformV2(tmpTestFileAst, tmpFuzzFile, fset)
	newfuzzBody = append([]byte(fmt.Sprintf("package %s\n", tmpTestFileAst.Name.Name)), newfuzzBody...)

	ioutil.WriteFile(outputFile, newfuzzBody, 0666)

	fuzzTestFileAst, err := parser.ParseFile(fset, outputFile, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	fixImport(tmpTestFileAst, fuzzTestFileAst)
	fixReturn(fuzzTestFileAst)
	fixTRun(fuzzTestFileAst)

	buf := new(bytes.Buffer)

	renderAST(buf, fset, fuzzTestFileAst)
	ioutil.WriteFile(outputFile, buf.Bytes(), 0666)

	return outputFile, nil
}

func (p *Composer) metaPrase() {
	if p.metainfo == nil {
		metaBytes, _ := ioutil.ReadFile(p.metapath)
		tcmi := new(metainfo.TestCaseMetaInfo)
		yaml.Unmarshal(metaBytes, tcmi)
		p.metainfo = tcmi
	}
}

func (p *Composer) sourceParse() {
	if p.parseResult == nil {
		sr, _ := p.parse(p.filepath, nil)
		p.parseResult = sr
	}
}

func (p *Composer) ReplaceTcmi(mi *metainfo.TestCaseMetaInfo) {
	p.metainfo = mi
}

func (p *Composer) PreParse(filepath string, metapath string) {
	p.metapath = metapath

	p.metaPrase()
	if len(p.filepath) == 0 {
		p.filepath = filepath
		p.sourceParse() //source parse depends metaPrase
	}
}

func (p *Composer) PreParseSrcOnly(filepath string, mi *metainfo.TestCaseMetaInfo) {
	p.filepath = filepath
	p.metainfo = mi
	p.sourceParse() //source parse depends metaPrase
}

func (p *Composer) Reset() {
	p.filepath = ""
}

func (p *Composer) RecoverModifiedFiles() {
	for _, modifiedFile := range p.globalModifiedFiles {
		os.Rename(modifiedFile+".go.bak", modifiedFile)
	}
}
