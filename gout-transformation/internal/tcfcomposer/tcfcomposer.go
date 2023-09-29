package tcfcomposer

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io/ioutil"
	"reflect"
	"strings"

	//"reflect"
	"math/rand"

	//"reflect"
	"io"
	"os"
	"text/template"

	yaml "gopkg.in/yaml.v2"
	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

// Composer can parse Go files.
type Composer struct {
	// The importer to resolve packages from import paths.
	IsSrcParsed bool
	Importer    types.Importer
	filepath    string
	metapath    string
	parseResult *Result
	metainfo    *(metainfo.TestCaseMetaInfo)
}

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

func Fuzz{{.TestName}} (f *testing.F) {
    f.Fuzz(func(t *testing.T) {{.Body}})
}`))

func (p *Composer) GenerateOneFunc() []byte {
	t := fuzzSrc
	result := p.parseResult
	//dot := map[string]interface{}{"PkgName": result.Header.Package, "Imported": result.Header.Imports[0].Path, "TestName": result.Funcs[0].Name, "Body": string(result.Funcs[0].Body)}
	dot := map[string]interface{}{"TestName": result.Funcs[0].Name, "Body": string(result.Funcs[0].Body)}
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, dot); err != nil {
		panic("GenerateOneFunc")
	}
	return buf.Bytes()
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
	dot := map[string]interface{}{"TestName": result.Funcs[targetIdx].Name, "Body": string(result.Funcs[targetIdx].Body)}
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

	dot := map[string]interface{}{"TestName": result.Funcs[targetIdx].Name, "Body": string(result.Funcs[targetIdx].Body)}
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, dot); err != nil {
		panic("GenerateOneFunc")
	}
	return buf.Bytes(), nil
}

func appendFuzzParam(fl *ast.FuncLit, v *metainfo.VariableMetaInfo) {
	fmt.Println("[+]appending fuzztype for", v.VarName)
	switch v.VarType {
	case metainfo.FuzzableString:
		appendingVariable := &ast.Field{
			Names: []*ast.Ident{&ast.Ident{Name: v.VarName}},
			Type:  &ast.Ident{Name: "string"},
		}
		fl.Type.Params.List = append(fl.Type.Params.List, appendingVariable)
	case metainfo.FuzzableBytes:
		//key of supporting new fuzzable argument
		appendingVariable := &ast.Field{
			Names: []*ast.Ident{&ast.Ident{Name: v.VarName}},
			Type:  &ast.Ident{Name: "[]byte"},
		}
		fl.Type.Params.List = append(fl.Type.Params.List, appendingVariable)
	default:
		fmt.Println("[-]Unknown fuzztype for", v.VarName)
	}
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
					fmt.Println(s)
				case *ast.AssignStmt:
					fmt.Println(s)
				case *ast.ExprStmt:
					if ce, ok := s.X.(*ast.CallExpr); ok {
						curCallee := v.Callee[strings.LastIndex(v.Callee, ".")+1:]
						handleCe := ceFinder(ce, token.Pos(v.VarPos), curCallee)
						if handleCe != nil {
							fmt.Println(reflect.TypeOf(handleCe))
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

func generateArgsForAdd(addIndex int, mi *metainfo.TestCaseMetaInfo) []ast.Expr {
	res := []ast.Expr{}

	for _, v := range mi.VariableList {
		bl := new(ast.BasicLit)
		switch v.VarType {
		case metainfo.FuzzableString:
			//key of add new fuzzable argument
			bl.Kind = token.STRING
			// bl.Value = "\"" + v.VarValue[addIndex] + "\""
		}
		res = append(res, bl) //why we can append instance to pointer array?
	}

	return res
}

func appendAdd(fuzzFunc *ast.FuncDecl, mi *metainfo.TestCaseMetaInfo) {
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

func (p *Composer) Transform(f *ast.File, mi *metainfo.TestCaseMetaInfo) ([]byte, error) {
	fuzzFunctionName := "Fuzz" + mi.Name
	fmt.Fprintln(os.Stderr, "[+]Transforming fuzz driver", fuzzFunctionName)
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
	//transform for Fuzz call back
	transformFuzzCallBack(targetFuzzFunction, mi)

	//transform for add init corpus
	//appendAdd(targetFuzzFunction, mi)

	return nil, nil
}

func (p *Composer) Generate() error {
	outputFile := p.filepath + "_" + p.metainfo.Name + ".fuzz.go"
	if _, err := os.Stat(outputFile); errors.Is(err, os.ErrNotExist) {

		res := []([]byte){}
		oneBytes, err := p.GenerateByTestCaseInfo(p.metainfo)
		res = append(res, oneBytes)

		origBytes, rderr := ioutil.ReadFile(p.filepath)
		if rderr != nil {
			panic(rderr)
		}

		newBytes := origBytes
		for _, fuzzBytes := range res {
			newBytes = append(newBytes, fuzzBytes...)
		}

		ioutil.WriteFile(outputFile, newBytes, 0666)

		fset := token.NewFileSet()

		f, err := parser.ParseFile(fset, outputFile, nil, parser.ParseComments)

		if err != nil {
			panic(err)
		}

		p.Transform(f, p.metainfo)

		buf := new(bytes.Buffer)
		renderAST(buf, fset, f)
		fmt.Println("[+]Fuzz driver of ", p.metainfo.Name, "generated at", outputFile)
		ioutil.WriteFile(outputFile, buf.Bytes(), 0666)
		return err
	}
	fmt.Println("[+]Fuzz driver of ", p.metainfo.Name, "is here")
	return nil
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
