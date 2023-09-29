// Package goparse contains logic for parsing Go files. Specifically it parses
// source and test files into domain models for generating tests.
package tcfcomposer

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"xyz.asd.qwe/gout-transformation/internal/models"
)

// ErrEmptyFile represents an empty file error.
var ErrEmptyFile = errors.New("file is empty")

// Result representats a parsed Go file.
type Result struct {
	// The package name and imports of a Go file.
	Header *models.Header
	// All the functions and methods in a Go file.
	Funcs []*models.Function
}

// Parse parses a given Go file at srcPath, along any files that share the same
// package, into a domain model for generating tests.
func (p *Composer) parse(srcPath string, files []models.Path) (*Result, error) {
	b, err := p.readFile(srcPath)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := p.parseFile(fset, srcPath)
	if err != nil {
		return nil, err
	}
	fs, err := p.parseFiles(fset, f, files)
	if err != nil {
		return nil, err
	}
	return &Result{
		Header: &models.Header{
			Comments: parsePkgComment(f, f.Package),
			Package:  f.Name.String(),
			Imports:  parseImports(f.Imports),
			Code:     goCode(b, f),
		},
		Funcs: p.parseFunctions(fset, f, fs),
	}, nil
}

func (p *Composer) readFile(srcPath string) ([]byte, error) {
	b, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadFile: %v", err)
	}
	if len(b) == 0 {
		return nil, ErrEmptyFile
	}
	return b, nil
}

func (p *Composer) parseFile(fset *token.FileSet, srcPath string) (*ast.File, error) {
	f, err := parser.ParseFile(fset, srcPath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("target parser.ParseFile(): %v", err)
	}
	return f, nil
}

func (p *Composer) parseFiles(fset *token.FileSet, f *ast.File, files []models.Path) ([]*ast.File, error) {
	pkg := f.Name.String()
	var fs []*ast.File
	for _, file := range files {
		ff, err := parser.ParseFile(fset, string(file), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("other file parser.ParseFile: %v", err)
		}
		if name := ff.Name.String(); name != pkg {
			continue
		}
		fs = append(fs, ff)
	}
	return fs, nil
}

func (p *Composer) parseFunctions(fset *token.FileSet, f *ast.File, fs []*ast.File) []*models.Function {
	ul, el := p.parseTypes(fset, fs)
	var funcs []*models.Function
	for _, d := range f.Decls {
		fDecl, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		funcs = append(funcs, parseFunc(fDecl, ul, el, fset.Position(f.Pos()).Filename))
	}
	return funcs
}

func (p *Composer) parseTypes(fset *token.FileSet, fs []*ast.File) (map[string]types.Type, map[*types.Struct]ast.Expr) {
	conf := &types.Config{
		Importer: p.Importer,
		// Adding a NO-OP error function ignores errors and performs best-effort
		// type checking. https://godoc.org/golang.org/x/tools/go/types#Config
		Error: func(error) {},
	}
	ti := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
	}
	// Note: conf.Check can fail, but since Info is not required data, it's ok.
	conf.Check("", fset, fs, ti)
	ul := make(map[string]types.Type)
	el := make(map[*types.Struct]ast.Expr)
	for e, t := range ti.Types {
		// Collect the underlying types.
		ul[t.Type.String()] = t.Type.Underlying()
		// Collect structs to determine the fields of a receiver.
		if v, ok := t.Type.(*types.Struct); ok {
			el[v] = e
		}
	}
	return ul, el
}

func parsePkgComment(f *ast.File, pkgPos token.Pos) []string {
	var comments []string
	var count int

	for _, comment := range f.Comments {

		if comment.End() >= pkgPos {
			break
		}
		for _, c := range comment.List {
			count += len(c.Text) + 1 // +1 for '\n'
			if count < int(c.End()) {
				n := int(c.End()) - count - 1
				comments = append(comments, strings.Repeat("\n", n))
				count++ // for last of '\n'
			}
			comments = append(comments, c.Text)
		}
	}

	if int(pkgPos)-count > 1 {
		comments = append(comments, strings.Repeat("\n", int(pkgPos)-count-2))
	}
	return comments
}

// Returns the Go code below the imports block.
func goCode(b []byte, f *ast.File) []byte {
	furthestPos := f.Name.End()
	for _, node := range f.Imports {
		if pos := node.End(); pos > furthestPos {
			furthestPos = pos
		}
	}
	if furthestPos < token.Pos(len(b)) {
		furthestPos++

		// Avoid wrong output on windows-encoded files
		if b[furthestPos-2] == '\r' && b[furthestPos-1] == '\n' && furthestPos < token.Pos(len(b)) {
			furthestPos++
		}
	}
	return b[furthestPos:]
}

func parseFuncBody(fDecl *ast.FuncDecl, filePath string) []byte {
	startPos := fDecl.Pos() - 1 //byte count to index
	endPos := fDecl.End() - 1
	file, openErr := os.Open(filePath)
	if openErr != nil {
		panic(openErr)
	}
	res, readErr := ioutil.ReadAll(file)
	if readErr != nil {
		panic(readErr)
	}
	res = res[startPos:endPos]

	for i := 0; i < len(res); i++ {
		if res[i] == '{' {
			startPos = token.Pos(i)
			break
		}
	}
	stackPointer := 0
	for i := startPos; i < token.Pos(len(res)); i++ {
		if res[i] == '{' {
			stackPointer += 1
		} else if res[i] == '}' {
			stackPointer -= 1
		}
		if stackPointer == 0 {
			endPos = i + 1
			break
		}
	}
	res = res[startPos:endPos]
	return res
}

func parseFunc(fDecl *ast.FuncDecl, ul map[string]types.Type, el map[*types.Struct]ast.Expr, filePath string) *models.Function {
	f := &models.Function{
		Name:       fDecl.Name.String(),
		IsExported: fDecl.Name.IsExported(),
		Receiver:   parseReceiver(fDecl.Recv, ul, el),
		Parameters: parseFieldList(fDecl.Type.Params, ul),
		Body:       parseFuncBody(fDecl, filePath),
	}

	fs := parseFieldList(fDecl.Type.Results, ul)
	i := 0
	for _, fi := range fs {
		if fi.Type.String() == "error" {
			f.ReturnsError = true
			continue
		}
		fi.Index = i
		f.Results = append(f.Results, fi)
		i++
	}
	if fDecl.Body != nil {
		f.TestInputs = parseLocalConcreteVariables(fDecl.Body, ul)
		// parseLocalConcreteVariables(fDecl.Body, ul) //TODO for JX
	}
	return f
}

func parseImports(imps []*ast.ImportSpec) []*models.Import {
	var is []*models.Import
	for _, imp := range imps {
		var n string
		if imp.Name != nil {
			n = imp.Name.String()
		}
		is = append(is, &models.Import{
			Name: n,
			Path: imp.Path.Value,
		})
	}
	return is
}

func parseReceiver(fl *ast.FieldList, ul map[string]types.Type, el map[*types.Struct]ast.Expr) *models.Receiver {
	if fl == nil {
		return nil
	}
	r := &models.Receiver{
		Field: parseFieldList(fl, ul)[0],
	}
	t, ok := ul[r.Type.Value]
	if !ok {
		return r
	}
	s, ok := t.(*types.Struct)
	if !ok {
		return r
	}
	st, found := el[s]
	if !found {
		return r
	}
	r.Fields = append(r.Fields, parseFieldList(st.(*ast.StructType).Fields, ul)...)
	for i, f := range r.Fields {
		// https://github.com/cweill/gotests/issues/69
		if i >= s.NumFields() {
			break
		}
		f.Name = s.Field(i).Name()
	}
	return r

}

func parseFieldList(fl *ast.FieldList, ul map[string]types.Type) []*models.Field {
	if fl == nil {
		return nil
	}
	i := 0
	var fs []*models.Field
	for _, f := range fl.List {
		for _, pf := range parseFields(f, ul) {
			pf.Index = i
			fs = append(fs, pf)
			i++
		}
	}
	return fs
}

func parseFields(f *ast.Field, ul map[string]types.Type) []*models.Field {
	t := parseExpr(f.Type, ul)
	if len(f.Names) == 0 {
		return []*models.Field{{
			Type: t,
		}}
	}
	var fs []*models.Field
	for _, n := range f.Names {
		fs = append(fs, &models.Field{
			Name: n.Name,
			Type: t,
		})
	}
	return fs
}

func parseExprDeeply(expr ast.Expr) []string {
	known_values := []string{}
	switch ev := expr.(type) {
	case *ast.BasicLit:
		known_values = append(known_values, types.ExprString(ev))
	case *ast.CompositeLit:
		for _, elt := range ev.Elts {
			clknown_values := parseExprDeeply(elt)
			known_values = append(known_values, clknown_values...)
		}
	case *ast.KeyValueExpr:
		known_values = append(known_values, parseExprDeeply(ev.Value)...)
	case *ast.Ident:
		known_values = append(known_values, ev.Name)
	default:
		fmt.Println("unknown", reflect.TypeOf(ev))
	}
	return known_values
}

func parseRhsDeeply(rhs ast.Expr) []string {
	known_values := []string{}

	t_known_values := parseExprDeeply(rhs)
	known_values = append(known_values, t_known_values...)

	return known_values
}

func parseAssign(as *ast.AssignStmt) []*models.Variable {
	// ATTENTION(jx): right must be const
	// function call or any other is not accepted

	// set the varRes.Value as rhs
	assigns := make([]*models.Variable, 0)
	/*
		type Variable struct {
		    Name  string
		    Type  *Expression
		    Index int
		    Value *ast.Node
		}
	*/
	for idx, lhs := range as.Lhs {
		assignVar := &models.Variable{
			Name: types.ExprString(lhs),
		}
		fmt.Println("assign.Name: ", assignVar.Name)
		if true {

			if len(as.Rhs) <= idx {
				break
			}
			rhs := as.Rhs[idx]
			// if rhs type is supported
			// unsupported type like function call will be skipped
			if rhs := isExprSupported(rhs); rhs == nil {
				continue
			}
			assignVar.Value = rhs

			// TODO(jx): parse rhs to screen
			fmt.Println("assign.Value: ", parseRhsDeeply(rhs))

			assigns = append(assigns, assignVar)
		}
	}
	return assigns
}

func parseDecl(decl *ast.DeclStmt) []*models.Variable {
	// ATTENTION(jx): must have a value to assign
	// that value must be supported
	decls := make([]*models.Variable, 0)
	if gDecl, ok := decl.Decl.(*ast.GenDecl); ok {
		for _, spec := range gDecl.Specs {
			if valueSpec, ok := spec.(*ast.ValueSpec); ok {
				for idx, name := range valueSpec.Names {
					declVar := &models.Variable{
						Name: name.Name,
					}
					fmt.Println("decl.Name: ", declVar.Name)
					if len(valueSpec.Values) <= idx {
						break
					}
					value := valueSpec.Values[idx]
					if value = isExprSupported(value); value == nil {
						continue
					}
					declVar.Value = value
					fmt.Println("decl.Value: ", parseExprDeeply(value))
					decls = append(decls, declVar)
				}
			}
		}

	}

	return decls
}

func parseConstInCall(call *ast.CallExpr) []*models.Variable {
	constArgs := make([]*models.Variable, 0)
	// name = "%%N"
	//

	for argIdx, arg := range call.Args {
		if _, ok := arg.(*ast.Ident); !ok {
			if arg = isExprSupported(arg); arg != nil {
				getCallName := func(call *ast.CallExpr) string {
					if call.Fun != nil {
						if fun, ok := call.Fun.(*ast.Ident); ok {
							return fun.Name
						}
						if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
							return fmt.Sprintf("%s.%s", fun.X.(*ast.Ident).Name, fun.Sel.Name)
						}
					}
					return ""
				}

				// fmt.Println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
				// fmt.Println("[-] Callee is not an Ident. Call jx to fix it")
				// fmt.Println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

				constVar := &models.Variable{
					Name:  fmt.Sprintf("%%%s$%v", getCallName(call), argIdx),
					Value: arg,
				}
				//fmt.Println("arg name: ", constVar.Name)
				//fmt.Println("arg value: ", parseExprDeeply(arg))

				constArgs = append(constArgs, constVar)
			}
		}
	}

	return constArgs
}
func parseLocalConcreteVariables(fb *ast.BlockStmt, ul map[string]types.Type) []*models.Variable {
	varRes := make([]*models.Variable, 0)

	for _, st := range fb.List {
		if as, ok := st.(*ast.AssignStmt); ok {
			varRes = append(varRes, parseAssign(as)...)
		} else if decl, ok := st.(*ast.DeclStmt); ok {
			varRes = append(varRes, parseDecl(decl)...)
		} else if exp, ok := st.(*ast.ExprStmt); ok {
			if call, ok := exp.X.(*ast.CallExpr); ok {
				varRes = append(varRes, parseConstInCall(call)...)
			}
		} else {
			// any other format to init a variable
			fmt.Println(reflect.TypeOf(st))
		}
		/* */
	}
	return varRes
}

func parseExpr(e ast.Expr, ul map[string]types.Type) *models.Expression {
	switch v := e.(type) {
	case *ast.StarExpr:
		val := types.ExprString(v.X)
		return &models.Expression{
			Value:      val,
			IsStar:     true,
			Underlying: underlying(val, ul),
		}
	case *ast.Ellipsis:
		exp := parseExpr(v.Elt, ul)
		return &models.Expression{
			Value:      exp.Value,
			IsStar:     exp.IsStar,
			IsVariadic: true,
			Underlying: underlying(exp.Value, ul),
		}
	default:
		val := types.ExprString(e)
		return &models.Expression{
			Value:      val,
			Underlying: underlying(val, ul),
			IsWriter:   val == "io.Writer",
		}
	}
}

func isExprSupported(expr ast.Expr) ast.Expr {
	//TODO(jx): more type is waiting to be added
	if callexp, ok := expr.(*ast.CallExpr); ok {
		// type trans like : []byte("aaaa")
		if array, ok := callexp.Fun.(*ast.ArrayType); ok {
			if ident, ok := array.Elt.(*ast.Ident); ok && ident.Name == "byte" {
				return callexp.Args[0]
			}
		}
		return nil
	}
	if basicexpr, ok := expr.(*ast.BasicLit); ok {
		return basicexpr
	}

	if comexpr, ok := expr.(*ast.CompositeLit); ok {
		return comexpr
	}

	return nil
}

func underlying(val string, ul map[string]types.Type) string {
	if ul[val] != nil {
		return ul[val].String()
	}
	return ""
}
