package callsitecomposer

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"text/template"

	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

func getLocKey(argVar *metainfo.ArgInCall) string {
	key := fmt.Sprintf("%s:%d:%d", argVar.Fpath, argVar.CallLine, argVar.CallCol)
	return key
}

func checkNodeShouldFuzz(fset *token.FileSet, node ast.Node, candidate map[string][]*metainfo.ArgInCall) (args []*metainfo.ArgInCall, ok bool) {
	if node == nil || !node.Pos().IsValid() {
		return nil, false
	}
	var pos token.Position
	switch n := node.(type) {
	case *ast.CallExpr:
		pos = fset.Position(n.Lparen)
	default:

	}
	key := fmt.Sprintf("%s:%d:%d", pos.Filename, pos.Line, pos.Column)
	args, ok = candidate[key]
	return
}

func generateGetFuzzDataNode(arg ast.Expr, argMeta *metainfo.ArgInCall) *ast.CallExpr {
	getfuzzdataTemplate := func() *ast.CallExpr {
		res := new(ast.CallExpr)
		switch argMeta.Type {
		case metainfo.FuzzableString:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetString")}
		case metainfo.FuzzableBytes:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetBytes")}
		case metainfo.FuzzableInt:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt")}
		case metainfo.FuzzableInt8:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt8")}
		case metainfo.FuzzableInt16:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt16")}
		case metainfo.FuzzableInt32:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt32")}
		case metainfo.FuzzableInt64:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetInt64")}
		case metainfo.FuzzableUint:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint")}
		case metainfo.FuzzableUint8:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint8")}
		case metainfo.FuzzableUint16:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint16")}
		case metainfo.FuzzableUint32:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint32")}
		case metainfo.FuzzableUint64:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetUint64")}
		case metainfo.FuzzableFloat32:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat32")}
		case metainfo.FuzzableFloat64:
			res.Fun = &ast.SelectorExpr{X: ast.NewIdent("transstruct"), Sel: ast.NewIdent("GetFloat64")}
		default:
			fmt.Fprintf(os.Stderr, "unsupported type\n")
			res = nil
		}
		return res
	}
	temp := getfuzzdataTemplate()
	temp.Args = append(temp.Args, arg)
	return temp
}

func renderAST(w io.Writer, fset *token.FileSet, astFile *ast.File) {
	cfg := printer.Config{
		Mode:     printer.TabIndent,
		Tabwidth: 8,
		Indent:   0,
	}
	cfg.Fprint(w, fset, astFile)
}

var fuzzSrc = template.Must(template.New("main").Parse(`
func Fuzz{{.TestName}} ({{.FuzzDataName}} []byte) int {
	t := &testing.T{}
	_ = t
	var skippingTableDriven bool
	_, skippingTableDriven = os.LookupEnv("SKIPPING_TABLE_DRIVEN")
	_ = skippingTableDriven
	transstruct.SetFuzzData({{.FuzzDataName}})
	{{.Body}}
	return 1
}`))

func GetDockToGoFuzz(testName, filepath string) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath, nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}
	var targetFuzzFunction *ast.FuncDecl
	for _, d := range f.Decls {
		fDecl, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fDecl.Name.String() == testName {
			targetFuzzFunction = fDecl
		}
	}
	newBody := parseFuncBody(targetFuzzFunction, filepath)

	generateRandomString := func(n int) string {
		var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		b := make([]rune, n)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		return string(b)
	}

	t := fuzzSrc
	dot := map[string]interface{}{"TestName": testName, "Body": string(newBody), "FuzzDataName": generateRandomString(3)}
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, dot); err != nil {
		panic("GenerateOneFunc")
	}

	return buf.Bytes()

}

func parseFuncBody(fDecl *ast.FuncDecl, filePath string) []byte {
	startPos := fDecl.Pos() - 1 //byte count to index
	endPos := fDecl.End() - 1
	//return parseFuncBodyCore(startPos, endPos, filePath)
	return parseFuncBodyNaive(startPos, endPos, filePath)
}

func parseFuncBodyNaive(sp, ep token.Pos, filePath string) []byte {
	startPos := sp
	endPos := ep
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
	for i := len(res) - 1; 0 <= i; i-- {
		if res[i] == '}' {
			endPos = token.Pos(i)
			break
		}
	}

	res = res[startPos+1 : endPos]
	return res
}

func fixImport(f, newf *ast.File) {
	addImport := func(af *ast.File, path, name string) {
		newImport := &ast.ImportSpec{
			Name: ast.NewIdent(name),
			Path: &ast.BasicLit{
				Kind:  token.STRING,
				Value: fmt.Sprintf("%q", path),
			},
		}
		impDecl := &ast.GenDecl{
			Lparen: af.Name.End(),
			Tok:    token.IMPORT,
			Specs: []ast.Spec{
				newImport,
			},
			Rparen: af.Name.End(),
		}
		// Make the new import the first Decl in the file.
		astFile := af
		astFile.Decls = append(astFile.Decls, nil)
		copy(astFile.Decls[1:], astFile.Decls[0:])
		astFile.Decls[0] = impDecl
		astFile.Imports = append(astFile.Imports, newImport)
	}
	allImports := make(map[string]*ast.ImportSpec)
	for idx, im := range f.Imports {
		importName := ""
		if im.Name == nil {
			terms := strings.Split(im.Path.Value[1:len(im.Path.Value)-1], "/")
			importName = terms[len(terms)-1]
		} else {
			importName = im.Name.Name
		}
		allImports[importName] = f.Imports[idx]
	}

	added := make(map[string]bool)
	for _, decl := range newf.Decls {
		if targetF, ok := decl.(*ast.FuncDecl); ok {
			ast.Inspect(targetF, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if isimport, ok := sel.X.(*ast.Ident); ok {
						impname := isimport.Name
						if imp, ok := allImports[impname]; ok && !added[impname] {
							var name string
							if imp.Name != nil {
								name = imp.Name.Name
							}
							addImport(newf, strings.Trim(imp.Path.Value, "\""), name)
							added[impname] = true
							// newf.Imports = append(newf.Imports, allImports[sel.X.(*ast.Ident).Name])
						}
					}

				}
				return true
			})
		}
	}
	if !added["os"] {
		addImport(newf, "os", "")
	}
	addImport(newf, "jkl/gout-transformation/pkg/transstruct", "")

}

func fixReturn(file *ast.File) {
	for _, decl := range file.Decls {
		if targetF, ok := decl.(*ast.FuncDecl); ok {
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
