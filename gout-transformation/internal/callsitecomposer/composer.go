package callsitecomposer

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"strings"

	"xyz.asd.qwe/gout-transformation/pkg/metainfo"
)

// Composer can parse Go files.
type Composer struct {
	// The importer to resolve packages from import paths.
	Testfile string
	Metapath string

	Metainfo            *(metainfo.CallsiteMeta)
	GlobalModifiedFiles []string
}

// Generate write the generated fuzz func into a single _test.go file,
// instead of a _fuzz.go func as before.
// when doing this, an important thing is to get the correct imports,
// and the generated driver needs to be compiled with go-fuzz-test
func (c *Composer) Generate() (string, error) {
	outputFile := c.Testfile + "_" + c.Metainfo.Name[strings.LastIndex(c.Metainfo.Name, ".")+1:] + "_test.go"
	tmpFuzzFile := c.Testfile + "_" + c.Metainfo.Name[strings.LastIndex(c.Metainfo.Name, ".")+1:] + "_fuzz.go"

	fset := token.NewFileSet()
	tmpTestFileAst, err := parser.ParseFile(fset, c.Testfile, nil, parser.ParseComments)
	if err != nil {
		return "", err
	}
	newfuzzbody := c.Transform(tmpTestFileAst, tmpFuzzFile, fset)

	newfuzzbody = append([]byte(fmt.Sprintf("package %s\n", tmpTestFileAst.Name.Name)), newfuzzbody...)

	ioutil.WriteFile(outputFile, newfuzzbody, 0666)

	fuzzTestAst, err := parser.ParseFile(fset, outputFile, nil, parser.ParseComments)
	fixImport(tmpTestFileAst, fuzzTestAst)
	fixReturn(fuzzTestAst)

	buf := new(bytes.Buffer)
	renderAST(buf, fset, fuzzTestAst)
	ioutil.WriteFile(outputFile, buf.Bytes(), 0666)

	return outputFile, nil

}

// Transfrom trans the Testbody and returns the fuzz body
func (c *Composer) Transform(f *ast.File, tmpFuzzFile string, fset *token.FileSet) []byte {
	testFuncName := c.Metainfo.Name[strings.LastIndex(c.Metainfo.Name, ".")+1:]
	var targetTestFunc *ast.FuncDecl
	for _, d := range f.Decls {
		fDeccl, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fDeccl.Name.String() == testFuncName {
			targetTestFunc = fDeccl
		}
	}

	c.transformTestBody(f, targetTestFunc, fset)

	buf := new(bytes.Buffer)
	renderAST(buf, fset, f)
	ioutil.WriteFile(tmpFuzzFile, buf.Bytes(), 0666)
	defer os.Remove(tmpFuzzFile)

	newFuzzFuncByte := GetDockToGoFuzz(testFuncName, tmpFuzzFile)

	return newFuzzFuncByte

}

func (c *Composer) transformTestBody(f *ast.File, testfunc *ast.FuncDecl, fset *token.FileSet) {
	candidateCall := make(map[string][]*metainfo.ArgInCall)

	for _, argVar := range c.Metainfo.Args {
		key := getLocKey(argVar)
		candidateCall[key] = append(candidateCall[key], argVar)
	}

	var stack []ast.Node

	ast.Inspect(testfunc, func(node ast.Node) bool {
		genedForOutsideCall := false
		switch n := node.(type) {
		case *ast.CallExpr:
			if metaArgs, ok := checkNodeShouldFuzz(fset, n, candidateCall); ok {
				for _, argMeta := range metaArgs {
					//TODO(jx): there should not has a check, bug it crashes if not
					if argMeta.ArgIndex >= len(n.Args) {
						continue
					}
					getfuzzdataNode := generateGetFuzzDataNode(n.Args[argMeta.ArgIndex], argMeta)
					if getfuzzdataNode != nil {
						genedForOutsideCall = true
						n.Args[argMeta.ArgIndex] = getfuzzdataNode
					}
				}
			}
		}

		if node == nil {
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, node)
		}
		// TODO(jx): only fuzz the outside call?
		// what if format like FA(FB(string) string, FC(int) unsupported type)?
		// fuck! it dont work for this style
		return !genedForOutsideCall
	})

}
