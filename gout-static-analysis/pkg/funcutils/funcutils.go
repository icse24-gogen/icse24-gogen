package funcutils

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

func IsFuncUseless(fn *ssa.Function) bool {
	fname := fn.Name()
	pkgpath := fn.Pkg.Pkg.Path()
	if strings.Contains(fname, "$") {
		return true
	}
	if strings.HasPrefix(fname, "init") {
		return true
	}
	if strings.Contains(pkgpath, ".test") {
		return true
	}
	return false
}

func IsMethodUseless(fn types.Object, pkg *ssa.Package) bool {
	fname := fn.Name()
	pkgpath := pkg.Pkg.Path()
	if strings.Contains(fname, "$") {
		return true
	}
	if strings.HasPrefix(fname, "init") {
		return true
	}
	if strings.Contains(pkgpath, ".test") {
		return true
	}
	return false
}

// IsCalleeUseless judge testing api
func IsCalleeUseless(fn *ssa.Function) bool {
	fString := fn.String()
	pkgPath := fn.Pkg.Pkg.Name()
	if strings.Contains(fString, "*testing.common") {
		return true
	}
	if pkgPath == "testing" {
		return true
	}
	return false
}

func IsFuncExported(fn *ssa.Function) bool {
	fname := fn.Name()
	if strings.Contains(fname, "$") {
		return false
	}
	firstCha := fname[0]
	if int8(firstCha) >= 65 && int8(firstCha) <= 90 {
		return true
	}
	return false
}

func IsMethodExported(fn types.Object) bool {
	fname := fn.Name()
	if strings.Contains(fname, "$") {
		return false
	}
	firstCha := fname[0]
	if int8(firstCha) >= 65 && int8(firstCha) <= 90 {
		return true
	}
	return false
}

func IsFuncMethod(fn *ssa.Function) bool {
	if fn.Signature.Recv() != nil {
		return true
	}
	return false
}

func IsFunctionBelongsToAssertPkg(fn *ssa.Function) bool {
	if fn.Pkg != nil {
		if strings.Contains(fn.Pkg.String(), "assert") {
			return true
		}
	}
	return false
}

func IsFuncTest(fn *ssa.Function) bool {
	fname := fn.Name()
	filepath := fn.Prog.Fset.Position(fn.Pos()).Filename

	if strings.HasPrefix(fname, "Test") && strings.HasSuffix(filepath, "_test.go") {
		return true
	}
	return false
}
