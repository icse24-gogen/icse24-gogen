package testcaseextractor

import (
	"fmt"
	"golang.org/x/tools/go/ssa"
	"xyz.asd.qwe/gout-static-analysis/pkg/funcutils"
	"xyz.asd.qwe/gout-static-analysis/pkg/pkgutils"
)

func collectTestCasesFunctionFromPackage(pkg *ssa.Package) []*ssa.Function {
	res := make([]*ssa.Function, 0)
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if funcutils.IsFuncUseless(fn) {
				continue // inline, init, or func added by compiler
			}
			if funcutils.IsFuncTest(fn) {
				res = append(res, fn)
			}
		}
	}
	return res
}

func TestcaseExtractor(patterns []string) {
	patterns = patterns[0:1]
	pkgs := pkgutils.LoadProjPackages(patterns)
	for _, pkg := range pkgs { //handle package
		if pkg != nil {
			testCases := collectTestCasesFunctionFromPackage(pkg) //Get all TestCases. Could be used for specify a function
			for _, tc := range testCases {
				fmt.Println(tc.String())
			}
		}
	}
	return
}
