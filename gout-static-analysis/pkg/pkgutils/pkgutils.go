package pkgutils

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"strings"
)

var ThisProjPkgs []*ssa.Package

func LoadProjPackages(projPathPatterns []string) []*ssa.Package {
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,

		Tests: true,
	}
	initial, err := packages.Load(cfg, projPathPatterns...)
	if err != nil {
		panic(err)
	}
	_, t := ssautil.Packages(initial, ssa.NaiveForm)
	ThisProjPkgs = t

	prog, pkgs := ssautil.AllPackages(initial, ssa.NaiveForm)
	//prog, pkgs := ssautil.Packages(initial, ssa.NaiveForm) //when specific project
	prog.Build()
	return pkgs
}

var stdPkgs = map[string]bool{
	"archive": true, "bufio": true, "bytes": true, "compress": true, "container": true,
	"context": true, "crypto": true, "database": true, "debug": true, "embed": true,
	"encoding": true, "errors": true, "expvar": true, "flag": true, "fmt": true,
	"go": true, "hash": true, "html": true, "image": true, "index": true, "internal": true,
	"io": true, "log": true, "math": true, "mime": true, "net": true, "os": true, "path": true,
	"plugin": true, "reflect": true, "regexp": true, "runtime": true, "sort": true, "strconv": true,
	"strings": true, "sync": true, "syscall": true, "text": true,
	"time": true, "unicode": true, "unsafe": true, "vendor": true,
} //这里去掉了testing，后面可能要单独处理

func JudgePkgIsStd(pkgName string) bool { //加前缀
	if _, ok := stdPkgs[pkgName]; ok {
		return true
	}
	for key, _ := range stdPkgs {
		if strings.HasPrefix(pkgName, key+"/") {
			return true
		}
	}
	return false
}

func JudgePkgIsTesting(pkgName string) bool {
	if pkgName == "testing" {
		return true
	}
	return false
}
