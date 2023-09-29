package apiutil

import (
	"fmt"
	"go/types"
	"golang.org/x/tools/go/ssa"
	"xyz.asd.qwe/gout-static-analysis/pkg/funcutils"
)

func mergeMaps(m1 map[string]string, m2 map[string]string) map[string]string {
	for k, v := range m2 {
		m1[k] = v
	}
	return m1
}

func handlePkgSetFuzzFuncCallee(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.allFuncMethodDecl == nil {
		mapOfProj.allFuncMethodDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if funcutils.IsFuncUseless(fn) || funcutils.IsFuncTest(fn) {
				continue // inline, init, or func added by compiler
			}

			//judge fuzz Func, set callee to map
			if len(fn.Name()) < 4 {
				continue
			}
			if fn.Name()[:4] == "Fuzz" {
				fmt.Println("Get a fuzz func: ", fn.String())
				mapOfProj.setOneFuncCalleesToAllFuncMathodDecl(fn, "")
			}
		}
	}
}

func handlePkgSetAllAPI(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.allFuncMethodDecl == nil {
		mapOfProj.allFuncMethodDecl = make(map[string]string)
	}
	if mapOfProj.allFuncDecl == nil {
		mapOfProj.allFuncDecl = make(map[string]string)
	}
	if mapOfProj.allMethodDecl == nil {
		mapOfProj.allMethodDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if funcutils.IsFuncUseless(fn) || funcutils.IsFuncTest(fn) {
				continue // inline, init, or func added by compiler
			}
			//all func set to map
			mapOfProj.setOneFuncToAllFuncDecl(fn)
		}

		if _, toTypeOk := member.(*ssa.Type); toTypeOk {
			typePointer := types.NewPointer(member.Type())
			ms := pkg.Prog.MethodSets.MethodSet(typePointer)
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				mapOfProj.setOneFuncToAllMethodDecl(m.Obj(), pkg)
			}

			ms = pkg.Prog.MethodSets.MethodSet(member.Type())
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				mapOfProj.setOneFuncToAllMethodDecl(m.Obj(), pkg)
			}
		}
	}
	mergeMaps(mapOfProj.allFuncMethodDecl, mapOfProj.allFuncDecl)
	mergeMaps(mapOfProj.allFuncMethodDecl, mapOfProj.allMethodDecl)
}

func handlePkgSetAllFunc(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.allFuncDecl == nil {
		mapOfProj.allFuncDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if funcutils.IsFuncUseless(fn) || funcutils.IsFuncTest(fn) {
				continue // inline, init, or func added by compiler
			}
			if funcutils.IsFuncMethod(fn) {
				continue
			}
			//all func set to map
			mapOfProj.setOneFuncToAllFuncDecl(fn)
		}
	}
}

func handlePkgSetExportFunc(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.exportFuncDecl == nil {
		mapOfProj.exportFuncDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if funcutils.IsFuncUseless(fn) || funcutils.IsFuncTest(fn) {
				continue // inline, init, or func added by compiler
			}
			if funcutils.IsFuncMethod(fn) || !funcutils.IsFuncExported(fn) {
				continue
			}
			//all func set to map
			mapOfProj.setOneFuncToExportFuncDecl(fn)
		}
	}
}

func handlePkgSetInternalFunc(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.internalFuncDecl == nil {
		mapOfProj.internalFuncDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if funcutils.IsFuncUseless(fn) || funcutils.IsFuncTest(fn) {
				continue // inline, init, or func added by compiler
			}
			if funcutils.IsFuncMethod(fn) || funcutils.IsFuncExported(fn) {
				continue
			}
			//all func set to map
			mapOfProj.setOneFuncToInternalFuncDecl(fn)
		}
	}
}

func handlePkgSetAllMethod(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.allMethodDecl == nil {
		mapOfProj.allMethodDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if _, toTypeOk := member.(*ssa.Type); toTypeOk {
			typePointer := types.NewPointer(member.Type())
			ms := pkg.Prog.MethodSets.MethodSet(typePointer)
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				if funcutils.IsMethodUseless(m.Obj(), pkg) {
					continue
				}
				//all Methods set to map
				mapOfProj.setOneFuncToAllMethodDecl(m.Obj(), pkg)
			}

			ms = pkg.Prog.MethodSets.MethodSet(member.Type())
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				mapOfProj.setOneFuncToAllMethodDecl(m.Obj(), pkg)
			}
		}
	}
}

func handlePkgSetExportMethod(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.exportMethodDecl == nil {
		mapOfProj.exportMethodDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if _, toTypeOk := member.(*ssa.Type); toTypeOk {
			typePointer := types.NewPointer(member.Type())
			ms := pkg.Prog.MethodSets.MethodSet(typePointer)
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				if funcutils.IsMethodUseless(m.Obj(), pkg) || !funcutils.IsMethodExported(m.Obj()) {
					continue
				}
				//all Exported Methods set to map
				mapOfProj.setOneFuncToExportMethodDecl(m.Obj(), pkg)
			}

			ms = pkg.Prog.MethodSets.MethodSet(member.Type())
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				mapOfProj.setOneFuncToAllMethodDecl(m.Obj(), pkg)
			}
		}
	}
}

func handlePkgSetInternalMethod(pkg *ssa.Package, mapOfProj *pkgCallableAPIMap) {
	if mapOfProj.internalMethodDecl == nil {
		mapOfProj.internalMethodDecl = make(map[string]string)
	}
	for _, member := range pkg.Members {
		if _, toTypeOk := member.(*ssa.Type); toTypeOk {
			typePointer := types.NewPointer(member.Type())
			ms := pkg.Prog.MethodSets.MethodSet(typePointer)
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				if funcutils.IsMethodUseless(m.Obj(), pkg) || funcutils.IsMethodExported(m.Obj()) {
					continue
				}
				//all Exported Methods set to map
				mapOfProj.setOneFuncToInternalMethodDecl(m.Obj(), pkg)
			}

			ms = pkg.Prog.MethodSets.MethodSet(member.Type())
			if ms.Len() == 0 {
				continue
			}
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i)
				mapOfProj.setOneFuncToAllMethodDecl(m.Obj(), pkg)
			}
		}
	}
}
