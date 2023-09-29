package ftccomposer

import (
	"text/template"
)

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
package {{.PkgName}}

import (
    target "{{.Imported}}"
    "testing"
)


func Fuzz{{.TestName}}(f *testing.F) {
	testcases := []string{"12345", "12346"}
    for _, tc := range testcases {
        f.Add(tc) // Use f.Add to provide a seed corpus
    }
    f.Fuzz(func(t *testing.T, fs0 string) {{.Body}})
}`))
