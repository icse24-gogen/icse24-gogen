package main

import (
	"flag"
	"xyz.asd.qwe/gout-static-analysis/pkg/scorer"
)

//var (
//	projPath = flag.String("proj", "", "assign the root dir of a project, if not assigned, the current dir will be filled in")
//	projpkgs []*ssa.Package
//)

func main() {

	//flag.Parse()
	//apiutil.LoadPkg(flag.Args()[0])

	flag.Parse()
	patterns := flag.Args()

	//testcaseextractor.TestcaseExtractor(patterns)

	s := scorer.NewScorer(patterns)
	s.ShowStatistics()

	//s.OutputDensityCsv()
	//s.ShowStatistics()
	//scorer.NewScorer(patterns)

	//scorer.MyExtractTry(patterns)

	//s.ShowScore()
	//s.GetWhichType()
	/*
		for _, pkg := range pkgs {
			if pkg == nil {
				fmt.Println("skipping nil")
				//TODO(jx): why all packages can return some nil package?
				continue
			}
			scorer.GetMultiArgTestee(pkg)
		}
	*/
}
