package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestBins(t *testing.T) {
	os.Chdir("/home/user/workspace/gowork/src/purelib/casbin")
	findcmd := exec.Command("/bin/sh", "-c", `find . -name "Fuzz*.zip" | grep -v "resultFuzz"`)
	outinfo, err := findcmd.CombinedOutput()
	if err != nil {
		panic(err)
	}
	bins := strings.Split(strings.TrimRight(string(outinfo), "\n"), "\n")
	for idx, binname := range bins {
		targetF := binname[strings.LastIndex(binname, "/")+1 : strings.LastIndex(binname, ".")] // FuzzTestXxx
		t.Log(idx, targetF)
	}
}
