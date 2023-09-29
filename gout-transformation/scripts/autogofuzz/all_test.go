package main

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestDir(t *testing.T) {
	s := "xx.go"
	path := filepath.Dir(s)
	fmt.Println(path)

}
