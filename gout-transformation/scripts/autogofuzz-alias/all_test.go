package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestDir(t *testing.T) {
	s := "xx.go"
	path := filepath.Dir(s)
	fmt.Println(path)

}

func TestDateTime(t *testing.T) {
	now := time.Now().Add(8 * time.Hour)
	fmt.Println(now.String())
}
