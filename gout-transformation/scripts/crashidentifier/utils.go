package main

import (
	"fmt"
	"os"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func printSlice(s []interface{}) {
	for _, e := range s {
		fmt.Printf("%v, ", e)
	}
}
