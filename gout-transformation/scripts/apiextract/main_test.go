package main

import (
	"fmt"
	"testing"
)

func TestListEqual(t *testing.T) {
	a := []int{1, 2, 3}
	b := []int{1, 2, 3}
	fmt.Println(listEqual(a, b))
}
