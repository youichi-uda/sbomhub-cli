// Package main is a reachability test fixture for go_analyzer_test.go.
//
// The fixture requires example.test/vulnpkg in its go.mod. With no
// vulnerable symbols supplied, the analyzer stops at stage 1 and reports
// StatusImportOnly (the module is present in the module graph).
package main

import "fmt"

func main() {
	fmt.Println("imports vulnpkg transitively; no symbol supplied")
}
