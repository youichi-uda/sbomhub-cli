// Package main is a fixture source tree for reachability_test.go.
//
// Its go.mod requires example.test/vulnpkg, so the analyzer (run with no
// vulnerable symbols) reports import_only for that module and not_present
// for any module absent from go.mod. The analyzer reads go.mod only in
// this path (no packages.Load), so the fixture stays offline-safe.
package main

import "fmt"

func main() {
	fmt.Println("reachability fixture")
}
