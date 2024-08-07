package main

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2023 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	_ "embed"

	CLI "github.com/essentialkaos/sslcli/v3/cli"
)

// ////////////////////////////////////////////////////////////////////////////////// //

//go:embed go.mod
var gomod []byte

// gitrev is short hash of the latest git commit
var gitrev string

// ////////////////////////////////////////////////////////////////////////////////// //

func main() {
	CLI.Run(gitrev, gomod)
}
