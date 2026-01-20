//go:build selfupdate

package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2026 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"strings"

	"github.com/essentialkaos/ek/v13/fmtc"
	"github.com/essentialkaos/ek/v13/options"
	"github.com/essentialkaos/ek/v13/selfupdate"
	"github.com/essentialkaos/ek/v13/selfupdate/interactive"
	storage "github.com/essentialkaos/ek/v13/selfupdate/storage/basic"
	"github.com/essentialkaos/ek/v13/terminal"
)

// ////////////////////////////////////////////////////////////////////////////////// //

var withSelfUpdate = true

// ////////////////////////////////////////////////////////////////////////////////// //

// updateBinary updates current binary to the latest version
func updateBinary() int {
	quiet := strings.ToLower(options.GetS(OPT_UPDATE)) == "quiet"
	updInfo, hasUpdate, err := storage.NewStorage("https://apps.kaos.ws").Check(APP, VER)

	if err != nil {
		if !quiet {
			terminal.Error("Can't update binary: %v", err)
		}

		return 1
	}

	if !hasUpdate {
		fmtc.If(!quiet).Println("{g}You are using the latest version of the app{!}")
		return 0
	}

	pubKey := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnYHsOTvrKqeE97dsEt7Ge97+yUcvQJn1++s++FqShDyqwV8CcoKp0E6nDTc8SxInZ5wxwcScxSicfvC9S73OSg=="

	if quiet {
		err = selfupdate.Run(updInfo, pubKey, nil)
	} else {
		err = selfupdate.Run(updInfo, pubKey, interactive.Dispatcher())
	}

	if err != nil {
		return 1
	}

	return 0
}

// ////////////////////////////////////////////////////////////////////////////////// //
