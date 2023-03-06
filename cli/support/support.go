package support

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2023 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/essentialkaos/ek/v12/fmtc"
	"github.com/essentialkaos/ek/v12/fmtutil"
	"github.com/essentialkaos/ek/v12/fsutil"
	"github.com/essentialkaos/ek/v12/hash"
	"github.com/essentialkaos/ek/v12/strutil"
	"github.com/essentialkaos/ek/v12/system"

	"github.com/essentialkaos/depsy"
)

// ////////////////////////////////////////////////////////////////////////////////// //

// ShowSupportInfo prints verbose info about application, system, dependencies and
// important environment
func ShowSupportInfo(app, ver, gitRev string, gomod []byte) {
	fmtutil.SeparatorTitleColorTag = "{s-}"
	fmtutil.SeparatorFullscreen = false
	fmtutil.SeparatorColorTag = "{s-}"
	fmtutil.SeparatorSize = 80

	showApplicationInfo(app, ver, gitRev)
	showOSInfo()
	showDepsInfo(gomod)

	fmtutil.Separator(false)
}

// ////////////////////////////////////////////////////////////////////////////////// //

// showApplicationInfo shows verbose information about application
func showApplicationInfo(app, ver, gitRev string) {
	fmtutil.Separator(false, "APPLICATION INFO")

	printInfo(7, "Name", app)
	printInfo(7, "Version", ver)

	printInfo(7, "Go", fmtc.Sprintf(
		"%s {s}(%s/%s){!}",
		strings.TrimLeft(runtime.Version(), "go"),
		runtime.GOOS, runtime.GOARCH,
	))

	if gitRev != "" {
		if !fmtc.DisableColors && fmtc.IsTrueColorSupported() {
			printInfo(7, "Git SHA", gitRev+getHashColorBullet(gitRev))
		} else {
			printInfo(7, "Git SHA", gitRev)
		}
	}

	bin, _ := os.Executable()
	binSHA := hash.FileHash(bin)

	if binSHA != "" {
		binSHA = strutil.Head(binSHA, 7)
		if !fmtc.DisableColors && fmtc.IsTrueColorSupported() {
			printInfo(7, "Bin SHA", binSHA+getHashColorBullet(binSHA))
		} else {
			printInfo(7, "Bin SHA", binSHA)
		}
	}
}

// showOSInfo shows verbose information about system
func showOSInfo() {
	osInfo, err := system.GetOSInfo()

	if err == nil {
		fmtutil.Separator(false, "OS INFO")

		printInfo(12, "Name", osInfo.Name)
		printInfo(12, "Pretty Name", osInfo.PrettyName)
		printInfo(12, "Version", osInfo.VersionID)
		printInfo(12, "ID", osInfo.ID)
		printInfo(12, "ID Like", osInfo.IDLike)
		printInfo(12, "Version ID", osInfo.VersionID)
		printInfo(12, "Version Code", osInfo.VersionCodename)
		printInfo(12, "CPE", osInfo.CPEName)
	}

	systemInfo, err := system.GetSystemInfo()

	if err != nil {
		return
	} else {
		if osInfo == nil {
			fmtutil.Separator(false, "SYSTEM INFO")
			printInfo(12, "Name", systemInfo.OS)
		}
	}

	printInfo(12, "Arch", systemInfo.Arch)
	printInfo(12, "Kernel", systemInfo.Kernel)

	containerEngine := "No"

	switch {
	case fsutil.IsExist("/.dockerenv"):
		containerEngine = "Yes (Docker)"
	case fsutil.IsExist("/run/.containerenv"):
		containerEngine = "Yes (Podman)"
	}

	fmtc.NewLine()

	printInfo(12, "Container", containerEngine)
}

// showDepsInfo shows information about all dependencies
func showDepsInfo(gomod []byte) {
	deps := depsy.Extract(gomod, false)

	if len(deps) == 0 {
		return
	}

	fmtutil.Separator(false, "DEPENDENCIES")

	for _, dep := range deps {
		if dep.Extra == "" {
			fmtc.Printf(" {s}%8s{!}  %s\n", dep.Version, dep.Path)
		} else {
			fmtc.Printf(" {s}%8s{!}  %s {s-}(%s){!}\n", dep.Version, dep.Path, dep.Extra)
		}
	}
}

// getHashColorBullet return bullet with color from hash
func getHashColorBullet(v string) string {
	if len(v) > 6 {
		v = strutil.Head(v, 6)
	}

	return fmtc.Sprintf(" {#" + strutil.Head(v, 6) + "}● {!}")
}

// printInfo formats and prints info record
func printInfo(size int, name, value string) {
	name = name + ":"
	size++

	if value == "" {
		fm := fmt.Sprintf("  {*}%%-%ds{!}  {s-}—{!}\n", size)
		fmtc.Printf(fm, name)
	} else {
		fm := fmt.Sprintf("  {*}%%-%ds{!}  %%s\n", size)
		fmtc.Printf(fm, name, value)
	}
}

// ////////////////////////////////////////////////////////////////////////////////// //
