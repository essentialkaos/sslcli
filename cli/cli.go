package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2017 ESSENTIAL KAOS                         //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"errors"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	"pkg.re/essentialkaos/ek.v7/arg"
	"pkg.re/essentialkaos/ek.v7/fmtc"
	"pkg.re/essentialkaos/ek.v7/fmtutil"
	"pkg.re/essentialkaos/ek.v7/fsutil"
	"pkg.re/essentialkaos/ek.v7/usage"
	"pkg.re/essentialkaos/ek.v7/usage/update"

	"pkg.re/essentialkaos/sslscan.v5"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const (
	APP  = "SSLScan Client"
	VER  = "1.4.0"
	DESC = "Command-line client for the SSL Labs API"
)

const (
	ARG_FORMAT          = "f:format"
	ARG_DETAILED        = "d:detailed"
	ARG_IGNORE_MISMATCH = "i:ignore-mismatch"
	ARG_AVOID_CACHE     = "c:avoid-cache"
	ARG_PUBLIC          = "p:public"
	ARG_PERFECT         = "P:perfect"
	ARG_QUIET           = "q:quiet"
	ARG_NOTIFY          = "n:notify"
	ARG_NO_COLOR        = "nc:no-color"
	ARG_HELP            = "h:help"
	ARG_VER             = "v:version"
)

const (
	FORMAT_TEXT = "text"
	FORMAT_YAML = "yaml"
	FORMAT_JSON = "json"
	FORMAT_XML  = "xml"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type HostCheckInfo struct {
	Host            string               `json:"host"`
	LowestGrade     string               `json:"lowestGrade"`
	HighestGrade    string               `json:"highestGrade"`
	LowestGradeNum  float64              `json:"lowestGradeNum"`
	HighestGradeNum float64              `json:"highestGradeNum"`
	Endpoints       []*EndpointCheckInfo `json:"endpoints"`
}

type EndpointCheckInfo struct {
	IPAdress string  `json:"ipAddress"`
	Grade    string  `json:"grade"`
	GradeNum float64 `json:"gradeNum"`
}

// ////////////////////////////////////////////////////////////////////////////////// //

var argMap = arg.Map{
	ARG_FORMAT:          &arg.V{},
	ARG_DETAILED:        &arg.V{Type: arg.BOOL},
	ARG_IGNORE_MISMATCH: &arg.V{Type: arg.BOOL},
	ARG_AVOID_CACHE:     &arg.V{Type: arg.BOOL},
	ARG_PUBLIC:          &arg.V{Type: arg.BOOL},
	ARG_PERFECT:         &arg.V{Type: arg.BOOL},
	ARG_QUIET:           &arg.V{Type: arg.BOOL},
	ARG_NOTIFY:          &arg.V{Type: arg.BOOL},
	ARG_NO_COLOR:        &arg.V{Type: arg.BOOL},
	ARG_HELP:            &arg.V{Type: arg.BOOL, Alias: "u:usage"},
	ARG_VER:             &arg.V{Type: arg.BOOL, Alias: "ver"},
}

var gradeNumMap = map[string]float64{
	"A+":  4.3,
	"A":   4.0,
	"A-":  3.7,
	"B":   3.0,
	"C":   2.0,
	"D":   1.0,
	"E":   0.5,
	"F":   0.0,
	"T":   0.0,
	"M":   0.0,
	"Err": 0.0,
}

var api *sslscan.API

// ////////////////////////////////////////////////////////////////////////////////// //

// Init starts initialization rutine
func Init() {
	args, errs := arg.Parse(argMap)

	if len(errs) != 0 {
		fmtc.Println("{r}Arguments parsing errors:{!}")

		for _, err := range errs {
			fmtc.Printf("  {r}%v{!}\n", err)
		}

		os.Exit(1)
	}

	if arg.GetB(ARG_NO_COLOR) {
		fmtc.DisableColors = true
	}

	if arg.GetB(ARG_VER) {
		showAbout()
		return
	}

	if arg.GetB(ARG_HELP) || len(args) == 0 {
		showUsage()
		return
	}

	runtime.GOMAXPROCS(2)

	process(args)
}

// process starting request processing
func process(args []string) {
	var (
		ok    bool
		err   error
		hosts []string
	)

	api, err = sslscan.NewAPI("SSLCli", VER)

	if err != nil {
		if !arg.GetB(ARG_FORMAT) {
			fmtc.Printf("{r}%v{!}\n", err)
		}

		os.Exit(1)
	}

	// By default all fine
	ok = true
	hosts = args

	if fsutil.CheckPerms("FR", hosts[0]) {
		hosts, err = readHostList(hosts[0])

		if err != nil && arg.GetB(ARG_FORMAT) {
			fmtc.Printf("{r}%v{!}\n", err)
			os.Exit(1)
		}
	}

	var (
		grade      string
		checksInfo []*HostCheckInfo
		checkInfo  *HostCheckInfo
	)

	for _, host := range hosts {

		switch {
		case arg.GetB(ARG_QUIET):
			grade, _ = quietCheck(host)
		case arg.GetB(ARG_FORMAT):
			grade, checkInfo = quietCheck(host)
			checksInfo = append(checksInfo, checkInfo)
		default:
			grade = check(host)
		}

		switch {
		case arg.GetB(ARG_PERFECT) && grade != "A+":
			ok = false
		case grade[:1] != "A":
			ok = false
		}
	}

	if arg.GetB(ARG_FORMAT) {
		switch arg.GetS(ARG_FORMAT) {
		case FORMAT_TEXT:
			encodeAsText(checksInfo)
		case FORMAT_JSON:
			encodeAsJSON(checksInfo)
		case FORMAT_XML:
			encodeAsXML(checksInfo)
		case FORMAT_YAML:
			encodeAsYAML(checksInfo)
		default:
			os.Exit(1)
		}
	}

	if arg.GetB(ARG_NOTIFY) {
		fmtc.Bell()
	}

	if !ok {
		os.Exit(1)
	}
}

// check check some host
func check(host string) string {
	var err error
	var info *sslscan.AnalyzeInfo

	showServerMessage()

	params := sslscan.AnalyzeParams{
		Public:         arg.GetB(ARG_PUBLIC),
		StartNew:       arg.GetB(ARG_AVOID_CACHE),
		FromCache:      !arg.GetB(ARG_AVOID_CACHE),
		IgnoreMismatch: arg.GetB(ARG_IGNORE_MISMATCH),
	}

	fmtc.Printf("{*}%s{!} → ", host)

	ap, err := api.Analyze(host, params)

	if err != nil {
		fmtc.Printf("{r}%v{!}\n", err)
		return "T"
	}

	t := &fmtc.T{}

	for {
		info, err = ap.Info()

		if err != nil {
			t.Printf("{r}%v{!}\n", err)
			return "Err"
		}

		if info.Status == sslscan.STATUS_ERROR {
			t.Printf("{r}%s{!}\n", info.StatusMessage)
			return "Err"
		} else if info.Status == sslscan.STATUS_READY {
			break
		}

		if len(info.Endpoints) != 0 {
			message := getStatusInProgress(info.Endpoints)

			if message != "" {
				t.Printf("{s}%s...{!}", message)
			}
		}

		if info.Status == sslscan.STATUS_IN_PROGRESS {
			time.Sleep(6 * time.Second)
		} else {
			time.Sleep(2 * time.Second)
		}
	}

	if len(info.Endpoints) == 1 {
		t.Println(getColoredGrade(info.Endpoints[0].Grade))
	} else {
		t.Println(getColoredGrades(info.Endpoints))
	}

	if arg.GetB(ARG_DETAILED) {
		printDetailedInfo(ap, info)
	}

	lowestGrade, _ := getGrades(info.Endpoints)

	return lowestGrade
}

// showServerMessage show message from SSL Labs API
func showServerMessage() {
	serverMessage := strings.Join(api.Info.Messages, " ")
	wrappedMessage := fmtutil.Wrap(serverMessage, "", 80)

	var coloredMessage string

	for _, line := range strings.Split(wrappedMessage, "\n") {
		coloredMessage += "{s-}" + line + "{!}\n"
	}

	fmtc.NewLine()
	fmtc.Println(coloredMessage)
}

// quietCheck check some host without any output to console
func quietCheck(host string) (string, *HostCheckInfo) {
	var err error
	var info *sslscan.AnalyzeInfo

	var checkInfo = &HostCheckInfo{
		Host:            host,
		LowestGrade:     "T",
		HighestGrade:    "T",
		LowestGradeNum:  0.0,
		HighestGradeNum: 0.0,
		Endpoints:       make([]*EndpointCheckInfo, 0),
	}

	params := sslscan.AnalyzeParams{
		Public:         arg.GetB(ARG_PUBLIC),
		StartNew:       arg.GetB(ARG_AVOID_CACHE),
		FromCache:      !arg.GetB(ARG_AVOID_CACHE),
		IgnoreMismatch: arg.GetB(ARG_IGNORE_MISMATCH),
	}

	ap, err := api.Analyze(host, params)

	if err != nil {
		return "Err", checkInfo
	}

	for {
		info, err = ap.Info()

		if err != nil {
			return "Err", checkInfo
		}

		if info.Status == sslscan.STATUS_ERROR {
			return "Err", checkInfo
		} else if info.Status == sslscan.STATUS_READY {
			break
		}

		time.Sleep(time.Second)
	}

	appendEndpointsInfo(checkInfo, info.Endpoints)

	lowestGrade, highestGrade := getGrades(info.Endpoints)

	checkInfo.LowestGrade = lowestGrade
	checkInfo.HighestGrade = highestGrade
	checkInfo.LowestGradeNum = gradeNumMap[lowestGrade]
	checkInfo.HighestGradeNum = gradeNumMap[highestGrade]

	return lowestGrade, checkInfo
}

// getColoredGrade return grade with color tags
func getColoredGrade(grade string) string {
	switch grade {
	case "A", "A-", "A+":
		return "{g}" + grade + "{!}"
	case "B", "C", "D", "E":
		return "{y}" + grade + "{!}"
	case "":
		return "{r}Err{!}"
	}

	return "{r}" + grade + "{!}"
}

// getColoredGrades return grades with color tags for many endpoints
func getColoredGrades(endpoints []*sslscan.EndpointInfo) string {
	var result string

	for _, endpoint := range endpoints {
		result += getColoredGrade(endpoint.Grade) + "{s-}/" + endpoint.IPAdress + "{!} "
	}

	return result
}

// getGrades return lowest and highest grades
func getGrades(endpoints []*sslscan.EndpointInfo) (string, string) {
	var (
		lowest  = 8
		highest = -2
	)

	gradesW := map[string]int{
		"Err": -2, "M": -1, "T": 0, "F": 1, "E": 2, "D": 3,
		"C": 4, "B": 5, "A": 6, "A-": 7, "A+": 8,
	}
	gradesN := map[int]string{
		-2: "Err", -1: "M", 0: "T", 1: "F", 2: "E", 3: "D",
		4: "C", 5: "B", 6: "A", 7: "A-", 8: "A+",
	}

	for _, endpoint := range endpoints {
		w := gradesW[getNormGrade(endpoint.Grade)]

		if w < lowest {
			lowest = w
		}

		if w > highest {
			highest = w
		}
	}

	return gradesN[lowest], gradesN[highest]
}

// getStatusInProgress return status message from any in-progress endpoint
func getStatusInProgress(endpoints []*sslscan.EndpointInfo) string {
	if len(endpoints) == 1 {
		return endpoints[0].StatusDetailsMessage
	}

	for num, endpoint := range endpoints {
		if endpoint.Grade != "" {
			continue
		}

		if endpoint.StatusDetailsMessage != "" {
			return fmtc.Sprintf("#%d: %s", num, endpoint.StatusDetailsMessage)
		}
	}

	return ""
}

// readHostList read file with hosts
func readHostList(file string) ([]string, error) {
	var result []string

	fd, err := os.OpenFile(file, os.O_RDONLY, 0)

	if err != nil {
		return result, err
	}

	defer fd.Close()

	listData, err := ioutil.ReadAll(fd)

	if err != nil {
		return result, err
	}

	list := strings.Split(string(listData[:]), "\n")

	for _, host := range list {
		if host != "" {
			result = append(result, strings.TrimRight(host, " "))
		}
	}

	if len(result) == 0 {
		return result, errors.New("File with hosts is empty")
	}

	return result, nil
}

// appendEndpointsInfo append endpoint check result to struct with info about all checks for host
func appendEndpointsInfo(checkInfo *HostCheckInfo, endpoints []*sslscan.EndpointInfo) {
	for _, endpoint := range endpoints {
		grade := getNormGrade(endpoint.Grade)

		checkInfo.Endpoints = append(checkInfo.Endpoints, &EndpointCheckInfo{
			IPAdress: endpoint.IPAdress,
			Grade:    grade,
			GradeNum: gradeNumMap[grade],
		})
	}
}

// getNormGrade return grade or error
func getNormGrade(grade string) string {
	switch grade {
	case "":
		return "Err"
	default:
		return grade
	}
}

// ////////////////////////////////////////////////////////////////////////////////// //

func showUsage() {
	info := usage.NewInfo("", "host...")

	info.AddOption(ARG_FORMAT, "Output result in different formats", "text|json|yaml|xml")
	info.AddOption(ARG_DETAILED, "Show detailed info for each endpoint")
	info.AddOption(ARG_IGNORE_MISMATCH, "Proceed with assessments on certificate mismatch")
	info.AddOption(ARG_AVOID_CACHE, "Disable cache usage")
	info.AddOption(ARG_PUBLIC, "Publish results on sslscan.com")
	info.AddOption(ARG_PERFECT, "Return non-zero exit code if not A+")
	info.AddOption(ARG_NOTIFY, "Notify when check is done")
	info.AddOption(ARG_QUIET, "Don't show any output")
	info.AddOption(ARG_NO_COLOR, "Disable colors in output")
	info.AddOption(ARG_HELP, "Show this help message")
	info.AddOption(ARG_VER, "Show version")

	info.AddExample("google.com", "Check google.com")
	info.AddExample("-P google.com", "Check google.com and return zero exit code only if result is perfect (A+)")
	info.AddExample("-p -c google.com", "Check google.com, publish results, disable cache usage")
	info.AddExample("hosts.txt", "Check all hosts defined in hosts.txt file")

	info.Render()
}

func showAbout() {
	about := &usage.About{
		App:           APP,
		Version:       VER,
		Desc:          DESC,
		Year:          2009,
		Owner:         "Essential Kaos",
		License:       "Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>",
		UpdateChecker: usage.UpdateChecker{"essentialkaos/sslcli", update.GitHubChecker},
	}

	about.Render()
}
