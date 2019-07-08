package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2019 ESSENTIAL KAOS                         //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"pkg.re/essentialkaos/ek.v10/fmtc"
	"pkg.re/essentialkaos/ek.v10/fmtutil"
	"pkg.re/essentialkaos/ek.v10/fsutil"
	"pkg.re/essentialkaos/ek.v10/options"
	"pkg.re/essentialkaos/ek.v10/strutil"
	"pkg.re/essentialkaos/ek.v10/usage"
	"pkg.re/essentialkaos/ek.v10/usage/update"

	"pkg.re/essentialkaos/sslscan.v11"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const (
	APP  = "SSLScan Client"
	VER  = "2.4.0"
	DESC = "Command-line client for the SSL Labs API"
)

const (
	OPT_FORMAT          = "f:format"
	OPT_DETAILED        = "d:detailed"
	OPT_IGNORE_MISMATCH = "i:ignore-mismatch"
	OPT_AVOID_CACHE     = "c:avoid-cache"
	OPT_PUBLIC          = "p:public"
	OPT_PERFECT         = "P:perfect"
	OPT_MAX_LEFT        = "M:max-left"
	OPT_QUIET           = "q:quiet"
	OPT_NOTIFY          = "n:notify"
	OPT_NO_COLOR        = "nc:no-color"
	OPT_HELP            = "h:help"
	OPT_VER             = "v:version"
)

const (
	DELAY_PRE_CHECK = 2 * time.Second
	DELAY_PROGRESS  = 6 * time.Second
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

var optMap = options.Map{
	OPT_FORMAT:          {},
	OPT_MAX_LEFT:        {},
	OPT_DETAILED:        {Type: options.BOOL},
	OPT_IGNORE_MISMATCH: {Type: options.BOOL},
	OPT_AVOID_CACHE:     {Type: options.BOOL},
	OPT_PUBLIC:          {Type: options.BOOL},
	OPT_PERFECT:         {Type: options.BOOL},
	OPT_QUIET:           {Type: options.BOOL},
	OPT_NOTIFY:          {Type: options.BOOL},
	OPT_NO_COLOR:        {Type: options.BOOL},
	OPT_HELP:            {Type: options.BOOL, Alias: "u:usage"},
	OPT_VER:             {Type: options.BOOL, Alias: "ver"},
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
var maxLeftToExpiry int64
var serverMessageShown bool

// ////////////////////////////////////////////////////////////////////////////////// //

// Init starts initialization rutine
func Init() {
	args, errs := options.Parse(optMap)

	if len(errs) != 0 {
		printError("Arguments parsing errors:")

		for _, err := range errs {
			printError("  %v", err)
		}

		os.Exit(1)
	}

	configureUI()
	prepare()

	if options.GetB(OPT_VER) {
		showAbout()
		return
	}

	if options.GetB(OPT_HELP) || len(args) == 0 {
		showUsage()
		return
	}

	runtime.GOMAXPROCS(2)

	process(args)
}

// configureUI configures user interface
func configureUI() {
	if options.GetB(OPT_NO_COLOR) {
		fmtc.DisableColors = true
	}

	fmtutil.SeparatorSymbol = "–"
}

// prepare prepares utility for processing data
func prepare() {
	if !options.Has(OPT_MAX_LEFT) {
		return
	}

	var err error

	maxLeftToExpiry, err = parseMaxLeft(options.GetS(OPT_MAX_LEFT))

	if err != nil {
		printError(err.Error())
		os.Exit(1)
	}
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
		if !options.GetB(OPT_FORMAT) {
			printError(err.Error())
		}

		os.Exit(1)
	}

	// By default all fine
	ok = true
	hosts = args

	if fsutil.CheckPerms("FR", hosts[0]) {
		hosts, err = readHostList(hosts[0])

		if err != nil && options.GetB(OPT_FORMAT) {
			printError(err.Error())
			os.Exit(1)
		}
	}

	var grade string
	var expiredSoon bool
	var checksInfo []*HostCheckInfo
	var checkInfo *HostCheckInfo

	for _, host := range hosts {
		switch {
		case options.GetB(OPT_QUIET):
			grade, expiredSoon, _ = quietCheck(host)
		case options.GetB(OPT_FORMAT):
			grade, expiredSoon, checkInfo = quietCheck(host)
			checksInfo = append(checksInfo, checkInfo)
		default:
			grade, expiredSoon = check(host)
			fmtc.NewLine()
		}

		switch {
		case options.GetB(OPT_PERFECT) && grade != "A+",
			strutil.Head(grade, 1) != "A",
			expiredSoon:
			ok = false
		}
	}

	if options.Has(OPT_FORMAT) {
		renderReport(checksInfo)
	}

	if options.GetB(OPT_NOTIFY) {
		fmtc.Bell()
	}

	if !ok {
		os.Exit(1)
	}
}

// check check some host
func check(host string) (string, bool) {
	var err error
	var info *sslscan.AnalyzeInfo

	showServerMessage()

	params := sslscan.AnalyzeParams{
		Public:         options.GetB(OPT_PUBLIC),
		StartNew:       options.GetB(OPT_AVOID_CACHE),
		FromCache:      !options.GetB(OPT_AVOID_CACHE),
		IgnoreMismatch: options.GetB(OPT_IGNORE_MISMATCH),
	}

	fmtc.TPrintf("{*}%s{!} → {s}Preparing for tests…{!}", host)

	ap, err := api.Analyze(host, params)

	if err != nil {
		fmtc.TPrintf("{*}%s{!} → {r}%v{!}\n", host, err)
		return "T", false
	}

	for {
		info, err = ap.Info(false, params.FromCache)

		if err != nil {
			fmtc.TPrintf("{*}%s{!} → {r}%v{!}\n", host, err)
			return "Err", false
		}

		if info.Status == sslscan.STATUS_ERROR {
			fmtc.TPrintf("{*}%s{!} → {r}%s{!}\n", host, info.StatusMessage)
			return "Err", false
		} else if info.Status == sslscan.STATUS_READY {
			break
		}

		if len(info.Endpoints) != 0 {
			message := getStatusInProgress(info.Endpoints)

			if message != "" {
				fmtc.TPrintf("{*}%s{!} → {s}%s…{!}", host, message)
			}
		}

		if info.Status == sslscan.STATUS_IN_PROGRESS {
			time.Sleep(DELAY_PROGRESS)
		} else {
			time.Sleep(DELAY_PRE_CHECK)
		}
	}

	expiryMessage := getExpiryMessage(ap, maxLeftToExpiry)

	if len(info.Endpoints) == 1 {
		fmtc.TPrintf("{*}%s{!} → "+getColoredGrade(info.Endpoints[0].Grade)+expiryMessage+"\n", host)
	} else {
		fmtc.TPrintf("{*}%s{!} → "+getColoredGrades(info.Endpoints)+expiryMessage+"\n", host)
	}

	if options.GetB(OPT_DETAILED) {
		printDetailedInfo(ap, true)
	}

	lowestGrade, _ := getGrades(info.Endpoints)

	return lowestGrade, expiryMessage != ""
}

// showServerMessage show message from SSL Labs API
func showServerMessage() {
	if serverMessageShown {
		return
	}

	serverMessage := strings.Join(api.Info.Messages, " ")
	wrappedMessage := fmtutil.Wrap(serverMessage, "", 80)

	var coloredMessage string

	for _, line := range strings.Split(wrappedMessage, "\n") {
		coloredMessage += "{s-}" + line + "{!}\n"
	}

	fmtc.NewLine()
	fmtc.Println(coloredMessage)
	fmtc.Printf(
		"{s-}Assessments: %d/%d (CoolOff: %d)\n",
		api.Info.CurrentAssessments+1,
		api.Info.MaxAssessments,
		api.Info.NewAssessmentCoolOff,
	)
	fmtc.NewLine()

	serverMessageShown = true
}

// quietCheck check some host without any output to console
func quietCheck(host string) (string, bool, *HostCheckInfo) {
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
		Public:         options.GetB(OPT_PUBLIC),
		StartNew:       options.GetB(OPT_AVOID_CACHE),
		FromCache:      !options.GetB(OPT_AVOID_CACHE),
		IgnoreMismatch: options.GetB(OPT_IGNORE_MISMATCH),
	}

	ap, err := api.Analyze(host, params)

	if err != nil {
		return "Err", false, checkInfo
	}

	for {
		info, err = ap.Info(false, params.FromCache)

		if err != nil {
			return "Err", false, checkInfo
		}

		if info.Status == sslscan.STATUS_ERROR {
			return "Err", false, checkInfo
		} else if info.Status == sslscan.STATUS_READY {
			break
		}

		time.Sleep(time.Second)
	}

	var expiredSoon bool

	if maxLeftToExpiry > 0 {
		expiredSoon = getExpiryMessage(ap, maxLeftToExpiry) != ""
	}

	appendEndpointsInfo(checkInfo, info.Endpoints)

	lowestGrade, highestGrade := getGrades(info.Endpoints)

	checkInfo.LowestGrade = lowestGrade
	checkInfo.HighestGrade = highestGrade
	checkInfo.LowestGradeNum = gradeNumMap[lowestGrade]
	checkInfo.HighestGradeNum = gradeNumMap[highestGrade]

	return lowestGrade, expiredSoon, checkInfo
}

// renderReport renders report in different formats
func renderReport(checksInfo []*HostCheckInfo) {
	switch options.GetS(OPT_FORMAT) {
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
			return fmt.Sprintf("#%d: %s", num, endpoint.StatusDetailsMessage)
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

// parseMaxLeft parses max left option value
func parseMaxLeft(dur string) (int64, error) {
	tm := strutil.Tail(dur, 1)
	t := strings.Trim(dur, "dwmy")
	ti, err := strconv.ParseInt(t, 10, 64)

	if err != nil {
		return -1, fmt.Errorf("Invalid value for --max-left option: %s", dur)
	}

	switch strings.ToLower(tm) {
	case "w":
		return ti * 604800, nil
	case "m":
		return ti * 2592000, nil
	case "y":
		return ti * 31536000, nil
	default:
		return ti * 86400, nil
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

// printError prints error message to console
func printError(f string, a ...interface{}) {
	fmtc.Fprintf(os.Stderr, "{r}"+f+"{!}\n", a...)
}

// ////////////////////////////////////////////////////////////////////////////////// //

func showUsage() {
	info := usage.NewInfo("", "host…")

	info.AddOption(OPT_FORMAT, "Output result in different formats", "text|json|yaml|xml")
	info.AddOption(OPT_DETAILED, "Show detailed info for each endpoint")
	info.AddOption(OPT_IGNORE_MISMATCH, "Proceed with assessments on certificate mismatch")
	info.AddOption(OPT_AVOID_CACHE, "Disable cache usage")
	info.AddOption(OPT_PUBLIC, "Publish results on sslscan.com")
	info.AddOption(OPT_PERFECT, "Return non-zero exit code if not A+")
	info.AddOption(OPT_MAX_LEFT, "Check expiry date {s-}(num + d/w/m/y){!}", "duration")
	info.AddOption(OPT_NOTIFY, "Notify when check is done")
	info.AddOption(OPT_QUIET, "Don't show any output")
	info.AddOption(OPT_NO_COLOR, "Disable colors in output")
	info.AddOption(OPT_HELP, "Show this help message")
	info.AddOption(OPT_VER, "Show version")

	info.AddExample("google.com", "Check google.com")
	info.AddExample("-P google.com", "Check google.com and return zero exit code only if result is perfect (A+)")
	info.AddExample("-p -c google.com", "Check google.com, publish results, disable cache usage")
	info.AddExample("-M 3m -q google.com", "Check google.com in quiet mode and return error if cert expire in 3 months")
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
