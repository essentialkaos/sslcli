package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2023 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/essentialkaos/ek/v13/fmtc"
	"github.com/essentialkaos/ek/v13/fmtutil"
	"github.com/essentialkaos/ek/v13/fsutil"
	"github.com/essentialkaos/ek/v13/options"
	"github.com/essentialkaos/ek/v13/pager"
	"github.com/essentialkaos/ek/v13/req"
	"github.com/essentialkaos/ek/v13/strutil"
	"github.com/essentialkaos/ek/v13/support"
	"github.com/essentialkaos/ek/v13/support/deps"
	"github.com/essentialkaos/ek/v13/terminal"
	"github.com/essentialkaos/ek/v13/timeutil"
	"github.com/essentialkaos/ek/v13/usage"
	"github.com/essentialkaos/ek/v13/usage/completion/bash"
	"github.com/essentialkaos/ek/v13/usage/completion/fish"
	"github.com/essentialkaos/ek/v13/usage/completion/zsh"
	"github.com/essentialkaos/ek/v13/usage/man"
	"github.com/essentialkaos/ek/v13/usage/update"

	sslscan "github.com/essentialkaos/sslscan/v14"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const (
	APP  = "SSLScan Client"
	VER  = "3.0.2"
	DESC = "Command-line client for the SSL Labs API"
)

const (
	OPT_EMAIL           = "e:email"
	OPT_FORMAT          = "f:format"
	OPT_DETAILED        = "d:detailed"
	OPT_IGNORE_MISMATCH = "i:ignore-mismatch"
	OPT_AVOID_CACHE     = "c:avoid-cache"
	OPT_PUBLIC          = "p:public"
	OPT_PERFECT         = "P:perfect"
	OPT_MAX_LEFT        = "M:max-left"
	OPT_QUIET           = "q:quiet"
	OPT_NOTIFY          = "n:notify"
	OPT_PAGER           = "G:pager"
	OPT_NO_COLOR        = "nc:no-color"
	OPT_HELP            = "h:help"
	OPT_VER             = "v:version"

	OPT_REGISTER = "register"
	OPT_NAME     = "name"
	OPT_ORG      = "org"

	OPT_VERB_VER     = "vv:verbose-version"
	OPT_COMPLETION   = "completion"
	OPT_GENERATE_MAN = "generate-man"
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
	IPAddress string  `json:"ipAddress"`
	Grade     string  `json:"grade"`
	GradeNum  float64 `json:"gradeNum"`
}

// ////////////////////////////////////////////////////////////////////////////////// //

var optMap = options.Map{
	OPT_EMAIL:           {},
	OPT_FORMAT:          {},
	OPT_MAX_LEFT:        {},
	OPT_DETAILED:        {Type: options.BOOL},
	OPT_IGNORE_MISMATCH: {Type: options.BOOL},
	OPT_AVOID_CACHE:     {Type: options.BOOL},
	OPT_PUBLIC:          {Type: options.BOOL},
	OPT_PERFECT:         {Type: options.BOOL},
	OPT_QUIET:           {Type: options.BOOL},
	OPT_NOTIFY:          {Type: options.BOOL},
	OPT_PAGER:           {Type: options.BOOL},
	OPT_NO_COLOR:        {Type: options.BOOL},
	OPT_HELP:            {Type: options.BOOL},
	OPT_VER:             {Type: options.MIXED},

	OPT_REGISTER: {Type: options.BOOL, Bound: []string{OPT_EMAIL, OPT_NAME, OPT_ORG}},
	OPT_NAME:     {},
	OPT_ORG:      {},

	OPT_VERB_VER:     {Type: options.BOOL},
	OPT_COMPLETION:   {},
	OPT_GENERATE_MAN: {Type: options.BOOL},
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
var maxLeftToExpiry time.Duration
var serverMessageShown bool
var email string

var colorTagApp, colorTagVer string

// ////////////////////////////////////////////////////////////////////////////////// //

// Run is main function
func Run(gitRev string, gomod []byte) {
	var err error
	var ok bool

	runtime.GOMAXPROCS(2)

	args, errs := options.Parse(optMap)

	if !errs.IsEmpty() {
		terminal.Error("Options parsing errors:")
		terminal.Error(errs.String())
		os.Exit(1)
	}

	configureUI()

	switch {
	case options.Has(OPT_COMPLETION):
		os.Exit(printCompletion())
	case options.Has(OPT_GENERATE_MAN):
		printMan()
		os.Exit(0)
	case options.GetB(OPT_VER):
		genAbout(gitRev).Print(options.GetS(OPT_VER))
		os.Exit(0)
	case options.GetB(OPT_VERB_VER):
		support.Collect(APP, VER).
			WithRevision(gitRev).
			WithDeps(deps.Extract(gomod)).
			WithChecks(checkAPIAvailability()).
			Print()
		os.Exit(0)
	case options.GetB(OPT_HELP) || (len(args) == 0 && !options.GetB(OPT_REGISTER)):
		genUsage().Print()
		os.Exit(0)
	}

	checkForEmail()

	err = prepare()

	if err != nil {
		terminal.Error(err)
		os.Exit(1)
	}

	switch {
	case options.GetB(OPT_REGISTER):
		err, ok = registerUser()
	default:
		err, ok = runHostCheck(args)
	}

	if err != nil {
		terminal.Error(err)
	}

	if !ok {
		os.Exit(1)
	}
}

// configureUI configures user interface
func configureUI() {
	if options.GetB(OPT_NO_COLOR) {
		fmtc.DisableColors = true
	}

	fmtutil.SeparatorSymbol = "–"
	fmtutil.SeparatorSize = 92

	switch {
	case fmtc.IsTrueColorSupported():
		colorTagApp, colorTagVer = "{*}{#00AFFF}", "{#00AFFF}"
	case fmtc.Is256ColorsSupported():
		colorTagApp, colorTagVer = "{*}{#39}", "{#39}"
	default:
		colorTagApp, colorTagVer = "{*}{c}", "{c}"
	}
}

// prepare prepares utility for processing data
func prepare() error {
	if !options.Has(OPT_MAX_LEFT) {
		return nil
	}

	var err error

	maxLeftToExpiry, err = timeutil.ParseDuration(options.GetS(OPT_MAX_LEFT), 'd')

	if err != nil {
		return err
	}

	return nil
}

// checkForEmail checks for provided email
func checkForEmail() {
	email = strutil.Q(options.GetS(OPT_EMAIL), os.Getenv("SSLLABS_EMAIL"))

	if email != "" {
		return
	}

	terminal.Error("You must provide an email address to make requests to the API.")
	terminal.Error(
		"You can provide it using %s option, or using SSLLABS_EMAIL environment variable.",
		options.Format(OPT_EMAIL),
	)

	fmtc.Println("{s-}More info: {_}https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md#register-for-scan-api-initiation-and-result-fetching{!}")

	os.Exit(1)
}

// registerUser sends user registration request
func registerUser() (error, bool) {
	api, err := sslscan.NewAPI("SSLCli", VER, email)

	if err != nil {
		if !options.GetB(OPT_FORMAT) {
			return fmt.Errorf("Error while sending request to SSL Labs API: %v", err), false
		}

		return nil, false
	}

	org := options.GetS(OPT_ORG)
	name := options.GetS(OPT_NAME)

	if !strings.Contains(name, " ") {
		return fmt.Errorf("Name must contain first and last name"), false
	}

	firstName, lastName, _ := strings.Cut(name, " ")

	fmtc.NewLine()
	fmtc.Printf("  {s}Email:{!}        %s\n", email)
	fmtc.Printf("  {s}Organization:{!} %s\n", org)
	fmtc.Printf("  {s}First Name:{!}   %s\n", firstName)
	fmtc.Printf("  {s}Last Name:{!}    %s\n", lastName)
	fmtc.NewLine()

	resp, err := api.Register(&sslscan.RegisterRequest{
		FirstName:    firstName,
		LastName:     lastName,
		Email:        email,
		Organization: org,
	})

	if err != nil {
		return fmt.Errorf("Can't register user: %v", err), false
	}

	fmtc.Printf("{g}%s{!}\n\n", resp.Message)

	return nil, true
}

// runHostCheck starts check for host
func runHostCheck(args options.Arguments) (error, bool) {
	var ok bool
	var err error
	var hosts []string

	api, err = sslscan.NewAPI("SSLCli", VER, email)

	if err != nil {
		if !options.GetB(OPT_FORMAT) {
			return fmt.Errorf("Error while sending request to SSL Labs API: %v", err), false
		}

		return nil, false
	}

	ok = true // By default everything is fine

	if fsutil.CheckPerms("FR", args.Get(0).String()) {
		hosts, err = readHostList(args.Get(0).String())

		if err != nil {
			if !options.GetB(OPT_FORMAT) {
				return err, false
			}

			return nil, false
		}
	} else {
		hosts = args.Strings()
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
		return nil, false
	}

	return nil, true
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

	fmtc.TPrintf("{*}%s{!} {s-}→{!} {s}Preparing for tests…{!}", host)

	ap, err := api.Analyze(host, params)

	if err != nil {
		fmtc.TPrintf("{*}%s{!} {s-}→{!} {r}%v{!}\n", host, err)
		return "T", false
	}

	for {
		info, err = ap.Info(false, params.FromCache)

		if err != nil {
			fmtc.TPrintf("{*}%s{!} {s-}→{!} {r}%v{!}\n", host, err)
			return "Err", false
		}

		if info.Status == sslscan.STATUS_ERROR {
			fmtc.TPrintf("{*}%s{!} {s-}→{!} {r}%s{!}\n", host, info.StatusMessage)
			return "Err", false
		} else if info.Status == sslscan.STATUS_READY {
			break
		}

		if len(info.Endpoints) != 0 {
			message := getStatusInProgress(info.Endpoints)

			if message != "" {
				fmtc.TPrintf("{*}%s{!} {s-}→{!} {s}%s…{!}", host, message)
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
		fmtc.TPrintf("{*}%s{!} {s-}→{!} "+getColoredGrade(info.Endpoints[0].Grade)+expiryMessage+"\n", host)
	} else {
		fmtc.TPrintf("{*}%s{!} {s-}→{!} "+getColoredGrades(info.Endpoints)+expiryMessage+"\n", host)
	}

	if options.GetB(OPT_DETAILED) {
		if options.GetB(OPT_PAGER) {
			if pager.Setup() == nil {
				defer pager.Complete()
			}
		}

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
		result += getColoredGrade(endpoint.Grade) + "{s}/" + endpoint.IPAddress + "{!} "
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

// readHostList reads file with hosts
func readHostList(file string) ([]string, error) {
	var result []string

	listData, err := os.ReadFile(file)

	if err != nil {
		return nil, err
	}

	list := strings.Split(string(listData), "\n")

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
			IPAddress: endpoint.IPAddress,
			Grade:     grade,
			GradeNum:  gradeNumMap[grade],
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

// checkAPIAvailability checks SSLLabs API availability
func checkAPIAvailability() support.Check {
	req.SetUserAgent("SSLCli", VER)

	resp, err := req.Request{
		URL:         sslscan.API_URL_INFO,
		AutoDiscard: true,
	}.Head()

	if err != nil {
		return support.Check{
			support.CHECK_ERROR, "SSLLabs API", "Can't send request",
		}
	} else if resp.StatusCode != 200 {
		return support.Check{
			support.CHECK_ERROR, "SSLLabs API", fmt.Sprintf(
				"API returned non-ok status code %s", resp.StatusCode,
			),
		}
	}

	return support.Check{support.CHECK_OK, "SSLLabs API", "API available"}
}

// printCompletion prints completion for given shell
func printCompletion() int {
	info := genUsage()

	switch options.GetS(OPT_COMPLETION) {
	case "bash":
		fmt.Print(bash.Generate(info, "sslcli"))
	case "fish":
		fmt.Print(fish.Generate(info, "sslcli"))
	case "zsh":
		fmt.Print(zsh.Generate(info, optMap, "sslcli"))
	default:
		return 1
	}

	return 0
}

// printMan prints man page
func printMan() {
	fmt.Println(man.Generate(genUsage(), genAbout("")))
}

// genUsage generates usage info
func genUsage() *usage.Info {
	info := usage.NewInfo("", "host…")

	info.AppNameColorTag = colorTagApp

	info.AddOption(OPT_EMAIL, "User account email {r}(required){!}", "email")
	info.AddOption(OPT_FORMAT, "Output result in different formats {s-}(text/json/yaml/xml){!}", "format")
	info.AddOption(OPT_DETAILED, "Show detailed info for each endpoint")
	info.AddOption(OPT_IGNORE_MISMATCH, "Proceed with assessments on certificate mismatch")
	info.AddOption(OPT_AVOID_CACHE, "Disable cache usage")
	info.AddOption(OPT_PUBLIC, "Publish results on sslscan.com")
	info.AddOption(OPT_PERFECT, "Return non-zero exit code if not A+")
	info.AddOption(OPT_MAX_LEFT, "Check expiry date {s-}(num + d/w/m/y){!}", "duration")
	info.AddOption(OPT_NOTIFY, "Notify when check is done")
	info.AddOption(OPT_QUIET, "Don't show any output")
	info.AddOption(OPT_PAGER, "Use pager for long output")
	info.AddOption(OPT_NO_COLOR, "Disable colors in output")
	info.AddOption(OPT_HELP, "Show this help message")
	info.AddOption(OPT_VER, "Show version")

	info.AddExample(
		"--register --email john@domain.com --org 'Some Organization' --name 'John Doe'",
		"Register new user account for scanning",
	)

	info.AddExample(
		"google.com",
		"Check google.com",
	)

	info.AddExample(
		"-P google.com",
		"Check google.com and return zero exit code only if result is perfect (A+)",
	)

	info.AddExample(
		"-p -c google.com",
		"Check google.com, publish results, disable cache usage",
	)

	info.AddExample(
		"-M 3m -q google.com",
		"Check google.com in quiet mode and return error if cert expire in 3 months",
	)

	info.AddExample(
		"hosts.txt",
		"Check all hosts defined in hosts.txt file",
	)

	return info
}

// genAbout generates info about version
func genAbout(gitRev string) *usage.About {
	about := &usage.About{
		App:     APP,
		Version: VER,
		Desc:    DESC,
		Year:    2009,
		Owner:   "ESSENTIAL KAOS",

		AppNameColorTag: colorTagApp,
		VersionColorTag: colorTagVer,
		DescSeparator:   "{s}—{!}",

		License: "Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>",
	}

	if gitRev != "" {
		about.Build = "git:" + gitRev
		about.UpdateChecker = usage.UpdateChecker{"essentialkaos/sslcli", update.GitHubChecker}
	}

	return about
}
