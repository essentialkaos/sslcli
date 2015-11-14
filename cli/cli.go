package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2015 Essential Kaos                         //
//      Essential Kaos Open Source License <http://essentialkaos.com/ekol?en>         //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"errors"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/essentialkaos/ek/arg"
	"github.com/essentialkaos/ek/fmtc"
	"github.com/essentialkaos/ek/fsutil"
	"github.com/essentialkaos/ek/req"
	"github.com/essentialkaos/ek/usage"

	"github.com/essentialkaos/ssllabs"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const (
	APP  = "SSL Labs Client"
	VER  = "1.0.4"
	DESC = "Command-line client for the SSL Labs API"
)

const (
	ARG_FORMAT          = "f:format"
	ARG_DETAILED        = "d:detailed"
	ARG_IGNORE_MISMATCH = "i:ignore-mismatch"
	ARG_CACHE           = "c:cache"
	ARG_DEV_API         = "D:dev-api"
	ARG_PRIVATE         = "p:private"
	ARG_PERFECT         = "P:perfect"
	ARG_QUIET           = "q:quiet"
	ARG_NOTIFY          = "n:notify"
	ARG_NO_COLOR        = "nc:no-color"
	ARG_HELP            = "h:help"
	ARG_VER             = "v:version"
)

const (
	FORMAT_TEXT = "text"
	FORMAT_JSON = "json"
	FORMAT_XML  = "xml"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type HostCheckInfo struct {
	Host         string               `json:"host"`
	LowestGrade  string               `json:"lowestGrade"`
	HighestGrade string               `json:"highestGrade"`
	Endpoints    []*EndpointCheckInfo `json:"endpoints"`
}

type EndpointCheckInfo struct {
	IPAdress string `json:"ipAddress"`
	Grade    string `json:"grade"`
}

// ////////////////////////////////////////////////////////////////////////////////// //

var argMap = arg.Map{
	ARG_FORMAT:          &arg.V{},
	ARG_DETAILED:        &arg.V{Type: arg.BOOL},
	ARG_IGNORE_MISMATCH: &arg.V{Type: arg.BOOL},
	ARG_CACHE:           &arg.V{Type: arg.BOOL},
	ARG_DEV_API:         &arg.V{Type: arg.BOOL},
	ARG_PRIVATE:         &arg.V{Type: arg.BOOL},
	ARG_PERFECT:         &arg.V{Type: arg.BOOL},
	ARG_QUIET:           &arg.V{Type: arg.BOOL},
	ARG_NOTIFY:          &arg.V{Type: arg.BOOL},
	ARG_NO_COLOR:        &arg.V{Type: arg.BOOL},
	ARG_HELP:            &arg.V{Type: arg.BOOL, Alias: "u:usage"},
	ARG_VER:             &arg.V{Type: arg.BOOL, Alias: "ver"},
}

var api *ssllabs.API

// ////////////////////////////////////////////////////////////////////////////////// //

// Init starts initialization rutine
func Init() {
	args, errs := arg.Parse(argMap)

	if len(errs) != 0 {
		fmtc.Println("{r}Arguments parsing errors:{!}")

		for _, err := range errs {
			fmtc.Printf("  {r}%s{!}\n", err.Error())
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

	req.UserAgent = fmtc.Sprintf("%s/%s (go; %s; %s-%s)",
		APP, VER, runtime.Version(),
		runtime.GOARCH, runtime.GOOS)

	process(args)
}

// starting processing
func process(args []string) {
	var (
		ok    bool
		err   error
		hosts []string
	)

	if arg.GetB(ARG_DEV_API) {
		api, err = ssllabs.NewAPI(ssllabs.API_DEVELOPMENT)
	} else {
		api, err = ssllabs.NewAPI(ssllabs.API_PRODUCTION)
	}

	if err != nil && arg.GetB(ARG_FORMAT) {
		fmtc.Printf("{r}%s{!}\n", err.Error())
		os.Exit(1)
	}

	// By default all fine
	ok = true
	hosts = args

	if fsutil.CheckPerms("FR", hosts[0]) {
		hosts, err = readHostList(hosts[0])

		if err != nil && arg.GetB(ARG_FORMAT) {
			fmtc.Printf("{r}%s{!}\n", err.Error())
			os.Exit(1)
		}
	}

	var grade string
	var checksInfo []*HostCheckInfo
	var checkInfo *HostCheckInfo

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

// check some host
func check(host string) string {
	var err error
	var info *ssllabs.AnalyzeInfo

	params := &ssllabs.AnalyzeParams{
		Private:        arg.GetB(ARG_PRIVATE),
		StartNew:       !arg.GetB(ARG_CACHE),
		FromCache:      arg.GetB(ARG_CACHE),
		IgnoreMismatch: arg.GetB(ARG_IGNORE_MISMATCH),
	}

	fmtc.Printf("%s → ", host)

	ap, err := api.Analyze(host, params)

	if err != nil {
		fmtc.Printf("{r}%s{!}\n", err.Error())
		return "T"
	}

	t := &fmtc.T{}

	for {
		info, err = ap.Info()

		if err != nil {
			t.Printf("{r}%s{!}\n", err.Error())
			return "Err"
		}

		if info.Status == ssllabs.STATUS_ERROR {
			t.Printf("{r}%s{!}\n", info.StatusMessage)
			return "Err"
		} else if info.Status == ssllabs.STATUS_READY {
			break
		}

		if len(info.Endpoints) != 0 {
			message := getStatusInProgress(info.Endpoints)

			if message != "" {
				t.Printf("{s}%s...{!}", message)
			}
		}

		time.Sleep(time.Second)
	}

	if len(info.Endpoints) == 1 {
		t.Println(getColoredGrade(info.Endpoints[0].Grade))
	} else {
		t.Println(getColoredGrades(info.Endpoints))
	}

	if arg.GetB(ARG_DETAILED) {
		getDetailedInfo(ap, info)
	}

	lowestGrade, _ := getGrades(info.Endpoints)

	return lowestGrade
}

// check some host without any output to console
func quietCheck(host string) (string, *HostCheckInfo) {
	var err error
	var info *ssllabs.AnalyzeInfo

	var checkInfo *HostCheckInfo = &HostCheckInfo{
		Host:         host,
		LowestGrade:  "T",
		HighestGrade: "T",
		Endpoints:    make([]*EndpointCheckInfo, 0),
	}

	params := &ssllabs.AnalyzeParams{
		Private:        arg.GetB(ARG_PRIVATE),
		StartNew:       !arg.GetB(ARG_CACHE),
		FromCache:      arg.GetB(ARG_CACHE),
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

		if info.Status == ssllabs.STATUS_ERROR {
			return "Err", checkInfo
		} else if info.Status == ssllabs.STATUS_READY {
			break
		}

		time.Sleep(time.Second)
	}

	appendEndpointsInfo(checkInfo, info.Endpoints)

	lowestGrade, highestGrade := getGrades(info.Endpoints)

	checkInfo.LowestGrade, checkInfo.HighestGrade = lowestGrade, highestGrade

	return lowestGrade, checkInfo
}

// get grade with color tags
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

// get grades with color tags for many endpoints
func getColoredGrades(endpoints []*ssllabs.EndpointInfo) string {
	var result string

	for _, endpoint := range endpoints {
		result += getColoredGrade(endpoint.Grade) + "{s}/" + endpoint.IPAdress + "{!} "
	}

	return result
}

// get lowest and highest grades
func getGrades(endpoints []*ssllabs.EndpointInfo) (string, string) {
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

// get status message from any in-progress endpoint
func getStatusInProgress(endpoints []*ssllabs.EndpointInfo) string {
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

// read file with hosts
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

// append endpoint check result to struct with info about all checks for host
func appendEndpointsInfo(checkInfo *HostCheckInfo, endpoints []*ssllabs.EndpointInfo) {
	for _, endpoint := range endpoints {
		checkInfo.Endpoints = append(checkInfo.Endpoints, &EndpointCheckInfo{
			IPAdress: endpoint.IPAdress,
			Grade:    getNormGrade(endpoint.Grade),
		})
	}
}

// return grade or error
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
	info := usage.NewInfo("ssllabs-client", "host...")

	info.AddOption(ARG_FORMAT, "Output result in different formats", "text|json|xml")
	info.AddOption(ARG_DETAILED, "Show detailed info for each endpoint")
	info.AddOption(ARG_IGNORE_MISMATCH, "Proceed with assessments on certificate mismatch")
	info.AddOption(ARG_CACHE, "Use cache if possible")
	info.AddOption(ARG_DEV_API, "Use dev API instead production")
	info.AddOption(ARG_PRIVATE, "Don't public results on ssllabs")
	info.AddOption(ARG_PERFECT, "Return non-zero exit code if not A+")
	info.AddOption(ARG_NOTIFY, "Notify when check is done")
	info.AddOption(ARG_QUIET, "Don't show any output")
	info.AddOption(ARG_NO_COLOR, "Disable colors in output")
	info.AddOption(ARG_HELP, "Show this help message")
	info.AddOption(ARG_VER, "Show version")

	info.AddExample("google.com", "Check google.com")
	info.AddExample("-p -c google.com", "Check google.com, don't publish results, use cache")

	info.Render()
}

func showAbout() {
	about := &usage.About{
		App:     APP,
		Version: VER,
		Desc:    DESC,
		Year:    2009,
		Owner:   "Essential Kaos",
		License: "Essential Kaos Open Source License <http://essentialkaos.com/ekol?en>",
	}

	about.Render()
}
