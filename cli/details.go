package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2023 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"fmt"
	"strings"
	"time"

	"github.com/essentialkaos/ek/v12/fmtc"
	"github.com/essentialkaos/ek/v12/fmtutil"
	"github.com/essentialkaos/ek/v12/httputil"
	"github.com/essentialkaos/ek/v12/pluralize"
	"github.com/essentialkaos/ek/v12/sliceutil"
	"github.com/essentialkaos/ek/v12/strutil"
	"github.com/essentialkaos/ek/v12/timeutil"

	"github.com/essentialkaos/sslscan/v13"
)

// ////////////////////////////////////////////////////////////////////////////////// //

// protocolList contains list of supported protocols
var protocolList = []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"}

// rootStores contains list of root stores
var rootStores = []string{"Mozilla", "Apple", "Android", "Java", "Windows"}

// protocolsNames is map protocol id -> protocol name
var protocolsNames = map[int]string{
	sslscan.PROTOCOL_SSL2:  "SSL 2.0",
	sslscan.PROTOCOL_SSL3:  "SSL 3.0",
	sslscan.PROTOCOL_TLS10: "TLS 1.0",
	sslscan.PROTOCOL_TLS11: "TLS 1.1",
	sslscan.PROTOCOL_TLS12: "TLS 1.2",
	sslscan.PROTOCOL_TLS13: "TLS 1.3",
}

// weakAlgorithms is map with weak algorithms names
var weakAlgorithms = map[string]bool{
	"SHA1withRSA": true,
	"MD5withRSA":  true,
	"MD2withRSA":  true,
}

// ////////////////////////////////////////////////////////////////////////////////// //

// isInsecureForwardSecrecy is flag for insecure forward secrecy
var isInsecureForwardSecrecy bool

// isWeakForwardSecrecy is flag for weak forward secrecy
var isWeakForwardSecrecy bool

// ////////////////////////////////////////////////////////////////////////////////// //

// printDetailedInfo fetches and prints detailed info for all endpoints
func printDetailedInfo(ap *sslscan.AnalyzeProgress, fromCache bool) {
	info, err := ap.Info(true, fromCache)

	if err != nil {
		printError("\nCan't fetch full analyze info: %v\n", err)
		return
	}

	if strings.ToUpper(info.Status) != "READY" {
		printError("\n%s\n", info.StatusMessage)
		return
	}

	printCertificateInfo(info.Certs, info.Endpoints)

	for index, endpoint := range info.Endpoints {
		fmtc.Printf("\n{c*} %s {!*}#%d (%s){!}\n", info.Host, index+1, endpoint.IPAddress)
		printDetailedEndpointInfo(endpoint, info.Certs)
	}
}

// printCertificateInfo prints info about server certificate
func printCertificateInfo(certs []*sslscan.Cert, endpoints []*sslscan.EndpointInfo) {
	fmtc.NewLine()

	printCategoryHeader("Server Key and Certificate")

	if len(certs) == 0 {
		fmtc.Println("\n {r}No valid certificates and keys{!}\n")
		fmtutil.Separator(true)
		return
	}

	cert := certs[0]

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Subject", extractSubject(cert.Subject))
	fmtc.Printf(" %-24s {s}|{!} {s-}Fingerprint: %s{!}\n", "", cert.SHA256Hash)
	fmtc.Printf(" %-24s {s}|{!} {s-}Pin: %s{!}\n", "", cert.PINSHA256)

	printCertNamesInfo(cert)
	printCertValidityInfo(cert)

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Serial number", cert.SerialNumber)
	fmtc.Printf(" %-24s {s}|{!} %s %d bits\n", "Key", cert.KeyAlg, cert.KeySize)
	fmtc.Printf(" %-24s {s}|{!} %s\n", "Weak Key (Debian)", printBool(cert.KeyKnownDebianInsecure))

	printCertIssuerInfo(cert)
	printCertSignatureInfo(cert)
	printCertValidationTypeInfo(cert)
	printCertTransparencyInfo(cert, endpoints)
	printCertRevocationInfo(cert)
	printCertDNSCAAInfo(cert)
	printCertTrustInfo(cert, endpoints)

	fmtutil.Separator(true)
}

// printDetailedEndpointInfo fetches and print detailed info for one endpoint
func printDetailedEndpointInfo(info *sslscan.EndpointInfo, certs []*sslscan.Cert) {
	fmtc.NewLine()

	isInsecureForwardSecrecy = false
	isWeakForwardSecrecy = false

	printChainInfo(info, certs)
	printProtocolsInfo(info.Details)
	printCipherSuitesInfo(info.Details)
	printHandshakeSimulationInfo(info.Details)
	printProtocolDetailsInfo(info.Details)
	printTransactionsInfo(info.Details)
	printMiscellaneousInfo(info)

	fmtutil.Separator(true)
}

// printChainInfo prints info about certificates in chain
func printChainInfo(info *sslscan.EndpointInfo, certs []*sslscan.Cert) {
	if len(info.Details.CertChains) == 0 {
		return
	}

	printCategoryHeader("Certification Paths")

	chain := info.Details.CertChains[0]

	printChainBasicInfo(chain)

	if len(chain.CertIDs) > 1 {
		for i := 1; i < len(chain.CertIDs); i++ {
			fmtutil.Separator(true)

			certID := chain.CertIDs[i]
			cert := findCertByID(certs, certID)

			if cert == nil {
				continue
			}

			printChainCertInfo(cert)
		}
	}
}

// printProtocolsInfo prints info about supported protocols
func printProtocolsInfo(details *sslscan.EndpointDetails) {
	if len(details.Protocols) == 0 {
		return
	}

	printCategoryHeader("Protocols")

	supportedProtocols := getProtocols(details.Protocols)

	for _, protocol := range protocolList {
		printProtocolInfo(protocol, supportedProtocols)
	}
}

// printCipherSuitesInfo prints info about supported cipher suites
func printCipherSuitesInfo(details *sslscan.EndpointDetails) {
	if details.Suites == nil && details.NoSNISuites == nil {
		return
	}

	printCategoryHeader("Cipher Suites")

	var allSuites []*sslscan.ProtocolSuites

	if details.NoSNISuites != nil {
		allSuites = append([]*sslscan.ProtocolSuites{details.NoSNISuites}, details.Suites...)
	} else {
		allSuites = details.Suites
	}

	for i := len(allSuites) - 1; i >= 0; i-- {
		suites := allSuites[i]
		noSNI := details.NoSNISuites != nil && suites.Protocol == details.NoSNISuites.Protocol

		printProtocolSuitesInfo(suites, noSNI)

		fmtutil.Separator(true)

		for _, suite := range suites.List {
			printProtocolSuiteInfo(suite, details.ChaCha20Preference)
		}

		if i != 0 {
			fmtutil.Separator(true)
		}
	}
}

// printHandshakeSimulationInfo prints info about handshakes simulations
func printHandshakeSimulationInfo(details *sslscan.EndpointDetails) {
	if details.SIMS == nil || len(details.SIMS.Results) == 0 {
		return
	}

	printCategoryHeader("Handshake Simulation")

	for _, sim := range details.SIMS.Results {
		if sim.ErrorCode != 0 {
			fmtc.Printf(" %-20s {s}|{!} {r}Fail{!}\n", sim.Client.Name+" "+sim.Client.Version)
			continue
		}

		printSimulationInfo(sim, details.Suites)
	}
}

// printProtocolDetailsInfo prints endpoint protocol details
func printProtocolDetailsInfo(details *sslscan.EndpointDetails) {
	printCategoryHeader("Protocol Details")

	printEndpointRenegotiationInfo(details)
	printEndpointPoodleStatus(details)
	printEndpointDrownStatus(details)
	printEndpointLogjamStatus(details)
	printEndpointFreakStatus(details)
	printEndpointFallbackSCSVStatus(details)
	printEndpointCompressionInfo(details)
	printEndpointRC4SupportStatus(details)
	printEndpointHeartbeatStatus(details)
	printEndpointHeartbleedStatus(details)
	printEndpointTicketbleedStatus(details)
	printEndpointOpenSSLCCSStatus(details)
	printEndpointLuckyMinus20Status(details)
	printEndpointRobotStatus(details)
	printEndpointFSStatus(details)
	printEndpointALPNStatus(details)
	printEndpointNPNStatus(details)
	printEndpointSNIStatus(details)
	printEndpointSessionsInfo(details)
	printEndpointStaplingInfo(details)
	printEndpointHSTSInfo(details)
	printEndpointHPKPInfo(details)
	printEndpointHandshakeInfo(details)
	printEndpointTLSInfo(details)
	printEndpointDHPrimesInfo(details)
	printEndpointECDHInfo(details)
	printEndpointNamedGroups(details.NamedGroups)
	print0RTTStatus(details.ZeroRTTEnabled)
}

// printTransactionsInfo prints info about HTTP transactions
func printTransactionsInfo(details *sslscan.EndpointDetails) {
	if len(details.HTTPTransactions) == 0 {
		return
	}

	printCategoryHeader("HTTP Requests")

	for index, transaction := range details.HTTPTransactions {
		fmtc.Printf(
			" {s-}%d{!} %s {s}(%s){!}\n",
			index+1, transaction.RequestURL, transaction.ResponseLine,
		)
	}
}

// printMiscellaneousInfo prints miscellaneous info about endpoint
func printMiscellaneousInfo(info *sslscan.EndpointInfo) {
	printCategoryHeader("Miscellaneous")

	printTestInfo(info)
	printWebServerInfo(info)
}

// ////////////////////////////////////////////////////////////////////////////////// //

// printCategoryHeader prints category name and separators
func printCategoryHeader(name string) {
	fmtutil.Separator(true)
	fmtc.Printf(" ▾ {*}%s{!}\n", strings.ToUpper(name))
	fmtutil.Separator(true)
}

// printCertNamesInfo prints common and alternative names from certificate
func printCertNamesInfo(cert *sslscan.Cert) {
	fmtc.Printf(" %-24s {s}|{!} %s\n", "Common names", strings.Join(cert.CommonNames, " "))

	if len(cert.AltNames) > 0 {
		if len(cert.AltNames) > 5 {
			fmtc.Printf(
				" %-24s {s}|{!} %s {s-}(+%d more){!}",
				"Alternative names",
				strings.Join(cert.AltNames[:4], " "),
				len(cert.AltNames)-4,
			)
		} else {
			fmtc.Printf(" %-24s {s}|{!} %s", "Alternative names", strings.Join(cert.AltNames, " "))
		}

		if cert.Issues&8 == 8 {
			fmtc.Println(" {r}MISMATCH{!}")
		} else {
			fmtc.NewLine()
		}
	}
}

// printCertValidityInfo prints certificate validity info
func printCertValidityInfo(cert *sslscan.Cert) {
	validFromDate := time.Unix(cert.NotBefore/1000, 0)
	validUntilDate := time.Unix(cert.NotAfter/1000, 0)
	validDays := (validUntilDate.Unix() - time.Now().Unix()) / 86400

	fmtc.Printf(
		" %-24s {s}|{!} %s\n", "Valid from",
		timeutil.Format(validFromDate, "%Y/%m/%d %H:%M:%S"),
	)

	fmtc.Printf(" %-24s {s}|{!} ", "Valid until")

	if time.Now().Unix() >= validUntilDate.Unix() {
		fmtc.Printf(
			"{r}%s (EXPIRED){!}\n",
			timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"),
		)
	} else {
		fmtc.Printf(
			"%s {s-}(expires in %s %s){!}\n",
			timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"),
			fmtutil.PrettyNum(validDays),
			pluralize.Pluralize(int(validDays), "day", "days"),
		)
	}
}

func printCertIssuerInfo(cert *sslscan.Cert) {
	fmtc.Printf(" %-24s {s}|{!} ", "Issuer")

	if cert.Issues&64 == 64 {
		fmtc.Printf("%s {s-}(Self-signed){!}\n", extractSubject(cert.IssuerSubject))
	} else {
		fmtc.Printf("%s\n", extractSubject(cert.IssuerSubject))

		if len(cert.CRLURIs) != 0 {
			fmtc.Printf(" %-24s {s}|{!} {s-}AIA: %s{!}\n", "", cert.CRLURIs[0])
		}
	}
}

// printCertSignatureInfo prints certificate signature info
func printCertSignatureInfo(cert *sslscan.Cert) {
	fmtc.Printf(" %-24s {s}|{!} ", "Signature algorithm")

	if weakAlgorithms[cert.SigAlg] {
		fmtc.Printf("{y}%s (WEAK){!}\n", cert.SigAlg)
	} else {
		fmtc.Printf("%s\n", cert.SigAlg)
	}
}

// printCertValidationTypeInfo prints certificate validation type
func printCertValidationTypeInfo(cert *sslscan.Cert) {
	fmtc.Printf(" %-24s {s}|{!} ", "Extended Validation")

	if cert.ValidationType == "E" {
		fmtc.Println("{g}Yes{!}")
	} else {
		fmtc.Println("No")
	}
}

// printCertTransparencyInfo prints certificate transparency info
func printCertTransparencyInfo(cert *sslscan.Cert, endpoints []*sslscan.EndpointInfo) {
	fmtc.Printf(" %-24s {s}|{!} ", "Certificate Transparency")

	for _, endpoint := range endpoints {
		details := endpoint.Details

		switch details.HasSCT {
		case 0:
			continue
		case 1:
			fmtc.Println("{g}Yes{!} {s-}(certificate){!}")
		case 2:
			fmtc.Println("{g}Yes{!} {s-}(stapled OCSP response){!}")
		case 4:
			fmtc.Println("{g}Yes{!} {s-}(TLS extension){!}")
		}

		return
	}

	fmtc.Println("{y}No{!}")
}

// printCertRevocationInfo prints certificate revocation status and info
func printCertRevocationInfo(cert *sslscan.Cert) {
	if cert.RevocationInfo != 0 {
		fmtc.Printf(
			" %-24s {s}|{!} %s\n", "Revocation information",
			getRevocationInfo(cert.RevocationInfo),
		)

		if len(cert.CRLURIs) != 0 {
			fmtc.Printf(" %-24s {s}|{!} {s-}CRL: %s{!}\n", "", cert.CRLURIs[0])
		}

		if len(cert.OCSPURIs) != 0 {
			fmtc.Printf(" %-24s {s}|{!} {s-}OCSP: %s{!}\n", "", cert.OCSPURIs[0])
		}
	}

	fmtc.Printf(" %-24s {s}|{!} ", "Revocation status")

	if cert.RevocationStatus&1 == 1 {
		fmtc.Printf("{r}%s{!}\n", getRevocationStatus(cert.RevocationStatus))
	} else {
		fmtc.Printf("%s\n", getRevocationStatus(cert.RevocationStatus))
	}
}

// printCertDNSCAAInfo prints certificate DNS Certification Authority Authorization
func printCertDNSCAAInfo(cert *sslscan.Cert) {
	fmtc.Printf(" %-24s {s}|{!} ", "DNS CAA")

	if cert.DNSCAA {
		fmtc.Println("{g}Yes{!}")
		if cert.CAAPolicy != nil {
			fmtc.Printf(
				" %-24s {s}|{!} {s-}policy host: %s{!}\n", "",
				cert.CAAPolicy.PolicyHostname,
			)

			for _, rec := range cert.CAAPolicy.CAARecords {
				fmtc.Printf(
					" %-24s {s}|{!} {s-}%s: %s flags: %d{!}\n", "",
					rec.Tag, rec.Value, rec.Flags,
				)
			}
		}
	} else {
		fmtc.Println("{y}No{!}")
	}
}

// printCertTrustInfo prints certificate trust status
func printCertTrustInfo(cert *sslscan.Cert, endpoints []*sslscan.EndpointInfo) {
	fmtc.Printf(" %-24s {s}|{!} ", "Trusted")

	trustInfo, isTrusted := getTrustInfo(cert.ID, endpoints)

	if !isTrusted {
		fmtc.Println("{r}No (NOT TRUSTED){!}")
	} else {
		if cert.Issues == 0 {
			fmtc.Println("{g}Yes{!}")
		} else {
			fmtc.Printf("{r}No (%s){!}\n", getCertIssuesDesc(cert.Issues))
		}
	}

	fmtc.Printf(" %-24s {s}|{!} ", "")

	for _, rootStore := range rootStores {
		switch trustInfo[rootStore] {
		case true:
			fmtc.Printf("{g}%s{!} ", rootStore)
		default:
			fmtc.Printf("{r}%s{!} ", rootStore)
		}
	}

	fmtc.NewLine()
}

// printChainBasicInfo prints info about provided certificates chain
func printChainBasicInfo(chain *sslscan.ChainCert) {
	fmtc.Printf(" %-24s {s}|{!} %d\n", "Certificates provided", len(chain.CertIDs))
	fmtc.Printf(" %-24s {s}|{!} ", "Chain issues")

	if chain.Issues == 0 {
		fmtc.Println("None")
	} else {
		fmtc.Printf("{y}%s{!}\n", getChainIssuesDesc(chain.Issues))
	}
}

// printChainCertInfo prints basic info about certificate from chain
func printChainCertInfo(cert *sslscan.Cert) {
	validUntilDate := time.Unix(cert.NotAfter/1000, 0)
	validDays := (validUntilDate.Unix() - time.Now().Unix()) / 86400

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Subject", extractSubject(cert.Subject))

	fmtc.Printf(" %-24s {s}|{!} {s-}Fingerprint: %s{!}\n", "", cert.SHA256Hash)
	fmtc.Printf(" %-24s {s}|{!} {s-}Pin: %s{!}\n", "", cert.PINSHA256)

	fmtc.Printf(
		" %-24s {s}|{!} %s {s-}(expires in %s %s){!}\n", "Valid until",
		timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"),
		fmtutil.PrettyNum(validDays),
		pluralize.Pluralize(int(validDays), "day", "days"),
	)

	fmtc.Printf(" %-24s {s}|{!} ", "Key")

	if cert.KeyAlg == "RSA" && cert.KeyStrength < 2048 {
		fmtc.Printf("{y}%s %d bits (WEAK){!}\n", cert.KeyAlg, cert.KeySize)
	} else {
		fmtc.Printf("%s %d bits\n", cert.KeyAlg, cert.KeySize)
	}

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Issuer", extractSubject(cert.IssuerSubject))

	fmtc.Printf(" %-24s {s}|{!} ", "Signature algorithm")

	if weakAlgorithms[cert.SigAlg] {
		fmtc.Printf("{y}%s (WEAK){!}\n", cert.SigAlg)
	} else {
		fmtc.Printf("%s\n", cert.SigAlg)
	}
}

// printProtocolInfo prints info about supported protocol
func printProtocolInfo(protocol string, supportedProtocols map[string]bool) {
	fmtc.Printf(" %-24s {s}|{!} ", protocol)

	switch {
	case protocol == "TLS 1.3" && supportedProtocols[protocol]:
		fmtc.Println("{g}Yes{!}")
	case protocol == "TLS 1.2":
		if supportedProtocols[protocol] {
			fmtc.Println("{g}Yes{!}")
		} else {
			fmtc.Println("{y}No{!}")
		}
	case protocol == "TLS 1.0", protocol == "TLS 1.1":
		if supportedProtocols[protocol] {
			fmtc.Println("{y}Yes{!}")
		} else {
			fmtc.Println("No")
		}
	case protocol == "SSL 3.0" && supportedProtocols[protocol]:
		fmtc.Printf("{r}%s (INSECURE){!}\n", printBool(supportedProtocols[protocol]))
	case protocol == "SSL 2.0" && supportedProtocols[protocol]:
		fmtc.Printf("{r}%s (INSECURE){!}\n", printBool(supportedProtocols[protocol]))
	default:
		fmtc.Printf("%s\n", printBool(supportedProtocols[protocol]))
	}
}

// printProtocolSuitesInfo prints info about suites protocol
func printProtocolSuitesInfo(suites *sslscan.ProtocolSuites, noSNI bool) {
	header := " " + protocolsNames[suites.Protocol]

	if noSNI {
		header += " {s}No SNI{!}"
	}

	if suites.Preference {
		header += " {s-}(suites in server-preferred order){!}"
	} else {
		header += " {s-}(server has no preference){!}"
	}

	fmtc.Println(header)
}

// printProtocolSuiteInfo prints info about cipher suite
func printProtocolSuiteInfo(suite *sslscan.Suite, chaCha20Preference bool) {
	insecure := strings.Contains(suite.Name, "_RC4_") || suite.CipherStrength < 112
	preferred := false

	weak := isWeakSuite(suite)

	if strings.Contains(suite.Name, "_CHACHA20_") && chaCha20Preference {
		preferred = true
	}

	if suite.Q != nil {
		switch *suite.Q {
		case 0:
			insecure = true
		case 1:
			weak = true
		}
	}

	switch {
	case insecure == true:
		fmtc.Printf(" {r}%-52s{!} {s}|{!} {r}%d (INSECURE){!} ", suite.Name, suite.CipherStrength)
	case weak == true:
		fmtc.Printf(" {y}%-52s{!} {s}|{!} {y}%d (WEAK){!} ", suite.Name, suite.CipherStrength)
	case preferred == true:
		fmtc.Printf(" {*}%-52s{!} {s}|{!} %d ", suite.Name, suite.CipherStrength)
	default:
		fmtc.Printf(" %-52s {s}|{!} %d ", suite.Name, suite.CipherStrength)
	}

	switch {
	case suite.KxType == "DH":
		fmtc.Printf("{s-}(DH %d bits){!}\n",
			suite.KxStrength)
	case suite.NamedGroupName != "":
		fmtc.Printf("{s-}(%s %s ~ %d bits RSA){!}\n",
			suite.KxType, suite.NamedGroupName, suite.KxStrength)
	default:
		fmtc.NewLine()
	}
}

// printSimulationInfo prints info about client simulation
func printSimulationInfo(sim *sslscan.SIM, suites []*sslscan.ProtocolSuites) {
	tag := "{s-}No FS{!}"
	suite := findSuite(suites, sim.ProtocolID, sim.SuiteID)

	if suite == nil {
		return
	}

	if strings.Contains(suite.Name, "DHE_") {
		tag = "{g}   FS{!}"

		if isWeakSuite(suite) {
			isWeakForwardSecrecy = true
		}
	}

	if strings.Contains(suite.Name, "_RC4_") {
		if strings.Contains(suite.Name, "DHE_") {
			isInsecureForwardSecrecy = true
		}

		tag = "{r}  RC4{!}"
	}

	if sim.Client.IsReference {
		fmtc.Printf(
			" %s {s}|{!} ",
			fmtutil.Align(fmtc.Sprintf(
				"%s %s {g}R{!}", sim.Client.Name, sim.Client.Version,
			), fmtutil.LEFT, 20),
		)
	} else {
		fmtc.Printf(
			" %s {s}|{!} ",
			fmtutil.Align(fmtc.Sprintf(
				"%s %s", sim.Client.Name, sim.Client.Version,
			), fmtutil.LEFT, 20),
		)
	}

	switch protocolsNames[sim.ProtocolID] {
	case "TLS 1.2", "TLS 1.3":
		fmtc.Printf("{g}%-7s{!} %-50s "+tag+" %d\n",
			protocolsNames[sim.ProtocolID],
			suite.Name, suite.CipherStrength,
		)
	case "TLS 1.1", "TLS 1.0":
		fmtc.Printf("{y}%-7s{!} %-50s "+tag+" %d\n",
			protocolsNames[sim.ProtocolID],
			suite.Name, suite.CipherStrength,
		)
	case "SSL 2.0", "SSL 3.0":
		fmtc.Printf("{r}%-7s{!} %-50s "+tag+" %d\n",
			protocolsNames[sim.ProtocolID],
			suite.Name, suite.CipherStrength,
		)
	default:
		fmtc.Printf("%-7s %-50s "+tag+" %d\n",
			protocolsNames[sim.ProtocolID],
			suite.Name, suite.CipherStrength,
		)
	}
}

// printEndpointRenegotiationInfo prints info about renegotiation
func printEndpointRenegotiationInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Secure Renegotiation")

	if details.RenegSupport == 0 {
		fmtc.Println("{y}Not supported{!}")
	} else {
		fmtc.Println("{g}Supported{!}")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Secure Client-Initiated Renegotiation")

	if details.RenegSupport&4 == 4 {
		fmtc.Println("Yes")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Insecure Client-Initiated Renegotiation")

	if details.RenegSupport&1 == 1 {
		fmtc.Println("{r}Supported (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointPoodleStatus prints status of POODLE vulnerability
func printEndpointPoodleStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "POODLE (SSLv3)")

	if details.Poodle {
		fmtc.Println("{r}Vulnerable (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "POODLE (TLS)")

	if details.PoodleTLS == 2 {
		fmtc.Println("{r}Vulnerable (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Zombie POODLE")

	if details.ZombiePoodle == 2 {
		fmtc.Println("{r}Vulnerable{!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "GOLDENDOODLE")

	if details.GoldenDoodle == 2 {
		fmtc.Println("{r}Vulnerable{!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "OpenSSL 0-Length")

	if details.ZeroLengthPaddingOracle == 2 {
		fmtc.Println("{r}Vulnerable{!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Sleeping POODLE")

	if details.SleepingPoodle == 2 {
		fmtc.Println("{r}Vulnerable{!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointDrownStatus prints status of DROWN vulnerability
func printEndpointDrownStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "DROWN")

	switch {
	case details.DrownErrors:
		fmtc.Println("{y}Unable to perform this test due to an internal error{!}")
	case details.DrownVulnerable:
		fmtc.Println("{r}Vulnerable{!}")
	default:
		fmtc.Println("No")
	}
}

// printEndpointLogjamStatus prints status of Logjam vulnerability
func printEndpointLogjamStatus(details *sslscan.EndpointDetails) {
	if details.Logjam {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable{!}\n", "Logjam")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Logjam")
	}
}

// printEndpointFreakStatus prints status of Freak vulnerability
func printEndpointFreakStatus(details *sslscan.EndpointDetails) {
	if details.Freak {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable{!}\n", "Freak")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Freak")
	}
}

// printEndpointFallbackSCSVStatus prints status of downgrade attack prevention
func printEndpointFallbackSCSVStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Downgrade attack prevention")

	if !details.FallbackSCSV {
		fmtc.Println("{y}No, TLS_FALLBACK_SCSV not supported{!}")
	} else {
		fmtc.Println("{g}Yes, TLS_FALLBACK_SCSV supported{!}")
	}
}

// printEndpointCompressionInfo prints status of SSL/TLS compression
func printEndpointCompressionInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "SSL/TLS compression")

	if details.CompressionMethods != 0 {
		fmtc.Println("{r}Vulnerable (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointRC4SupportStatus prints status of RC4 support
func printEndpointRC4SupportStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "RC4")

	if details.SupportsRC4 {
		fmtc.Println("{r}Yes (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointHeartbeatStatus prints status of Heartbeat vulnerability
func printEndpointHeartbeatStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} %s\n", "Heartbeat (extension)", printBool(details.Heartbeat))
}

// printEndpointHeartbleedStatus prints status of Heartbleed vulnerability
func printEndpointHeartbleedStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Heartbleed (vulnerability)")

	if details.Heartbleed {
		fmtc.Println("{r}Vulnerable (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointTicketbleedStatus prints status of Ticketbleed vulnerability
func printEndpointTicketbleedStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Ticketbleed (vulnerability)")

	switch details.Ticketbleed {
	case sslscan.TICKETBLEED_STATUS_FAILED:
		fmtc.Println("{y}Test failed{!}")
	case sslscan.TICKETBLEED_STATUS_UNKNOWN:
		fmtc.Println("{y}Unknown{!}")
	case sslscan.TICKETBLEED_STATUS_NOT_VULNERABLE:
		fmtc.Println("No")
	case sslscan.TICKETBLEED_STATUS_VULNERABLE:
		fmtc.Println("{r}Vulnerable and insecure{!}")
	}
}

// printEndpointOpenSSLCCSStatus prints status of OpenSSL CCS vulnerability
func printEndpointOpenSSLCCSStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "OpenSSL CCS vuln.")

	switch details.OpenSSLCCS {
	case sslscan.SSLCSC_STATUS_FAILED:
		fmtc.Println("{y}Test failed{!}")
	case sslscan.SSLCSC_STATUS_UNKNOWN:
		fmtc.Println("{y}Unknown{!}")
	case sslscan.SSLCSC_STATUS_NOT_VULNERABLE:
		fmtc.Println("No")
	case sslscan.SSLCSC_STATUS_POSSIBLE_VULNERABLE:
		fmtc.Println("{y}Possibly vulnerable, but not exploitable{!}")
	case sslscan.SSLCSC_STATUS_VULNERABLE:
		fmtc.Println("{r}Vulnerable and exploitable{!}")
	}
}

// printEndpointLuckyMinus20Status prints status of OpenSSL Padding Oracle vulnerability
func printEndpointLuckyMinus20Status(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "OpenSSL Padding Oracle vuln.")

	switch details.OpenSSLLuckyMinus20 {
	case sslscan.LUCKY_MINUS_STATUS_FAILED:
		fmtc.Println("{y}Test failed{!}")
	case sslscan.LUCKY_MINUS_STATUS_UNKNOWN:
		fmtc.Println("{y}Unknown{!}")
	case sslscan.LUCKY_MINUS_STATUS_NOT_VULNERABLE:
		fmtc.Println("No")
	case sslscan.LUCKY_MINUS_STATUS_VULNERABLE:
		fmtc.Println("{r}Vulnerable and insecure{!}")
	}
}

// printEndpointRobotStatus prints status of Bleichenbacher vulnerability
func printEndpointRobotStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "ROBOT (vulnerability)")

	switch details.Bleichenbacher {
	case sslscan.BLEICHENBACHER_STATUS_FAILED:
		fmtc.Println("{y}Test failed{!}")
	case sslscan.BLEICHENBACHER_STATUS_UNKNOWN:
		fmtc.Println("{y}Unknown{!}")
	case sslscan.BLEICHENBACHER_STATUS_NOT_VULNERABLE:
		fmtc.Println("No")
	case sslscan.BLEICHENBACHER_STATUS_VULNERABLE_WEAK:
		fmtc.Println("{r}Vulnerable (weak oracle){!}")
	case sslscan.BLEICHENBACHER_STATUS_VULNERABLE_STRONG:
		fmtc.Println("{r}Vulnerable (strong oracle){!}")
	case sslscan.BLEICHENBACHER_STATUS_INCONSISTENT_RESULTS:
		fmtc.Println("{y}Inconsistent results{!}")
	}
}

// printEndpointFSStatus prints status of Forward Secrecy support
func printEndpointFSStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Forward Secrecy")

	switch {
	case isInsecureForwardSecrecy:
		fmtc.Println("{r}Insecure key exchange{!}")
	case isWeakForwardSecrecy:
		fmtc.Println("{y}Weak key exchange{!}")
	case details.ForwardSecrecy == 0:
		fmtc.Println("{y}No (WEAK){!}")
	case details.ForwardSecrecy&1 == 1:
		fmtc.Println("{y}With some browsers{!}")
	case details.ForwardSecrecy&2 == 2:
		fmtc.Println("With modern browsers")
	case details.ForwardSecrecy&4 == 4:
		fmtc.Println("{g}Yes (with most browsers) (ROBUST){!}")
	}
}

// printEndpointALPNStatus prints status and info about ALPN support
func printEndpointALPNStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "ALPN")

	if details.SupportsALPN {
		fmtc.Printf("Yes {s-}(%s){!}\n", details.ALPNProtocols)
	} else {
		fmtc.Println("No")
	}
}

// printEndpointNPNStatus prints status and info about NPN support
func printEndpointNPNStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "NPN")

	if details.SupportsNPN {
		fmtc.Printf("Yes {s-}(%s){!}\n", details.NPNProtocols)
	} else {
		fmtc.Println("No")
	}
}

// printEndpointSNIStatus prints info about SNI requirements
func printEndpointSNIStatus(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "SNI Required")

	if details.SNIRequired {
		fmtc.Println("Yes")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointSessionsInfo prints info about sessions features
func printEndpointSessionsInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Session resumption (caching)")

	switch details.SessionResumption {
	case 0:
		fmtc.Println("{y}No (Session resumption is not enabled){!}")
	case 1:
		fmtc.Println("{y}No (IDs assigned but not accepted){!}")
	case 2:
		fmtc.Println("Yes")
	default:
		fmtc.Println("Unknown")
	}

	fmtc.Printf(
		" %-40s {s}|{!} %s\n", "Session resumption (tickets)",
		printBool(details.SessionTickets&1 == 1),
	)

}

// printEndpointStaplingInfo prints status of OCSP stapling support
func printEndpointStaplingInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "OCSP stapling")

	if details.OCSPStapling {
		fmtc.Println("{g}Yes{!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointHSTSInfo prints info about HSTS
func printEndpointHSTSInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Strict Transport Security (HSTS)")

	if details.HSTSPolicy != nil && details.HSTSPolicy.Status == sslscan.HSTS_STATUS_PRESENT {
		fmtc.Printf("{g}Yes{!} {s-}(%s){!}\n", details.HSTSPolicy.Header)

		if len(details.HSTSPreloads) != 0 {
			fmtc.Printf(" %-40s {s}|{!} ", "HSTS Preloading")
			fmtc.Println(getHSTSPreloadingMarkers(details.HSTSPreloads))
		}
	} else {
		fmtc.Println("No")
	}
}

// printEndpointHPKPInfo prints info about HPKP
func printEndpointHPKPInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Public Key Pinning (HPKP)")

	printPolicyInfo(details.HPKPPolicy)

	fmtc.Printf(" %-40s {s}|{!} ", "Public Key Pinning Report-Only")

	printPolicyInfo(details.HPKPRoPolicy)
}

// printEndpointHandshakeInfo prints info about long handshake intolerance
func printEndpointHandshakeInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Long handshake intolerance")

	switch {
	case details.MiscIntolerance&2 == 2:
		fmtc.Println("{y}Yes{!}")
	case details.MiscIntolerance&4 == 4:
		fmtc.Println("{y}Yes{!} {s-}(workaround success){!}")
	default:
		fmtc.Println("No")
	}
}

// printEndpointTLSInfo prints info about TLS extension intolerance
func printEndpointTLSInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "TLS extension intolerance")

	if details.MiscIntolerance&1 == 1 {
		fmtc.Println("{y}Yes{!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "TLS version intolerance")

	if details.ProtocolIntolerance != 0 {
		fmtc.Printf("{y}%s{!}\n", getProtocolIntolerance(details.ProtocolIntolerance))
	} else {
		fmtc.Println("No")
	}
}

// printEndpointDHPrimesInfo prints info about DH primes
func printEndpointDHPrimesInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "Uses common DH primes")

	if details.DHUsesKnownPrimes != 0 {
		fmtc.Println("{y}Yes (Replace with custom DH parameters if possible){!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "DH public server param (Ys) reuse")

	if details.DHYsReuse {
		fmtc.Println("{y}Yes{!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointECDHInfo prints info about ECDH param reuse
func printEndpointECDHInfo(details *sslscan.EndpointDetails) {
	fmtc.Printf(" %-40s {s}|{!} ", "ECDH public server param reuse")

	if details.ECDHParameterReuse {
		fmtc.Println("{y}Yes{!}")
	} else {
		fmtc.Println("No")
	}
}

// printEndpointNamedGroups prints list with supported named groups
func printEndpointNamedGroups(namedGroups *sslscan.NamedGroups) {
	fmtc.Printf(" %-40s {s}|{!} ", "Supported Named Groups")

	if namedGroups == nil || len(namedGroups.List) == 0 {
		fmtc.Println("—")
		return
	}

	var groups []string

	for _, group := range namedGroups.List {
		groups = append(groups, group.Name)
	}

	fmtc.Print(strings.Join(groups, ", "))

	if namedGroups.Preference {
		fmtc.Printf(" {s-}(server preferred order){!}\n")
	}
}

// print0RTTStatus prints 0-RTT support status
func print0RTTStatus(status int) {
	if status == -1 {
		return
	}

	fmtc.Printf(" %-40s {s}|{!} ", "0-RTT")

	switch status {
	case -2:
		fmtc.Println("Test failed")
	case 0:
		fmtc.Println("No")
	case 1:
		fmtc.Println("{g}Yes{!}")
	}
}

// printPolicyInfo prints info about HPKP policy
func printPolicyInfo(policy *sslscan.HPKPPolicy) {
	if policy == nil {
		fmtc.Println("No")
		return
	}

	switch policy.Status {
	case sslscan.HPKP_STATUS_INVALID:
		fmtc.Println("{r}Invalid{!}")
	case sslscan.HPKP_STATUS_DISABLED:
		fmtc.Println("{y}Disabled{!}")
	case sslscan.HPKP_STATUS_INCOMPLETE:
		fmtc.Println("{y}Incomplete{!}")
	case sslscan.HPKP_STATUS_VALID:
		fmtc.Printf("{g}Yes{!} ")

		if policy.IncludeSubDomains {
			fmtc.Printf(
				"{s-}(max-age=%d; includeSubdomains){!}\n",
				policy.MaxAge,
			)
		} else {
			fmtc.Printf(
				"{s-}(max-age=%d){!}\n",
				policy.MaxAge,
			)
		}

		for _, pin := range getPinsFromPolicy(policy) {
			fmtc.Printf(" %-40s {s}|{!} {s-}%s{!}\n", "", pin)
		}
	default:
		fmtc.Println("No")
	}
}

// printTestInfo prints basic info about test
func printTestInfo(info *sslscan.EndpointInfo) {
	details := info.Details
	testDate := time.Unix(info.Details.HostStartTime/1000, 0)

	fmtc.Printf(
		" %-24s {s}|{!} %s {s-}(%s ago){!}\n", "Test date",
		timeutil.Format(testDate, "%Y/%m/%d %H:%M:%S"),
		timeutil.PrettyDuration(time.Since(testDate)),
	)

	fmtc.Printf(
		" %-24s {s}|{!} %s\n", "Test duration",
		timeutil.PrettyDuration(info.Duration/1000),
	)

	if details.HTTPStatusCode == 0 {
		fmtc.Printf(" %-24s {s}|{!} {y}Request failed{!}\n", "HTTP status code")
	} else {
		fmtc.Printf(
			" %-24s {s}|{!} %d {s-}(%s){!}\n", "HTTP status code",
			details.HTTPStatusCode,
			httputil.GetDescByCode(details.HTTPStatusCode),
		)
	}
}

// printWebServerInfo prints basic info about web server
func printWebServerInfo(info *sslscan.EndpointInfo) {
	details := info.Details

	if details.HTTPForwarding != "" {
		if strings.Contains(details.HTTPForwarding, "http://") {
			fmtc.Printf(" %-24s {s}|{!} {y}%s (PLAINTEXT){!}\n", "HTTP forwarding", details.HTTPForwarding)
		} else {
			fmtc.Printf(" %-24s {s}|{!} %s\n", "HTTP forwarding", details.HTTPForwarding)
		}
	}

	if details.ServerSignature != "" {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "HTTP server signature", details.ServerSignature)
	} else {
		fmtc.Printf(" %-24s {s}|{!} Unknown\n", "HTTP server signature")
	}

	if info.ServerName != "" {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Server hostname", info.ServerName)
	} else {
		fmtc.Printf(" %-24s {s}|{!} —\n", "Server hostname")
	}
}

// printBool prints bool value as Yes/No
func printBool(value bool) string {
	switch value {
	case true:
		return "Yes"
	default:
		return "No"
	}
}

// getRevocationInfo decodes revocation info
func getRevocationInfo(info int) string {
	var result []string

	if info&1 == 1 {
		result = append(result, "CRL")
	}

	if info&2 == 2 {
		result = append(result, "OCSP")
	}

	return strings.Join(result, " ")
}

// getRevocationStatus returns description for revocation status
func getRevocationStatus(status int) string {
	switch status {
	case 0:
		return "Not checked"
	case 1:
		return "Bad (revoked)"
	case 2:
		return "Good (not revoked)"
	case 3:
		return "Revocation check error"
	case 4:
		return "No revocation information"
	default:
		return "Internal error"
	}
}

// getCertIssuesDesc returns description for cert issues
func getCertIssuesDesc(issues int) string {
	switch {
	case issues&1 == 1:
		return "No chain of trust"
	case issues&2 == 2:
		return "Not before"
	case issues&4 == 4:
		return "Not after"
	case issues&8 == 8:
		return "Hostname mismatch"
	case issues&16 == 16:
		return "Revoked"
	case issues&32 == 32:
		return "Bad common name"
	case issues&64 == 64:
		return "Self-signed"
	case issues&128 == 128:
		return "Blacklisted"
	case issues&256 == 256:
		return "Insecure signature"
	}

	return "Unknown"
}

// getChainIssuesDesc returns description for chain issues
func getChainIssuesDesc(issues int) string {
	switch {
	case issues&1 == 1:
		return "Unused"
	case issues&2 == 2:
		return "Incomplete chain"
	case issues&4 == 4:
		return "Chain contains unrelated or duplicate certificates"
	case issues&8 == 8:
		return "Order is incorrect"
	case issues&16 == 16:
		return "Contains a self-signed root certificate"
	case issues&32 == 32:
		return "Couldn't validate certificate from chain"
	}

	return "None"
}

// getProtocolIntolerance returns protocol intolerance info
func getProtocolIntolerance(issues int) string {
	var versions []string

	if issues&1 == 1 {
		versions = append(versions, "TLS 1.0")
	}

	if issues&2 == 2 {
		versions = append(versions, "TLS 1.1")
	}

	if issues&4 == 4 {
		versions = append(versions, "TLS 1.2")
	}

	if issues&8 == 8 {
		versions = append(versions, "TLS 1.3")
	}

	if issues&16 == 16 {
		versions = append(versions, "TLS 1.152")
	}

	if issues&32 == 32 {
		versions = append(versions, "TLS 2.152")
	}

	if len(versions) == 0 {
		return "No"
	}

	return strings.Join(versions, " ")
}

// getProtocols returns map with supported protocols
func getProtocols(protocols []*sslscan.Protocol) map[string]bool {
	var supported = make(map[string]bool)

	for _, protocol := range protocols {
		supported[protocol.Name+" "+protocol.Version] = true
	}

	return supported
}

// getPinsFromPolicy returns slice with all pins in policy
func getPinsFromPolicy(policy *sslscan.HPKPPolicy) []string {
	var pins []string

	for _, pin := range strings.Split(policy.Header, ";") {
		pin = strings.TrimSpace(pin)
		pin = strings.ReplaceAll(pin, "\"", "")
		pin = strings.Replace(pin, "=", ": ", 1)

		if strings.HasPrefix(pin, "pin-") {
			pins = append(pins, pin)
		}
	}

	return pins
}

// getHSTSPreloadingMarkers returns slice with colored HSTS preload markers
func getHSTSPreloadingMarkers(preloads []sslscan.HSTSPreload) string {
	var result []string

	for _, preload := range preloads {
		if preload.Status == sslscan.HSTS_STATUS_PRESENT {
			result = append(result, "{g}"+preload.Source+"{!}")
		} else {
			result = append(result, "{s-}"+preload.Source+"{!}")
		}
	}

	return strings.Join(result, " ")
}

// findSuite searches suite by protocol ID and suite ID
func findSuite(suites []*sslscan.ProtocolSuites, protocolID, suiteID int) *sslscan.Suite {
	for _, protocolSuites := range suites {
		if protocolSuites.Protocol != protocolID {
			continue
		}

		for _, suite := range protocolSuites.List {
			if suite.ID == suiteID {
				return suite
			}
		}
	}

	return nil
}

// findCertByID searches certificate by ID
func findCertByID(certs []*sslscan.Cert, certID string) *sslscan.Cert {
	for _, cert := range certs {
		if cert.ID == certID {
			return cert
		}
	}

	return nil
}

// isWeakSuite returns true if suite is weak
func isWeakSuite(suite *sslscan.Suite) bool {
	if suite.KxType == "DH" && suite.KxStrength < 2048 {
		return true
	}

	if strings.Contains(suite.Name, "TLS_RSA") && suite.CipherStrength <= 256 {
		return true
	}

	if strings.Contains(suite.Name, "_3DES_") {
		return true
	}

	return false
}

// extractSubject extracts subject name from certificate subject
func extractSubject(data string) string {
	subject := strutil.ReadField(data, 0, false, ",")
	subject = strings.ReplaceAll(subject, "CN=", "")
	subject = strings.ReplaceAll(subject, "OU=", "")

	return subject
}

// getTrustInfo returns info about certificate chain trust
func getTrustInfo(certID string, endpoints []*sslscan.EndpointInfo) (map[string]bool, bool) {
	var result = map[string]bool{
		"Mozilla": false,
		"Apple":   false,
		"Android": false,
		"Java":    false,
		"Windows": false,
	}

	for _, endpoint := range endpoints {
		for _, chain := range endpoint.Details.CertChains {
			for _, path := range chain.TrustPaths {
				if !sliceutil.Contains(path.CertIDs, certID) {
					continue
				}

				for _, store := range path.Trust {
					if store.IsTrusted && result[store.RootStore] == false {
						result[store.RootStore] = true
					}
				}
			}
		}
	}

	for rootStore, isTrusted := range result {
		if !isTrusted && rootStore != "Java" {
			return result, false
		}
	}

	return result, true
}

// getExpiryMessage returns message if cert is expired in given period
func getExpiryMessage(ap *sslscan.AnalyzeProgress, dur time.Duration) string {
	if dur <= 0 {
		return ""
	}

	info, err := ap.Info(true, true)

	if err != nil || strings.ToUpper(info.Status) != "READY" || len(info.Certs) == 0 {
		return ""
	}

	cert := info.Certs[0]
	validUntilDate := time.Unix(cert.NotAfter/1000, 0)

	if time.Until(validUntilDate) > dur {
		return ""
	}

	validDays := (validUntilDate.Unix() - time.Now().Unix()) / 86400

	return fmt.Sprintf(
		" {r}(expires in %s %s){!}",
		fmtutil.PrettyNum(validDays),
		pluralize.Pluralize(int(validDays), "day", "days"),
	)
}
