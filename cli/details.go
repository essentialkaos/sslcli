package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2016 Essential Kaos                         //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"strings"
	"time"

	"pkg.re/essentialkaos/ek.v5/fmtc"
	"pkg.re/essentialkaos/ek.v5/fmtutil"
	"pkg.re/essentialkaos/ek.v5/timeutil"

	"pkg.re/essentialkaos/sslscan.v2"
)

// ////////////////////////////////////////////////////////////////////////////////// //

// protocolList contains list of supported protocols
var protocolList = []string{"TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"}

// protocolIDs is map protocol id -> protocol name
var protocolIDs = map[int]string{
	512: "SSL 2.0",
	768: "SSL 3.0",
	769: "TLS 1.0",
	770: "TLS 1.1",
	771: "TLS 1.2",
}

// weakAlgorithms is map with weak algorithms names
var weakAlgorithms = map[string]bool{
	"SHA1withRSA": true,
	"MD5withRSA":  true,
	"MD2withRSA":  true,
}

// ////////////////////////////////////////////////////////////////////////////////// //

// printDetailedInfo fetch and print detailed info for all endpoints
func printDetailedInfo(ap *sslscan.AnalyzeProgress, info *sslscan.AnalyzeInfo) {
	showHeaders := len(info.Endpoints) > 1

	if showHeaders {
		fmtc.NewLine()
	}

	for index, endpoint := range info.Endpoints {
		if showHeaders {
			fmtc.Printf("\n{c} %s #%d (%s){!}\n\n", info.Host, index+1, endpoint.IPAdress)
		}

		printDetailedEndpointInfo(ap, endpoint.IPAdress)
	}
}

// printDetailedEndpointInfo fetch and print detailed info for one endpoint
func printDetailedEndpointInfo(ap *sslscan.AnalyzeProgress, ip string) {
	info, err := ap.DetailedInfo(ip)

	if err != nil {
		fmtc.Printf("\n{r}Can't fetch detailed info for %s{!}\n\n", ip)
		return
	}

	if strings.ToUpper(info.StatusMessage) != "READY" {
		fmtc.Printf("\n{r}%s{!}\n\n", info.StatusMessage)
		return
	}

	details := info.Details

	fmtc.NewLine()

	printCertificateInfo(details)
	printCertificationPathsInfo(details)
	printProtocolsInfo(details)
	suiteIndex := printCipherSuitesInfo(details)
	printHandshakeSimulationInfo(details, suiteIndex)
	printProtocolDetailsInfo(details)
	printMiscellaneousInfo(info)

	fmtutil.Separator(true)
	fmtc.NewLine()
}

// printCertificateInfo print basic info about server key and certificate
func printCertificateInfo(details *sslscan.EndpointDetails) {
	printCategoryHeader("Server Key and Certificate")

	validFromDate := time.Unix(details.Cert.NotBefore/1000, 0)
	validUntilDate := time.Unix(details.Cert.NotAfter/1000, 0)

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Common names", strings.Join(details.Cert.CommonNames, " "))

	if len(details.Cert.AltNames) > 0 {
		if len(details.Cert.AltNames) > 5 {
			fmtc.Printf(
				" %-24s {s}|{!} %s {s-}(+%d more){!}\n",
				"Alternative names",
				strings.Join(details.Cert.AltNames[:4], " "),
				len(details.Cert.AltNames)-4,
			)
		} else {
			fmtc.Printf(" %-24s {s}|{!} %s\n", "Alternative names", strings.Join(details.Cert.AltNames, " "))
		}
	}

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Valid from", timeutil.Format(validFromDate, "%Y/%m/%d %H:%M:%S"))

	fmtc.Printf(" %-24s {s}|{!} ", "Valid until")

	if time.Now().Unix() >= validUntilDate.Unix() {
		fmtc.Printf("{r}%s (EXPIRED){!}\n", timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"))
	} else {
		fmtc.Printf("%s\n", timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"))
	}

	fmtc.Printf(" %-24s {s}|{!} %s %d bits\n", "Key", details.Key.Alg, details.Key.Size)
	fmtc.Printf(" %-24s {s}|{!} %s\n", "Weak Key (Debian)", getBool(details.Key.DebianFlaw))

	fmtc.Printf(" %-24s {s}|{!} ", "Issuer")

	if details.Cert.Issues&64 == 64 {
		fmtc.Printf("%s {s-}(Self-signed){!}\n", details.Cert.IssuerLabel)
	} else {
		fmtc.Printf("%s\n", details.Cert.IssuerLabel)
	}

	fmtc.Printf(" %-24s {s}|{!} ", "Signature algorithm")

	if weakAlgorithms[details.Cert.SigAlg] {
		fmtc.Printf("{y}%s (WEAK){!}\n", details.Cert.SigAlg)
	} else {
		fmtc.Printf("%s\n", details.Cert.SigAlg)
	}

	fmtc.Printf(" %-24s {s}|{!} ", "Extended Validation")

	if details.Cert.ValidationType == "E" {
		fmtc.Println("{g}Yes{!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-24s {s}|{!} ", "Certificate Transparency")

	if details.Cert.SCT {
		fmtc.Println("{g}Yes{!}")
	} else {
		fmtc.Println("No")
	}

	if details.Cert.RevocationInfo != 0 {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Revocation information", getRevocationInfo(details.Cert.RevocationInfo))
	}

	fmtc.Printf(" %-24s {s}|{!} ", "Revocation status")

	if details.Cert.RevocationStatus&1 == 1 {
		fmtc.Printf("{r}%s{!}\n", getRevocationStatus(details.Cert.RevocationStatus))
	} else {
		fmtc.Printf("%s\n", getRevocationStatus(details.Cert.RevocationStatus))
	}

	fmtc.Printf(" %-24s {s}|{!} ", "Trusted")

	if details.Cert.Issues == 0 {
		fmtc.Println("{g}Yes{!}")
	} else {
		fmtc.Printf("{r}No (%s){!}\n", getCertIssuesDesc(details.Cert.Issues))
	}
}

// printCertificationPathsInfo print info about certificates in chain
func printCertificationPathsInfo(details *sslscan.EndpointDetails) {
	printCategoryHeader("Certification Paths")

	fmtc.Printf(" %-24s {s}|{!} %d\n", "Certificates provided", len(details.Chain.Certs))

	fmtc.Printf(" %-24s {s}|{!} ", "Chain issues")

	if details.Chain.Issues == 0 {
		fmtc.Println("None")
	} else {
		fmtc.Printf("{y}%s{!}\n", getChainIssuesDesc(details.Chain.Issues))
	}

	if len(details.Chain.Certs) > 1 {
		fmtutil.Separator(true)

		lastCertIndex := len(details.Chain.Certs) - 2

		for index, cert := range details.Chain.Certs[1:] {
			validUntilDate := time.Unix(cert.NotAfter/1000, 0)

			fmtc.Printf(" %-24s {s}|{!} %s\n", "Subject", cert.Label)
			fmtc.Printf(" %-24s {s}|{!} %s\n", "Valid until", timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"))

			fmtc.Printf(" %-24s {s}|{!} ", "Key")

			if cert.KeyAlg == "RSA" && cert.KeyStrength < 2048 {
				fmtc.Printf("{y}%s %d bits (WEAK){!}\n", cert.KeyAlg, cert.KeySize)
			} else {
				fmtc.Printf("%s %d bits\n", cert.KeyAlg, cert.KeySize)
			}

			fmtc.Printf(" %-24s {s}|{!} %s\n", "Issuer", cert.IssuerLabel)

			fmtc.Printf(" %-24s {s}|{!} ", "Signature algorithm")

			if weakAlgorithms[cert.SigAlg] {
				fmtc.Printf("{y}%s (WEAK){!}\n", cert.SigAlg)
			} else {
				fmtc.Printf("%s\n", cert.SigAlg)
			}

			if index < lastCertIndex {
				fmtutil.Separator(true)
			}
		}
	}
}

// printProtocolsInfo print info about supported protocols
func printProtocolsInfo(details *sslscan.EndpointDetails) {
	printCategoryHeader("Protocols")

	supportedProtocols := getProtocols(details.Protocols)

	for _, protocol := range protocolList {
		fmtc.Printf(" %-24s {s}|{!} ", protocol)

		switch {
		case protocol == "TLS 1.2":
			if supportedProtocols[protocol] {
				fmtc.Println("{g}Yes{!}")
			} else {
				fmtc.Println("{y}No{!}")
			}
		case protocol == "SSL 3.0" && supportedProtocols[protocol]:
			fmtc.Printf("{r}%s{!}\n", getBool(supportedProtocols[protocol]))
		case protocol == "SSL 2.0" && supportedProtocols[protocol]:
			fmtc.Printf("{r}%s{!}\n", getBool(supportedProtocols[protocol]))
		default:
			fmtc.Printf("%s\n", getBool(supportedProtocols[protocol]))
		}
	}
}

// printCipherSuitesInfo print info about supported cipher suites
func printCipherSuitesInfo(details *sslscan.EndpointDetails) map[int]int {
	printCategoryHeader("Cipher Suites")

	suiteIndex := make(map[int]int)

	for index, suite := range details.Suites.List {
		suiteIndex[suite.ID] = index

		tag := ""
		insecure := strings.Contains(suite.Name, "_RC4_")

		switch {
		case suite.Q != nil:
			tag = "{y}(WEAK){!}"
		case suite.DHStrength != 0 && suite.DHStrength < 2048:
			tag = "{y}(WEAK){!}"
		}

		if insecure {
			fmtc.Printf(" {r}%-42s{!} {s}|{!} {r}%d (INSECURE){!} ", suite.Name, suite.CipherStrength)
		} else {
			fmtc.Printf(" %-42s {s}|{!} %d ", suite.Name, suite.CipherStrength)
		}

		switch {
		case suite.DHStrength != 0:
			fmtc.Printf("{s-}(DH %d bits){!} "+tag+"\n",
				suite.DHStrength)
		case suite.ECDHBits != 0:
			fmtc.Printf("{s-}(ECDH %d bits ~ %d bits RSA){!} "+tag+"\n",
				suite.ECDHBits, suite.ECDHStrength)
		default:
			fmtc.Println(tag)
		}
	}

	return suiteIndex
}

// printHandshakeSimulationInfo print info about handshakes simulations
func printHandshakeSimulationInfo(details *sslscan.EndpointDetails, suiteIndex map[int]int) {
	printCategoryHeader("Handshake Simulation")

	for _, sim := range details.SIMS.Results {
		if sim.ErrorCode != 0 {
			fmtc.Printf(" %-24s {s}|{!} {r}Fail{!}\n", sim.Client.Name+" "+sim.Client.Version)
			continue
		}

		tag := "{s-}No FS{!}"
		suite := details.Suites.List[suiteIndex[sim.SuiteID]]

		if strings.Contains(suite.Name, "DHE_") {
			tag = "{g}   FS{!}"
		}

		if sim.Client.IsReference {
			fmtc.Printf(" %-38s {s}|{!} ", sim.Client.Name+" "+sim.Client.Version+" "+fmtc.Sprintf("{g}R"))
		} else {
			fmtc.Printf(" %-24s {s}|{!} ", sim.Client.Name+" "+sim.Client.Version)
		}

		switch protocolIDs[sim.ProtocolID] {
		case "TLS 1.2":
			fmtc.Printf("{g}%-7s{!} %-42s "+tag+" %d\n",
				protocolIDs[sim.ProtocolID],
				suite.Name, suite.CipherStrength,
			)
		case "SSL 2.0", "SSL 3.0":
			fmtc.Printf("{r}%-7s{!} %-42s "+tag+" %d\n",
				protocolIDs[sim.ProtocolID],
				suite.Name, suite.CipherStrength,
			)
		default:
			fmtc.Printf("%-7s %-42s "+tag+" %d\n",
				protocolIDs[sim.ProtocolID],
				suite.Name, suite.CipherStrength,
			)
		}
	}
}

// printProtocolDetailsInfo print endpoint protocol details
func printProtocolDetailsInfo(details *sslscan.EndpointDetails) {
	printCategoryHeader("Protocol Details")

	fmtc.Printf(" %-40s {s}|{!} ", "Secure Renegotiation")

	if details.RenegSupport&1 == 1 {
		fmtc.Println("{y}Not supported{!}")
	} else {
		fmtc.Println("{g}Supported{!}")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Secure Client-Initiated Renegotiation")

	if details.RenegSupport&4 == 4 {
		fmtc.Println("{y}Supported (DoS DANGER){!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Insecure Client-Initiated Renegotiation")

	if details.RenegSupport&1 == 1 {
		fmtc.Println("{r}Supported (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}

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

	fmtc.Printf(" %-40s {s}|{!} ", "DROWN")

	if details.DrownVulnerable {
		fmtc.Println("{r}Vulnerable{!}")
	} else {
		fmtc.Println("No")
	}

	if details.Logjam {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable{!}\n", "Logjam")
	}

	if details.Freak {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable{!}\n", "Freak")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Downgrade attack prevention")

	if !details.FallbackSCSV {
		fmtc.Println("{y}No, TLS_FALLBACK_SCSV not supported{!}")
	} else {
		fmtc.Println("{g}Yes, TLS_FALLBACK_SCSV supported{!}")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "SSL/TLS compression")

	if details.CompressionMethods != 0 {
		fmtc.Println("{r}Vulnerable (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "RC4")

	if details.SupportsRC4 {
		fmtc.Println("{r}Yes (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} %s\n", "Heartbeat (extension)", getBool(details.Heartbeat))

	fmtc.Printf(" %-40s {s}|{!} ", "Heartbleed (vulnerability)")

	if details.Heartbleed {
		fmtc.Println("{r}Vulnerable (INSECURE){!}")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "OpenSSL CCS vuln.")

	switch details.OpenSslCCS {
	case -1:
		fmtc.Println("{y}Test failed{!}")
	case 0:
		fmtc.Println("{y}Unknown{!}")
	case 1:
		fmtc.Println("No")
	case 2:
		fmtc.Println("{y}Possibly vulnerable, but not exploitable{!}")
	case 3:
		fmtc.Println("{r}Vulnerable and exploitable{!}")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "OpenSSL Padding Oracle vuln.")

	switch details.OpenSSLLuckyMinus20 {
	case -1:
		fmtc.Println("{y}Test failed{!}")
	case 0:
		fmtc.Println("{y}Unknown{!}")
	case 1:
		fmtc.Println("No")
	case 2:
		fmtc.Println("{r}Vulnerable and insecure{!}")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Forward Secrecy")

	switch {
	case details.ForwardSecrecy == 0:
		fmtc.Println("{y}No (WEAK){!}")
	case details.ForwardSecrecy&1 == 1:
		fmtc.Println("{y}With some browsers{!}")
	case details.ForwardSecrecy&2 == 2:
		fmtc.Println("With modern browsers")
	case details.ForwardSecrecy&4 == 4:
		fmtc.Println("{g}Yes (with most browsers) (ROBUST){!}")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Application-Layer Protocol Negotiation")

	if strings.Contains(details.NPNProtocols, "h2") {
		fmtc.Println("Yes")
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Next Protocol Negotiation")

	if details.SupportsNPN {
		fmtc.Printf("Yes {s-}(%s){!}\n", details.NPNProtocols)
	} else {
		fmtc.Println("No")
	}

	fmtc.Printf(" %-40s {s}|{!} ", "Session resumption (caching)")

	switch details.SessionResumption {
	case 0:
		fmtc.Println("{y}No (Session resumption is not enabled){!}")
	case 1:
		fmtc.Println("{y}No (IDs assigned but not accepted){!}")
	case 2:
		fmtc.Println("Yes")
	}

	fmtc.Printf(" %-40s {s}|{!} %s\n", "Session resumption (tickets)", getBool(details.SessionTickets&1 == 1))

	fmtc.Printf(" %-40s {s}|{!} ", "OCSP stapling")

	if details.OCSPStapling {
		fmtc.Println("{g}Yes{!}")
	} else {
		fmtc.Println("No")
	}

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

	fmtc.Printf(" %-40s {s}|{!} ", "Public Key Pinning (HPKP)")

	if details.HPKPPolicy != nil {
		switch details.HPKPPolicy.Status {
		case sslscan.HPKP_STATUS_INVALID:
			fmtc.Println("{r}Invalid{!}")
		case sslscan.HPKP_STATUS_DISABLED:
			fmtc.Println("{y}Disabled{!}")
		case sslscan.HPKP_STATUS_INCOMPLETE:
			fmtc.Println("{y}Incomplete{!}")
		case sslscan.HPKP_STATUS_VALID:
			fmtc.Printf("{g}Yes{!} ")

			if details.HPKPPolicy.IncludeSubDomains {
				fmtc.Printf(
					"{s-}(max-age=%d; includeSubdomains){!}\n",
					details.HPKPPolicy.MaxAge,
				)
			} else {
				fmtc.Printf(
					"{s-}(max-age=%d){!}\n",
					details.HPKPPolicy.MaxAge,
				)
			}

			for _, pin := range getPinsFromPolicy(details.HPKPPolicy) {
				fmtc.Printf(" %-40s {s}|{!} {s-}%s{!}\n", "", pin)
			}
		default:
			fmtc.Println("No")
		}
	} else {
		fmtc.Println("No")
	}

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

// printMiscellaneousInfo print miscellaneous info about endpoint
func printMiscellaneousInfo(info *sslscan.EndpointInfo) {
	printCategoryHeader("Miscellaneous")

	details := info.Details
	testDate := time.Unix(info.Details.HostStartTime/1000, 0)

	fmtc.Printf(
		" %-24s {s}|{!} %s {s-}(%s ago){!}\n", "Test date",
		timeutil.Format(testDate, "%Y/%m/%d %H:%M:%S"),
		timeutil.PrettyDuration(time.Since(testDate)),
	)

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Test duration", timeutil.PrettyDuration(info.Duration/1000))
	fmtc.Printf(" %-24s {s}|{!} %d\n", "HTTP status code", details.HTTPStatusCode)

	if details.HTTPForwarding != "" {
		if strings.Contains(details.HTTPForwarding, "http://") {
			fmtc.Printf(" %-24s {s}|{!} {y}%s (PLAINTEXT){!}\n", "HTTP forwarding", details.HTTPForwarding)
		} else {
			fmtc.Printf(" %-24s {s}|{!} %s\n", "HTTP forwarding", details.HTTPForwarding)
		}
	}

	if details.ServerSignature != "" {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "HTTP server signature", details.ServerSignature)
	}

	if info.ServerName != "" {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Server hostname", info.ServerName)
	}
}

// printCategoryHeader print category name and separators
func printCategoryHeader(name string) {
	fmtutil.Separator(true)
	fmtc.Printf(" ▾ {*}%s{!}\n", strings.ToUpper(name))
	fmtutil.Separator(true)
}

// getBool convert bool value to Yes/No
func getBool(value bool) string {
	switch value {
	case true:
		return "Yes"
	default:
		return "No"
	}
}

// getRevocationInfo decode revocation info
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

// getRevocationStatus return description for revocation status
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

// getCertIssuesDesc return description for cert issues
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

// getChainIssuesDesc return description for chain issues
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

// getProtocols return map with supported protocols
func getProtocols(protocols []*sslscan.Protocol) map[string]bool {
	var supported = make(map[string]bool)

	for _, protocol := range protocols {
		supported[protocol.Name+" "+protocol.Version] = true
	}

	return supported
}

// getPinsFromPolicy return slice with all pins in policy
func getPinsFromPolicy(policy *sslscan.HPKPPolicy) []string {
	var pins []string

	for _, pin := range strings.Split(policy.Header, ";") {
		pin = strings.TrimSpace(pin)
		pin = strings.Replace(pin, "\"", "", -1)
		pin = strings.Replace(pin, "=", ": ", 1)

		if strings.HasPrefix(pin, "pin-") {
			pins = append(pins, pin)
		}
	}

	return pins
}

// getHSTSPreloadingMarkers return slice with colored HSTS preload markers
func getHSTSPreloadingMarkers(preloads []*sslscan.HSTSPreload) string {
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
