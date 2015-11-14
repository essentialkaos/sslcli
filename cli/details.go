package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2015 Essential Kaos                         //
//      Essential Kaos Open Source License <http://essentialkaos.com/ekol?en>         //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"strings"
	"time"

	"github.com/essentialkaos/ek/fmtc"
	"github.com/essentialkaos/ek/fmtutil"
	"github.com/essentialkaos/ek/timeutil"

	"github.com/essentialkaos/ssllabs"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type Line struct {
	Header     string
	LongHeader bool
}

// ////////////////////////////////////////////////////////////////////////////////// //

var protocolList = []string{"TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"}

var protocolIDs = map[int]string{
	512: "SSL 2.0",
	768: "SSL 3.0",
	769: "TLS 1.0",
	770: "TLS 1.1",
	771: "TLS 1.2",
}

var weakAlgorithms = map[string]bool{
	"SHA1withRSA": true,
	"MD5withRSA":  true,
	"MD2withRSA":  true,
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Get detailed info for all endpoints
func getDetailedInfo(ap *ssllabs.AnalyzeProgress, info *ssllabs.AnalyzeInfo) {
	showHeaders := len(info.Endpoints) > 1

	if showHeaders {
		fmtc.NewLine()
	}

	for index, endpoint := range info.Endpoints {
		if showHeaders {
			fmtc.Printf("\n{c} %s #%d (%s){!}\n\n", info.Host, index+1, endpoint.IPAdress)
		}

		getDetailedEndpointInfo(ap, endpoint.IPAdress)
	}
}

// Get and print detailed info for one endpoint
func getDetailedEndpointInfo(ap *ssllabs.AnalyzeProgress, ip string) {
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

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.Println(" {*}Server Key and Certificate{!}")
	fmtutil.Separator(true)

	validFromDate := time.Unix(details.Cert.NotBefore/1000, 0)
	validUntilDate := time.Unix(details.Cert.NotAfter/1000, 0)

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Common names", strings.Join(details.Cert.CommonNames, " "))

	if len(details.Cert.AltNames) > 0 {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Alternative names", strings.Join(details.Cert.AltNames, " "))
	}

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Valid from", timeutil.Format(validFromDate, "%Y/%m/%d %H:%M:%S"))
	fmtc.Printf(" %-24s {s}|{!} %s\n", "Valid until", timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"))
	fmtc.Printf(" %-24s {s}|{!} %s %d bits\n", "Key", info.Details.Key.Alg, details.Key.Size)
	fmtc.Printf(" %-24s {s}|{!} %s\n", "Weak Key (Debian)", getBool(details.Key.DebianFlaw))

	if details.Cert.Issues&64 == 64 {
		fmtc.Printf(" %-24s {s}|{!} %s {s}(Self-signed){!}\n", "Issuer", details.Cert.IssuerLabel)
	} else {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Issuer", details.Cert.IssuerLabel)
	}

	if weakAlgorithms[details.Cert.SigAlg] {
		fmtc.Printf(" %-24s {s}|{!} {y}%s (WEAK){!}\n", "Signature algorithm", details.Cert.SigAlg)
	} else {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Signature algorithm", details.Cert.SigAlg)
	}

	if details.Cert.ValidationType == "E" {
		fmtc.Printf(" %-24s {s}|{!} {g}Yes{!}\n", "Extended Validation")
	} else {
		fmtc.Printf(" %-24s {s}|{!} No\n", "Extended Validation")
	}

	if details.Cert.SCT {
		fmtc.Printf(" %-24s {s}|{!} {g}Yes{!}\n", "Certificate Transparency")
	} else {
		fmtc.Printf(" %-24s {s}|{!} No\n", "Certificate Transparency")
	}

	if details.Cert.RevocationInfo != 0 {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Revocation information", getRevocationInfo(details.Cert.RevocationInfo))
	}

	if details.Cert.RevocationStatus&1 == 1 {
		fmtc.Printf(" %-24s {s}|{!} {r}%s{!}\n", "Revocation status", getRevocationStatus(details.Cert.RevocationStatus))
	} else {
		fmtc.Printf(" %-24s {s}|{!} %s\n", "Revocation status", getRevocationStatus(details.Cert.RevocationStatus))
	}

	if details.Cert.Issues == 0 {
		fmtc.Printf(" %-24s {s}|{!} {g}Yes{!}\n", "Trusted")
	} else {
		fmtc.Printf(" %-24s {s}|{!} {r}No (%s){!}\n", "Trusted", getCertIssuesDesc(details.Cert.Issues))
	}

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.Println(" {*}Certification Paths{!}")
	fmtutil.Separator(true)

	fmtc.Printf(" %-24s {s}|{!} %d\n", "Certificates provided", len(details.Chain.Certs))

	if details.Chain.Issues == 0 {
		fmtc.Printf(" %-24s {s}|{!} None\n", "Chain issues")
	} else {
		fmtc.Printf(" %-24s {s}|{!} {y}%s{!}\n", "Chain issues", getChainIssuesDesc(details.Chain.Issues))
	}

	if len(details.Chain.Certs) > 1 {
		fmtutil.Separator(true)

		lastCertIndex := len(details.Chain.Certs) - 2

		for index, cert := range details.Chain.Certs[1:] {
			validUntilDate := time.Unix(cert.NotAfter/1000, 0)

			fmtc.Printf(" %-24s {s}|{!} %s\n", "Subject", cert.Label)
			fmtc.Printf(" %-24s {s}|{!} %s\n", "Valid until", timeutil.Format(validUntilDate, "%Y/%m/%d %H:%M:%S"))

			if cert.KeyAlg == "RSA" && cert.KeyStrength < 2048 {
				fmtc.Printf(" %-24s {s}|{!} {y}%s %d bits (WEAK){!}\n", "Key", cert.KeyAlg, cert.KeySize)
			} else {
				fmtc.Printf(" %-24s {s}|{!} %s %d bits\n", "Key", cert.KeyAlg, cert.KeySize)
			}

			fmtc.Printf(" %-24s {s}|{!} %s\n", "Issuer", cert.IssuerLabel)

			if weakAlgorithms[cert.SigAlg] {
				fmtc.Printf(" %-24s {s}|{!} {y}%s (WEAK){!}\n", "Signature algorithm", cert.SigAlg)
			} else {
				fmtc.Printf(" %-24s {s}|{!} %s\n", "Signature algorithm", cert.SigAlg)
			}

			if index < lastCertIndex {
				fmtutil.Separator(true)
			}
		}
	}

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.Println(" {*}Protocols{!}")
	fmtutil.Separator(true)

	supportedProtocols := getProtocols(details.Protocols)

	for _, protocol := range protocolList {
		switch {
		case protocol == "TLS 1.2":
			if supportedProtocols[protocol] {
				fmtc.Printf(" %-24s {s}|{!} {g}Yes{!}\n", protocol)
			} else {
				fmtc.Printf(" %-24s {s}|{!} {r}No{!}\n", protocol)
			}
		case protocol == "SSL 3.0" && supportedProtocols[protocol]:
			fmtc.Printf(" %-24s {s}|{!} {r}%s{!}\n", protocol, getBool(supportedProtocols[protocol]))
		case protocol == "SSL 2.0" && supportedProtocols[protocol]:
			fmtc.Printf(" %-24s {s}|{!} {r}%s{!}\n", protocol, getBool(supportedProtocols[protocol]))
		default:
			fmtc.Printf(" %-24s {s}|{!} %s\n", protocol, getBool(supportedProtocols[protocol]))
		}
	}

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.Println(" {*}Cipher Suites{!}")
	fmtutil.Separator(true)

	suiteIndex := make(map[int]int)

	for index, suite := range details.Suites.List {
		suiteIndex[suite.ID] = index

		tag := ""

		switch {
		case suite.Q != nil:
			tag = "{r}(INSECURE){!}"
		case suite.DHStrength != 0 && suite.DHStrength < 2048:
			tag = "{y}(WEAK){!}"
		}

		switch {
		case suite.DHStrength != 0:
			fmtc.Printf(" %-42s {s}|{!} %d {s}(DH %d bits){!} "+tag+"\n",
				suite.Name, suite.CipherStrength, suite.DHStrength)
		case suite.ECDHBits != 0:
			fmtc.Printf(" %-42s {s}|{!} %d {s}(ECDH %d bits ~ %d bits RSA){!} "+tag+"\n",
				suite.Name, suite.CipherStrength, suite.ECDHBits, suite.ECDHStrength)
		default:
			fmtc.Printf(" %-42s {s}|{!} %d "+tag+"\n", suite.Name, suite.CipherStrength)
		}
	}

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.Println(" {*}Handshake Simulation{!}")
	fmtutil.Separator(true)

	for _, sim := range details.SIMS.Results {
		if sim.ErrorCode != 0 {
			fmtc.Printf(" %-24s {s}|{!} {r}Fail{!}\n", sim.Client.Name+" "+sim.Client.Version)
			continue
		}

		tag := "{s}No FS{!}"
		suite := details.Suites.List[suiteIndex[sim.SuiteID]]

		if strings.Contains(suite.Name, "DHE_") {
			tag = "{g}   FS{!}"
		}

		switch protocolIDs[sim.ProtocolID] {
		case "TLS 1.2":
			fmtc.Printf(" %-24s {s}|{!} {g}%-7s{!} %-42s "+tag+" %d\n",
				sim.Client.Name+" "+sim.Client.Version,
				protocolIDs[sim.ProtocolID],
				suite.Name, suite.CipherStrength,
			)
		case "SSL 2.0", "SSL 3.0":
			fmtc.Printf(" %-24s {s}|{!} {r}%-7s{!} %-42s "+tag+" %d\n",
				sim.Client.Name+" "+sim.Client.Version,
				protocolIDs[sim.ProtocolID],
				suite.Name, suite.CipherStrength,
			)
		default:
			fmtc.Printf(" %-24s {s}|{!} %-7s %-42s "+tag+" %d\n",
				sim.Client.Name+" "+sim.Client.Version,
				protocolIDs[sim.ProtocolID],
				suite.Name, suite.CipherStrength,
			)
		}
	}

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.Println(" {*}Protocol Details{!}")
	fmtutil.Separator(true)

	if details.RenegSupport&1 == 1 {
		fmtc.Printf(" %-40s {s}|{!} {y}Not supported{!}\n", "Secure Renegotiation")
	} else {
		fmtc.Printf(" %-40s {s}|{!} {g}Supported{!}\n", "Secure Renegotiation")
	}

	if details.RenegSupport&4 == 4 {
		fmtc.Printf(" %-40s {s}|{!} {y}Supported (DoS DANGER){!}\n", "Secure Client-Initiated Renegotiation")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Secure Client-Initiated Renegotiation")
	}

	if details.RenegSupport&1 == 1 {
		fmtc.Printf(" %-40s {s}|{!} {r}Supported (INSECURE){!}\n", "Insecure Client-Initiated Renegotiation")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Insecure Client-Initiated Renegotiation")
	}

	// if details.VulnBeast {
	// 	fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable (INSECURE){!}\n", "BEAST attack")
	// } else {
	// 	fmtc.Printf(" %-40s {s}|{!} No\n", "BEAST attack")
	// }

	if details.Poodle {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable (INSECURE){!}\n", "POODLE (SSLv3)")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "POODLE (SSLv3)")
	}

	if details.PoodleTLS == 2 {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable (INSECURE){!}\n", "POODLE (TLS)")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "POODLE (TLS)")
	}

	if !details.FallbackSCSV {
		fmtc.Printf(" %-40s {s}|{!} {y}No, TLS_FALLBACK_SCSV not supported{!}\n", "Downgrade attack prevention")
	} else {
		fmtc.Printf(" %-40s {s}|{!} {g}Yes, TLS_FALLBACK_SCSV supported{!}\n", "Downgrade attack prevention")
	}

	if details.CompressionMethods != 0 {
		fmtc.Printf(" %-40s {s}|{!} {r}Yes (INSECURE){!}\n", "SSL/TLS compression")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "SSL/TLS compression")
	}

	if details.SupportsRC4 {
		fmtc.Printf(" %-40s {s}|{!} {y}Yes (WEAK){!}\n", "RC4")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "RC4")
	}

	fmtc.Printf(" %-40s {s}|{!} %s\n", "Heartbeat (extension)", getBool(details.Heartbeat))

	if details.Heartbleed {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable (INSECURE){!}\n", "Heartbleed (vulnerability)")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Heartbleed (vulnerability)")
	}

	if details.Heartbleed {
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable (INSECURE){!}\n", "Heartbleed (vulnerability)")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Heartbleed (vulnerability)")
	}

	switch details.OpenSslCCS {
	case -1:
		fmtc.Printf(" %-40s {s}|{!} Test failed\n", "OpenSSL CCS vuln. (CVE-2014-0224)")
	case 0:
		fmtc.Printf(" %-40s {s}|{!} Unknown\n", "OpenSSL CCS vuln. (CVE-2014-0224)")
	case 1:
		fmtc.Printf(" %-40s {s}|{!} No\n", "OpenSSL CCS vuln. (CVE-2014-0224)")
	case 2:
		fmtc.Printf(" %-40s {s}|{!} {y}Possibly vulnerable, but not exploitable{!}\n", "OpenSSL CCS vuln. (CVE-2014-0224)")
	case 3:
		fmtc.Printf(" %-40s {s}|{!} {r}Vulnerable and exploitable{!}\n", "OpenSSL CCS vuln. (CVE-2014-0224)")
	}

	switch {
	case details.ForwardSecrecy == 0:
		fmtc.Printf(" %-40s {s}|{!} {y}No (WEAK){!}\n", "Forward Secrecy")
	case details.ForwardSecrecy&1 == 1:
		fmtc.Printf(" %-40s {s}|{!} {y}With some browsers{!}\n", "Forward Secrecy")
	case details.ForwardSecrecy&2 == 2:
		fmtc.Printf(" %-40s {s}|{!} With modern browsers\n", "Forward Secrecy")
	case details.ForwardSecrecy&4 == 4:
		fmtc.Printf(" %-40s {s}|{!} {g}Yes (with most browsers) (ROBUST){!}\n", "Forward Secrecy")
	}

	if details.SupportsNPN {
		fmtc.Printf(" %-40s {s}|{!} Yes {s}(%s){!}\n", "Next Protocol Negotiation (NPN)", details.NPNProtocols)
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Next Protocol Negotiation (NPN)")
	}

	switch details.SessionResumption {
	case 0:
		fmtc.Printf(" %-40s {s}|{!} {y}No (Session resumption is not enabled){!}\n", "Session resumption (caching)")
	case 1:
		fmtc.Printf(" %-40s {s}|{!} {y}No (IDs assigned but not accepted){!}\n", "Session resumption (caching)")
	case 2:
		fmtc.Printf(" %-40s {s}|{!} Yes\n", "Session resumption (caching)")
	}

	fmtc.Printf(" %-40s {s}|{!} %s\n", "Session resumption (tickets)", getBool(details.SessionTickets&1 == 1))

	if details.OCSPStapling {

		fmtc.Printf(" %-40s {s}|{!} {g}Yes{!}\n", "OCSP stapling")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "OCSP stapling")
	}

	if details.STSResponseHeader != "" {
		fmtc.Printf(" %-40s {s}|{!} {g}Yes{!} {s}(%s){!}\n", "Strict Transport Security (HSTS)", details.STSResponseHeader)
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Strict Transport Security (HSTS)")
	}

	if details.PKPResponseHeader != "" {
		fmtc.Printf(" %-40s {s}|{!} {g}Yes{!} {s}(%s){!}\n", "Public Key Pinning (HPKP)", details.PKPResponseHeader)
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Public Key Pinning (HPKP)")
	}

	if details.DHUsesKnownPrimes != 0 {
		fmtc.Printf(" %-40s {s}|{!} {y}Yes (Replace with custom DH parameters if possible){!}\n", "Uses common DH primes")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "Uses common DH primes")
	}

	if details.DHYsReuse {
		fmtc.Printf(" %-40s {s}|{!} {y}Yes{!}\n", "DH public server param (Ys) reuse")
	} else {
		fmtc.Printf(" %-40s {s}|{!} No\n", "DH public server param (Ys) reuse")
	}

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.Println(" {*}Miscellaneous{!}")
	fmtutil.Separator(true)

	testDate := time.Unix(details.HostStartTime/1000, 0)

	fmtc.Printf(" %-24s {s}|{!} %s\n", "Test date", timeutil.Format(testDate, "%Y/%m/%d %H:%M:%S"))
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

	// ////////////////////////////////////////////////////////////////////////////////// //

	fmtutil.Separator(true)
	fmtc.NewLine()
}

// Convert bool value to Yes/No
func getBool(value bool) string {
	switch value {
	case true:
		return "Yes"
	default:
		return "No"
	}
}

// Decode revocation info
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

// Get description for revocation status
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

// Get description for cert issues
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

// Get description for chain issues
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

// Get map with supported protocols
func getProtocols(protocols []*ssllabs.ProtocolInfo) map[string]bool {
	var supported = make(map[string]bool)

	for _, protocol := range protocols {
		supported[protocol.Name+" "+protocol.Version] = true
	}

	return supported
}
