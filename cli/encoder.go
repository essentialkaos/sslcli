package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2023 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ////////////////////////////////////////////////////////////////////////////////// //

// encodeAsText print check info in simple text format
func encodeAsText(checksInfo []*HostCheckInfo) {
	for _, info := range checksInfo {
		grades := []string{}

		for _, endpoint := range info.Endpoints {
			grades = append(grades, endpoint.Grade)
		}

		fmt.Printf("%s %s\n", info.Host, strings.Join(grades, ","))
	}
}

// encodeAsJSON print check info in JSON format
func encodeAsJSON(checksInfo []*HostCheckInfo) {
	jsonData, err := json.MarshalIndent(checksInfo, "", "  ")

	if err != nil {
		fmt.Println("{}")
		os.Exit(1)
	}

	fmt.Println(string(jsonData[:]))
}

// encodeAsXML print check info in XML format
func encodeAsXML(checksInfo []*HostCheckInfo) {
	fmt.Println("<hosts>")

	for _, info := range checksInfo {
		fmt.Printf(
			"  <host name=\"%s\" lowest=\"%s\" highest=\"%s\" lowestNum=\"%.1f\" highestNum=\"%.1f\">\n",
			info.Host, info.LowestGrade, info.HighestGrade, info.LowestGradeNum, info.HighestGradeNum,
		)

		if len(info.Endpoints) != 0 {
			fmt.Println("    <endpoints>")

			for _, endpoint := range info.Endpoints {
				fmt.Printf(
					"      <endpoint ip=\"%s\" grade=\"%s\" grade=\"%.1f\" />\n",
					endpoint.IPAdress, endpoint.Grade, endpoint.GradeNum,
				)
			}

			fmt.Println("    </endpoints>")
		}

		fmt.Println("  </host>")
	}

	fmt.Println("</hosts>")
}

// encodeAsYAML print check info in YAML format
func encodeAsYAML(checksInfo []*HostCheckInfo) {
	fmt.Println("---")
	fmt.Println("hosts:")

	for _, info := range checksInfo {
		fmt.Println("  -")

		fmt.Println("    endpoints:")

		for _, endpoint := range info.Endpoints {
			fmt.Println("      -")
			fmt.Printf("        grade: %s\n", endpoint.Grade)
			fmt.Printf("        gradeNum: %.1f\n", endpoint.GradeNum)
			fmt.Printf("        ipAddress: \"%s\"\n", endpoint.IPAdress)
		}

		fmt.Printf("    host: %s\n", info.Host)
		fmt.Printf("    highestGrade: %s\n", info.HighestGrade)
		fmt.Printf("    highestGradeNum: %.1f\n", info.HighestGradeNum)
		fmt.Printf("    lowestGrade: %s\n", info.LowestGrade)
		fmt.Printf("    lowestGradeNum: %.1f\n", info.LowestGradeNum)
	}
}
