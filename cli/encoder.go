package cli

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2016 Essential Kaos                         //
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

func encodeAsText(checksInfo []*HostCheckInfo) {
	for _, info := range checksInfo {
		grades := []string{}

		for _, endpoint := range info.Endpoints {
			grades = append(grades, endpoint.Grade)
		}

		fmt.Printf("%s %s\n", info.Host, strings.Join(grades, ","))
	}
}

func encodeAsJSON(checksInfo []*HostCheckInfo) {
	jsonData, err := json.MarshalIndent(checksInfo, "", "  ")

	if err != nil {
		fmt.Println("{}")
		os.Exit(1)
	}

	fmt.Println(string(jsonData[:]))
}

func encodeAsXML(checksInfo []*HostCheckInfo) {
	fmt.Println("<hosts>")

	for _, info := range checksInfo {
		fmt.Printf("  <host name=\"%s\" lowest=\"%s\" highest=\"%s\">\n",
			info.Host, info.LowestGrade, info.HighestGrade)

		if len(info.Endpoints) != 0 {
			fmt.Println("    <endpoints>")

			for _, endpoint := range info.Endpoints {
				fmt.Printf("      <endpoint ip=\"%s\" grade=\"%s\" />\n",
					endpoint.IPAdress, endpoint.Grade)
			}

			fmt.Println("    </endpoints>")
		}

		fmt.Println("  </host>")
	}

	fmt.Println("</hosts>")
}
