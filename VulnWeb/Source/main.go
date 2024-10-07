package main

import (
	"flag"
	"fmt"
	"os"
	"vulnweb/check"
	"vulnweb/utils"
)

func main() {
	urlPtr := flag.String("u", "", "URL to test vulnerabilities")
	flag.Parse()

	if *urlPtr == "" {
		check.Usage()
		os.Exit(1)
	}

	if err := check.ValidateURL(*urlPtr); err != nil {
		check.Usage()
		os.Exit(1)
	}

	// Genera el nombre del archivo de reporte desde utils
	reportFileName := utils.GenerateReportFile()

	// Crea el archivo de reporte
	file, err := os.Create(reportFileName)
	if err != nil {
		fmt.Println("Error creating report file:", err)
		os.Exit(1)
	}
	defer file.Close() // Cierra el archivo al final

	// Llama a la función checkVulnerabilities con la URL y el archivo de reporte
	utils.CheckVulnerabilities(*urlPtr, reportFileName)
}
