// SPDX-License-Identifier: MIT
//
//  main.go – точка входа. Обрабатывает флаги, читает файлы SARIF и
//  делегирует всю бизнес‑логику в service.go.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/correlator/service"
)

var (
	sastPath = flag.String("sast", "", "Path to SARIF file produced by a SAST scanner (required)")
	dastPath = flag.String("dast", "", "Path to SARIF file produced by a DAST scanner (required)")
	srcPath  = flag.String("src", "", "Path to SARIF file produced by a SAST scanner (required)")
	hostport = flag.String("hostport", "127.0.0.1:8000", "Path to SARIF file produced by a DAST scanner (required)")
	mode     = flag.String("mode", "simple", "Operation mode: \"simple\" – summary, \"scan\" – match findings")
	outPath  = flag.String("out", "correlated.json", "Output file for \"correlate\" mode (default: correlated.json)")
	ver      = flag.Bool("version", false, "Print version and exit")
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		`SARIF Correlator – утилита для быстрой работы с двумя SARIF‑отчетами.

Usage:
  %s -sast <file> -dast <file> [-mode simple|scan] [-out <file>]

Flags:
`,
		filepath.Base(os.Args[0]))
	flag.PrintDefaults()
	fmt.Fprintln(flag.CommandLine.Output(), `
Examples:
  # простая корреляция без запуска сканеров
  $ `+filepath.Base(os.Args[0])+` -sast sast.sarif -dast dast.sarif

  # корреляция с запуском сканеров, результат в result.json
  $ `+filepath.Base(os.Args[0])+` -mode scan -src /path/to/src -hostport 127.0.0.1:8000
`)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	svc := service.New()

	switch *mode {
	case "simple":
		if err := svc.Run(service.SimpleRunMode, sastPath, dastPath, nil, nil); err != nil {
			log.Fatal(err)
		}
	case "scan":
		if err := svc.Run(service.ScanRunMode, nil, nil, srcPath, hostport); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("mode not supported")
	}
}
