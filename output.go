package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type outputFormat string

const (
	formatText outputFormat = "text"
	formatJSON outputFormat = "json"
)

type scanReport struct {
	Version   string           `json:"version"`
	StartedAt time.Time        `json:"started_at"`
	Target    string           `json:"target"`
	Hosts     []hostScanResult `json:"hosts"`
	Duration  string           `json:"duration"`
}

func printBanner() {
	fmt.Println(`
  ____       ____                                 
 / ___| ___ / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |  _ / _ \ \___ \/ __/ _` + "`" + ` | '_ \| '_ \ / _ \ '__|
| |_| | (_) |____) | (_| (_| | | | | | | |  __/ |   
 \____|\___/|______/\___\__,_|_| |_|_| |_|\___|_|   
                                                   v2.0
  GoScanner - Network Port Scanner
  By Tensor Security Academy
`)
}

func printHostResult(result hostScanResult, format outputFormat) {
	if format == formatJSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	if len(result.Ports) == 0 {
		fmt.Printf("\n[%s] No open ports found (scanned %d ports)\n", result.IP, result.Scanned)
		return
	}

	fmt.Printf("\n[%s] Open ports (%d/%d):\n", result.IP, len(result.Ports), result.Scanned)
	fmt.Println(strings.Repeat("-", 55))
	fmt.Printf("  %-8s %-12s %-10s %s\n", "PORT", "STATE", "SERVICE", "BANNER")
	fmt.Println(strings.Repeat("-", 55))
	for _, p := range result.Ports {
		banner := p.Banner
		if len(banner) > 30 {
			banner = banner[:30] + "..."
		}
		fmt.Printf("  %-8d %-12s %-10s %s\n", p.Port, p.State, p.Service, banner)
	}
	fmt.Println(strings.Repeat("-", 55))
}

func printReport(report scanReport, format outputFormat) {
	if format == formatJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}
	fmt.Printf("\nScan complete. Duration: %s\n", report.Duration)
}

func printProgress(done, total int64) {
	if total == 0 {
		return
	}
	pct := float64(done) / float64(total) * 100
	filled := int(pct / 2)
	bar := strings.Repeat("#", filled) + strings.Repeat(".", 50-filled)
	fmt.Printf("\r  [%s] %.1f%% (%d/%d)", bar, pct, done, total)
}

func saveToFile(path string, report scanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
