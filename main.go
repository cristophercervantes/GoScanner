package main

import (
	"flag"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

var defaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
}

func main() {
	var (
		target      = flag.String("target", "", "Target IP, hostname, CIDR, or range (e.g. 192.168.1.0/24)")
		ports       = flag.String("ports", "", "Ports to scan (e.g. 80,443 or 1-1000). Defaults to common ports")
		workers     = flag.Int("workers", 500, "Number of concurrent workers")
		timeout     = flag.Int("timeout", 2000, "Connection timeout in milliseconds")
		pingOnly    = flag.Bool("ping-only", false, "Only discover live hosts, skip port scanning")
		skipDisc    = flag.Bool("skip-discovery", false, "Skip host discovery and scan all targets directly")
		grabBanner  = flag.Bool("banners", true, "Grab service banners from open ports")
		listTargets = flag.Bool("list-targets", false, "List expanded targets without scanning")
		outputFmt   = flag.String("output", "text", "Output format: text or json")
		saveFile    = flag.String("save", "", "Save results to file (JSON)")
		versionFlag = flag.Bool("version", false, "Show version info")
		updateFlag  = flag.Bool("update", false, "Update GoScanner to the latest version")
		checkUpdate = flag.Bool("check-update", false, "Check if a newer version is available")
		noProgress  = flag.Bool("no-progress", false, "Disable progress bar")
	)
	flag.Parse()

	if *versionFlag {
		printVersionInfo()
		return
	}

	if *updateFlag {
		runUpdate()
		return
	}

	if *checkUpdate {
		runCheckUpdate()
		return
	}

	printBanner()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: -target is required")
		fmt.Fprintln(os.Stderr, "Usage: GoScanner -target <host> [options]")
		fmt.Fprintln(os.Stderr, "       GoScanner -update")
		fmt.Fprintln(os.Stderr, "       GoScanner -version")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("Expanding targets for: %s\n", *target)
	targets, err := expandTargets(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d target(s)\n", len(targets))

	if *listTargets {
		for _, t := range targets {
			fmt.Println(t)
		}
		return
	}

	var portList []int
	if *ports == "" {
		portList = defaultPorts
		fmt.Printf("Using default %d common ports\n", len(portList))
	} else {
		portList, err = parsePorts(*ports)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Scanning %d port(s)\n", len(portList))
	}

	scanTimeout := time.Duration(*timeout) * time.Millisecond
	fmt.Printf("Timeout: %dms | Workers: %d\n\n", *timeout, *workers)

	outFmt := formatText
	if *outputFmt == "json" {
		outFmt = formatJSON
	}

	startTime := time.Now()
	report := scanReport{
		Version:   currentVersion,
		StartedAt: startTime,
		Target:    *target,
	}

	var liveHosts []string

	if *skipDisc {
		liveHosts = targets
	} else {
		fmt.Printf("Discovering live hosts...\n")
		discOpts := defaultDiscoveryOptions()
		discOpts.timeout = scanTimeout
		discOpts.workers = *workers
		liveResults := discoverHosts(targets, discOpts)
		for _, r := range liveResults {
			liveHosts = append(liveHosts, r.ip)
		}
		fmt.Printf("Found %d live host(s)\n\n", len(liveHosts))
	}

	if *pingOnly {
		fmt.Printf("Live hosts:\n")
		for _, h := range liveHosts {
			fmt.Printf("  %s\n", h)
		}
		fmt.Printf("\nDone. Duration: %s\n", time.Since(startTime).Round(time.Millisecond))
		return
	}

	if len(liveHosts) == 0 {
		fmt.Println("No live hosts found. Use -skip-discovery to scan anyway.")
		return
	}

	scanOpts := defaultScanOptions()
	scanOpts.timeout = scanTimeout
	scanOpts.workers = *workers
	scanOpts.grabBanner = *grabBanner

	totalPorts := int64(len(liveHosts) * len(portList))
	var progress atomic.Int64

	if !*noProgress && outFmt != formatJSON {
		go func() {
			for {
				done := progress.Load()
				printProgress(done, totalPorts)
				if done >= totalPorts {
					fmt.Println()
					return
				}
				time.Sleep(150 * time.Millisecond)
			}
		}()
	}

	var results []hostScanResult
	for _, host := range liveHosts {
		result := scanHost(host, portList, scanOpts, &progress)
		results = append(results, result)
		if !*noProgress && outFmt != formatJSON {
			time.Sleep(10 * time.Millisecond)
		}
		printHostResult(result, outFmt)
	}

	report.Hosts = results
	report.Duration = time.Since(startTime).Round(time.Millisecond).String()

	printReport(report, outFmt)

	if *saveFile != "" {
		if err := saveToFile(*saveFile, report); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save results: %v\n", err)
		} else {
			fmt.Printf("Results saved to %s\n", *saveFile)
		}
	}
}

func runUpdate() {
	fmt.Printf("Current version: %s\n", currentVersion)
	fmt.Println("Checking for updates...")

	release, newer, err := checkForUpdate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
		if isGoAvailable() {
			fmt.Println("Attempting update via go install...")
			if err := updateViaGoInstall(); err != nil {
				fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Go is not installed. Visit https://github.com/cristophercervantes/GoScanner/releases")
			os.Exit(1)
		}
		return
	}

	if !newer {
		fmt.Printf("You are already on the latest version (%s)\n", release.TagName)
		return
	}

	fmt.Printf("New version available: %s\n", release.TagName)

	if isGoAvailable() {
		fmt.Println("Updating via go install...")
		if err := updateViaGoInstall(); err != nil {
			fmt.Println("go install failed, trying binary download...")
			if err := updateViaBinary(release); err != nil {
				fmt.Fprintf(os.Stderr, "Binary update failed: %v\n", err)
				fmt.Printf("Manual install: go install %s@latest\n", modulePath)
				os.Exit(1)
			}
		}
	} else {
		fmt.Println("Downloading binary release...")
		if err := updateViaBinary(release); err != nil {
			fmt.Fprintf(os.Stderr, "Binary update failed: %v\n", err)
			fmt.Printf("Visit: %s\n", release.HTMLURL)
			os.Exit(1)
		}
	}
}

func runCheckUpdate() {
	fmt.Printf("Current version: %s\n", currentVersion)
	release, newer, err := checkForUpdate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Check failed: %v\n", err)
		os.Exit(1)
	}
	if newer {
		fmt.Printf("Update available: %s -> %s\n", currentVersion, release.TagName)
		fmt.Printf("Run: goscanner -update\n")
	} else {
		fmt.Printf("You are up to date (%s)\n", release.TagName)
	}
}
