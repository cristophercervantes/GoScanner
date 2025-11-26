// This tool is created by Cristopher and this is a project by Tensor Security Academy (TSA)

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cristophercervantes/GoScanner/internal/discovery"
	"github.com/cristophercervantes/GoScanner/internal/scanner"
	"github.com/cristophercervantes/GoScanner/pkg/network"
	scannertypes "github.com/cristophercervantes/GoScanner/pkg/types" // Renamed import to avoid conflict
)

const banner = `
╔═══════════════════════════════════════════════╗
║                  GoScanner                    ║
║           Network Discovery Tool              ║
║             Author: Cristopher                ║
╚═══════════════════════════════════════════════╝
`

func main() {
	config := parseFlags()
	
	// This will take input file if provided
	targets := processTargets(config)

	if len(targets) == 0 && !config.ListScan {
		fmt.Print(banner)
		fmt.Println("ERROR: No targets specified")
		fmt.Println("Use -h for help")
		os.Exit(1)
	}

	
	if config.ListScan {
		runListScan(targets)
		return
	}

	
	shouldRunDiscovery := config.PingOnly || 
		config.TCPSynPorts != "" || config.TCPAckPorts != "" || 
		config.UDPPorts != "" || config.SCTPPorts != "" ||
		config.ICMPEcho || config.ICMPTimestamp || config.ICMPNetmask ||
		config.IpProtocolPing != ""

	if shouldRunDiscovery {
		runHostDiscovery(config, targets)
		return
	}

	
	runPortScan(config, targets)
}

func processTargets(config scannertypes.ScanConfig) []string {
	var targets []string
	
	if config.InputFile != "" {
		fileTargets, err := readTargetsFromFile(config.InputFile)
		if err != nil {
			fmt.Printf("Failed to read input file: %s\n", err)
			os.Exit(1)
		}
		targets = append(targets, fileTargets...)
	}
	
	if config.Target != "" {
		targets = append(targets, config.Target)
	}
	
	return targets
}

func readTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		target := strings.TrimSpace(fileScanner.Text())
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}
	return targets, fileScanner.Err()
}

func runListScan(targets []string) {
	fmt.Print(banner)
	fmt.Println("List Scan - Targets to be scanned:")
	fmt.Println(strings.Repeat("─", 50))
	
	allTargets := []string{}
	
	for _, target := range targets {
		// Expand CIDR
		if network.IsCIDR(target) {
			ips, err := network.ExpandCIDR(target)
			if err == nil && len(ips) > 0 {
				allTargets = append(allTargets, ips...)
				continue
			}
		}
		
		if network.IsIPRange(target) {
			ips, err := network.ParseIPRange(target)
			if err == nil && len(ips) > 0 {
				allTargets = append(allTargets, ips...)
				continue
			}
		}
		
		// For hostnames, resolve them
		if net.ParseIP(target) == nil {
			ips, err := network.ResolveHost(target)
			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					allTargets = append(allTargets, fmt.Sprintf("%s (%s)", ip, target))
				}
				continue
			}
		}
		
		// Single IP address
		allTargets = append(allTargets, target)
	}
	
	// Remove duplicates and print
	uniqueTargets := removeDuplicates(allTargets)
	for _, target := range uniqueTargets {
		fmt.Println(target)
	}
	fmt.Printf("\nTotal targets: %d\n", len(uniqueTargets))
}

func removeDuplicates(targets []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, target := range targets {
		if !seen[target] {
			seen[target] = true
			result = append(result, target)
		}
	}
	return result
}

func runHostDiscovery(config scannertypes.ScanConfig, targets []string) {
	fmt.Print(banner)
	
	if len(targets) == 0 {
		fmt.Println("ERROR: No targets specified for host discovery")
		os.Exit(1)
	}

	fmt.Printf("Starting host discovery at %s\n", time.Now().Format("2006-01-02 15:04"))
	
	discoveryObj := discovery.NewDiscovery(config)
	activeHosts, err := discoveryObj.DiscoverHosts(targets)
	if err != nil {
		fmt.Printf("Discovery failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nHost discovery scan completed\n")
	fmt.Printf("Discovered %d hosts\n", len(activeHosts))
	
	if len(activeHosts) > 0 {
		fmt.Println("\nDiscovered hosts:")
		fmt.Println(strings.Repeat("─", 65))
		fmt.Printf("%-18s %-20s %s\n", "IP", "MAC", "STATUS")
		fmt.Println(strings.Repeat("─", 65))
		
		for _, host := range activeHosts {
			status := "UP"
			
			// Try to get hostname if DNS resolving is active
			hostname := ""
			if !config.NoDNS {
				hostname = getHostname(host.IP)
			}
			
		
			macDisplay := host.MAC
			if macDisplay == "" {
				macDisplay = "" 
			}
			
			if hostname != "" && hostname != host.IP {
				fmt.Printf("%-18s %-20s %s (%s)\n", host.IP, macDisplay, status, hostname)
			} else {
				fmt.Printf("%-18s %-20s %s\n", host.IP, macDisplay, status)
			}
		}
	} else {
		fmt.Println("No hosts discovered")
	}
}

func getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Return the first hostname, remove trailing dot
	hostname := names[0]
	if strings.HasSuffix(hostname, ".") {
		hostname = hostname[:len(hostname)-1]
	}
	return hostname
}

func runPortScan(config scannertypes.ScanConfig, targets []string) {
	fmt.Print(banner)
	
	if len(targets) == 0 {
		fmt.Println("ERROR: No targets specified for port scan")
		os.Exit(1)
	}

	ports, err := network.ParsePortRange(config.Ports)
	if err != nil {
		fmt.Printf("ERROR: Invalid port specification: %s\n", err)
		os.Exit(1)
	}

	if len(ports) == 0 {
		fmt.Println("ERROR: No valid ports to scan")
		os.Exit(1)
	}

	fmt.Printf("Starting GoScanner at %s\n", time.Now().Format("2006-01-02 15:04"))
	
	
	if config.SkipDiscovery {
		fmt.Println("Skipping host discovery - treating all hosts as online")
		for _, target := range targets {
			fmt.Printf("\nScanning: %s\n", target)
			config.Target = target
			scannerObj, err := scanner.CreateScanner(config)
			if err != nil {
				fmt.Printf("ERROR creating scanner for %s: %s\n", target, err)
				continue
			}
			
			results, err := scannerObj.Scan()
			if err != nil {
				fmt.Printf("Scan failed for %s: %s\n", target, err)
				continue
			}
			outputResults(results, config)
		}
		return
	}
	
	
	fmt.Println("Running host discovery first...")
	discoveryObj := discovery.NewDiscovery(config)
	activeHosts, err := discoveryObj.DiscoverHosts(targets)
	if err != nil {
		fmt.Printf("Host discovery failed: %s\n", err)
		os.Exit(1)
	}
	
	if len(activeHosts) == 0 {
		fmt.Println("No active hosts found to scan")
		return
	}
	
	fmt.Printf("\nScanning %d active hosts...\n", len(activeHosts))
	for _, host := range activeHosts {
		fmt.Printf("\nScanning: %s\n", host.IP)
		config.Target = host.IP
		scannerObj, err := scanner.CreateScanner(config)
		if err != nil {
			fmt.Printf("ERROR creating scanner for %s: %s\n", host.IP, err)
			continue
		}
		
		results, err := scannerObj.Scan()
		if err != nil {
			fmt.Printf("Scan failed for %s: %s\n", host.IP, err)
			continue
		}
		outputResults(results, config)
	}
}

func outputResults(results []scannertypes.ScanResult, config scannertypes.ScanConfig) {
	openPorts := countOpenPorts(results)
	
	if len(results) == 0 {
		fmt.Println("No ports scanned")
		return
	}
	
	fmt.Printf("\nPORT      STATE SERVICE\n")
	fmt.Println(strings.Repeat("─", 30))
	for _, result := range results {
		if result.State == "open" {
			fmt.Printf("%-5d/tcp %-5s %s\n", result.Port, result.State, result.Service)
		}
	}
	
	fmt.Printf("\n%d ports scanned, %d open ports found\n", len(results), openPorts)
}

func countOpenPorts(results []scannertypes.ScanResult) int {
	count := 0
	for _, result := range results {
		if result.State == "open" {
			count++
		}
	}
	return count
}

func parseFlags() scannertypes.ScanConfig {
	var config scannertypes.ScanConfig
	

	flag.BoolVar(&config.ListScan, "list-targets", false, "List Scan - simply list targets to scan")
	flag.BoolVar(&config.PingOnly, "ping-only", false, "Ping Scan - disable port scan, only discover hosts")
	flag.BoolVar(&config.SkipDiscovery, "skip-discovery", false, "Treat all hosts as online -- skip host discovery")
	
	
	flag.StringVar(&config.TCPSynPorts, "tcp-syn", "", "TCP SYN discovery to given ports (e.g., -tcp-syn 22,80,443)")
	flag.StringVar(&config.TCPAckPorts, "tcp-ack", "", "TCP ACK discovery to given ports")
	flag.StringVar(&config.UDPPorts, "udp-probe", "", "UDP discovery to given ports (e.g., -udp-probe 53,161)")
	flag.StringVar(&config.SCTPPorts, "sctp-probe", "", "SCTP discovery to given ports")
	

	flag.BoolVar(&config.ICMPEcho, "icmp-echo", false, "ICMP echo request discovery")
	flag.BoolVar(&config.ICMPTimestamp, "icmp-timestamp", false, "ICMP timestamp request discovery")
	flag.BoolVar(&config.ICMPNetmask, "icmp-netmask", false, "ICMP netmask request discovery")
	
	
	flag.StringVar(&config.IpProtocolPing, "ip-proto", "", "IP Protocol Ping (e.g., -ip-proto 1,2,4)")
	
	
	flag.BoolVar(&config.NoDNS, "no-dns", false, "Never do DNS resolution")
	flag.BoolVar(&config.AlwaysDNS, "always-dns", false, "Always resolve [default: sometimes]")
	flag.StringVar(&config.DNSServers, "dns-servers", "", "Specify custom DNS servers")
	flag.BoolVar(&config.SystemDNS, "system-dns", false, "Use OS's DNS resolver")
	
	
	flag.BoolVar(&config.Traceroute, "traceroute", false, "Trace hop path to each host")
	flag.StringVar(&config.InputFile, "input-file", "", "Input from list of hosts/networks")
	
	
	flag.StringVar(&config.Target, "target", "", "Target host, IP, CIDR, or IP range")
	flag.StringVar(&config.Ports, "ports", "1-1000", "Ports to scan")
	flag.StringVar(&config.ScanType, "scan-type", "tcp", "Scan type: tcp, syn")
	flag.IntVar(&config.Threads, "threads", 50, "Number of concurrent threads")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	
	config.Timeout = 3 * time.Second
	
	flag.Usage = func() {
		fmt.Print(banner)
		fmt.Println("Usage: goscanner [Scan Type] [Options] {target specification}")
		fmt.Println("\nTARGET SPECIFICATION:")
		fmt.Println("  Can pass IPv4 addresses, hostnames, CIDR ranges, or IP ranges:")
		fmt.Println("    192.168.1.1")
		fmt.Println("    192.168.1.0/24")
		fmt.Println("    192.168.1.1-100")
		fmt.Println("    192.168.1.1-192.168.1.100")
		fmt.Println("  -target: Specify target")
		fmt.Println("  -input-file <file>: Input from list of hosts/networks")
		
		fmt.Println("\nHOST DISCOVERY:")
		fmt.Println("  Target Specification:")
		fmt.Println("    -list-targets: List Scan - simply list targets to scan")
		fmt.Println("    -ping-only: Ping Scan - disable port scan, only discover hosts")
		fmt.Println("    -skip-discovery: Treat all hosts as online -- skip host discovery")
		
		fmt.Println("  Port-Specific Discovery:")
		fmt.Println("    -tcp-syn <portlist>: TCP SYN discovery (e.g., -tcp-syn 22,80,443)")
		fmt.Println("    -tcp-ack <portlist>: TCP ACK discovery")
		fmt.Println("    -udp-probe <portlist>: UDP discovery (e.g., -udp-probe 53,161)")
		fmt.Println("    -sctp-probe <portlist>: SCTP discovery")
		
		fmt.Println("  ICMP Discovery:")
		fmt.Println("    -icmp-echo: ICMP echo request discovery")
		fmt.Println("    -icmp-timestamp: ICMP timestamp request discovery") 
		fmt.Println("    -icmp-netmask: ICMP netmask request discovery")
		
		fmt.Println("  Protocol Ping:")
		fmt.Println("    -ip-proto <protocols>: IP Protocol Ping (e.g., -ip-proto 1,2,4)")
		
		fmt.Println("\nDNS OPTIONS:")
		fmt.Println("  -no-dns: Never do DNS resolution")
		fmt.Println("  -always-dns: Always resolve [default: sometimes]")
		fmt.Println("  -dns-servers <servers>: Specify custom DNS servers")
		fmt.Println("  -system-dns: Use OS's DNS resolver")
		
		fmt.Println("\nPORT SCANNING:")
		fmt.Println("  -ports <ports>: Ports to scan (default: 1-1000)")
		fmt.Println("  -scan-type <type>: tcp or syn (default: tcp)")
		fmt.Println("  -threads <number>: Parallel threads (default: 50)")
		fmt.Println("  -verbose: Verbose output")
		
		fmt.Println("\nOTHER OPTIONS:")
		fmt.Println("  -traceroute: Trace hop path to each host")
		
		fmt.Println("\nEXAMPLES:")
		fmt.Println("  Host Discovery:")
		fmt.Println("    goscanner -list-targets 192.168.1.0/24")
		fmt.Println("    goscanner -ping-only 192.168.1.0/24")
		fmt.Println("    goscanner -tcp-syn 22,80,443 192.168.1.0/24")
		fmt.Println("    goscanner -udp-probe 53,161 -icmp-echo 192.168.1.1-100")
		fmt.Println("    goscanner -tcp-syn 80 google.com")
		fmt.Println("    goscanner -skip-discovery -target 192.168.1.1 -ports 1-100")
		
		fmt.Println("  Port Scanning:")
		fmt.Println("    goscanner -target scanme.nmap.org -ports 22,80,443")
		fmt.Println("    goscanner -input-file targets.txt -ports 1-1000")
	}
	
	flag.Parse()
	return config
}
