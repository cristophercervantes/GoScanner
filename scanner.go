package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type portState string

const (
	stateOpen   portState = "open"
	stateClosed portState = "closed"
)

type portResult struct {
	Port    int       `json:"port"`
	State   portState `json:"state"`
	Service string    `json:"service"`
	Banner  string    `json:"banner,omitempty"`
	RTT     time.Duration `json:"-"`
}

type hostScanResult struct {
	IP      string       `json:"ip"`
	Ports   []portResult `json:"ports"`
	Scanned int          `json:"scanned"`
}

type scanOptions struct {
	timeout    time.Duration
	workers    int
	grabBanner bool
}

func defaultScanOptions() scanOptions {
	return scanOptions{
		timeout:    2 * time.Second,
		workers:    500,
		grabBanner: true,
	}
}

func scanHost(ip string, ports []int, opts scanOptions, progress *atomic.Int64) hostScanResult {
	type job struct {
		ip   string
		port int
	}

	jobs := make(chan job, len(ports))
	results := make(chan portResult, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < opts.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := scanPort(j.ip, j.port, opts)
				if progress != nil {
					progress.Add(1)
				}
				if r.State == stateOpen {
					results <- r
				}
			}
		}()
	}

	for _, p := range ports {
		jobs <- job{ip: ip, port: p}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var open []portResult
	for r := range results {
		open = append(open, r)
	}

	return hostScanResult{
		IP:      ip,
		Ports:   sortPorts(open),
		Scanned: len(ports),
	}
}

func scanPort(ip string, port int, opts scanOptions) portResult {
	result := portResult{Port: port, State: stateClosed}

	address := fmt.Sprintf("%s:%d", ip, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, opts.timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.RTT = time.Since(start)
	result.State = stateOpen
	result.Service = knownService(port)

	if opts.grabBanner {
		result.Banner = grabBanner(conn, port, opts.timeout)
	}

	return result
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout / 2))

	switch port {
	case 80, 8080, 8000, 8443:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	default:
		fmt.Fprintf(conn, "\r\n")
	}

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 80 {
			line = line[:80]
		}
		return line
	}
	return ""
}

func knownService(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-alt",
		8443:  "https-alt",
		27017: "mongodb",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

func sortPorts(ports []portResult) []portResult {
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[j].Port < ports[i].Port {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}
	return ports
}
