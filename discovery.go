package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type hostResult struct {
	ip     string
	alive  bool
	rtt    time.Duration
	method string
}

type discoveryOptions struct {
	timeout      time.Duration
	workers      int
	tcpFallback  bool
}

func defaultDiscoveryOptions() discoveryOptions {
	return discoveryOptions{
		timeout:     1 * time.Second,
		workers:     256,
		tcpFallback: true,
	}
}

func discoverHosts(targets []string, opts discoveryOptions) []hostResult {
	jobs := make(chan string, len(targets))
	results := make(chan hostResult, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < opts.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results <- probeHost(ip, opts)
			}
		}()
	}

	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var alive []hostResult
	for r := range results {
		if r.alive {
			alive = append(alive, r)
		}
	}
	return alive
}

func probeHost(ip string, opts discoveryOptions) hostResult {
	result := hostResult{ip: ip}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, 80), opts.timeout)
	if err == nil {
		conn.Close()
		result.alive = true
		result.rtt = time.Since(start)
		result.method = "tcp-80"
		return result
	}

	if opts.tcpFallback {
		for _, port := range []int{443, 22, 21, 23, 8080} {
			start = time.Now()
			conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), opts.timeout)
			if err == nil {
				conn.Close()
				result.alive = true
				result.rtt = time.Since(start)
				result.method = fmt.Sprintf("tcp-%d", port)
				return result
			}
		}
	}

	return result
}
