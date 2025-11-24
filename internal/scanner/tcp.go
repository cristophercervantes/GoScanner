package scanner

import (
    "fmt"
    "net"
    "sync"
    "sync/atomic"
    "time"

    "github.com/cristophercervantes/GoScanner/internal/fingerprint"
    "github.com/cristophercervantes/GoScanner/pkg/network"
    "github.com/cristophercervantes/GoScanner/pkg/types"
)

type TCPScanner struct {
    config types.ScanConfig
}

func NewTCPScanner(config types.ScanConfig) *TCPScanner {
    return &TCPScanner{
        config: config,
    }
}

func (t *TCPScanner) Scan() ([]types.ScanResult, error) {
    fmt.Printf("Starting TCP connect scan...\n")
    startTime := time.Now()

    ports, err := network.ParsePortRange(t.config.Ports)
    if err != nil {
        return nil, fmt.Errorf("failed to parse ports: %v", err)
    }

    if len(ports) == 0 {
        return nil, fmt.Errorf("no valid ports to scan")
    }

    fmt.Printf("Scanning %s, %d ports...\n", t.config.Target, len(ports))

    var results []types.ScanResult
    var mutex sync.Mutex
    var wg sync.WaitGroup

    var scanned int32
    var openPorts int32
    totalPorts := len(ports)

    semaphore := make(chan struct{}, t.config.Threads)
    progressTicker := time.NewTicker(1 * time.Second)
    defer progressTicker.Stop()

    go func() {
        for range progressTicker.C {
            currentScanned := atomic.LoadInt32(&scanned)
            currentOpen := atomic.LoadInt32(&openPorts)
            percent := float32(currentScanned) / float32(totalPorts) * 100
            fmt.Printf("\rProgress: %d/%d (%.1f%%) - Open: %d", currentScanned, totalPorts, percent, currentOpen)
        }
    }()

    for _, port := range ports {
        wg.Add(1)
        semaphore <- struct{}{}

        go func(p int) {
            defer wg.Done()
            defer func() { <-semaphore }()

            result := t.scanPort(t.config.Target, p)
            atomic.AddInt32(&scanned, 1)

            if result.State == "open" {
                atomic.AddInt32(&openPorts, 1)
            }

            mutex.Lock()
            results = append(results, result)
            mutex.Unlock()
        }(port)
    }

    wg.Wait()
    progressTicker.Stop()

    duration := time.Since(startTime)
    fmt.Printf("\nScan completed in %v\n", duration)

    return results, nil
}

func (t *TCPScanner) scanPort(host string, port int) types.ScanResult {
    address := network.FormatAddress(host, port)
    
    conn, err := net.DialTimeout("tcp", address, t.config.Timeout)
    if err != nil {
        return types.ScanResult{
            Host:      host,
            Port:      port,
            State:     "closed",
            Timestamp: time.Now(),
        }
    }
    defer conn.Close()

    fingerprinter := fingerprint.NewServiceFingerprinter(2 * time.Second)
    return fingerprinter.Fingerprint(host, port)
}
