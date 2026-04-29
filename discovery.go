package discovery

import (
        "fmt"
        "net"
        "sync"
        "time"
)

type HostResult struct {
        IP     string
        Alive  bool
        RTT    time.Duration
        Method string
}

type Options struct {
        Timeout     time.Duration
        Workers     int
        TCPFallback bool
        FallbackPort int
}

func DefaultOptions() Options {
        return Options{
                Timeout:      1 * time.Second,
                Workers:      256,
                TCPFallback:  true,
                FallbackPort: 80,
        }
}

func DiscoverHosts(targets []string, opts Options) []HostResult {
        jobs := make(chan string, len(targets))
        results := make(chan HostResult, len(targets))

        var wg sync.WaitGroup
        for i := 0; i < opts.Workers; i++ {
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

        var alive []HostResult
        for r := range results {
                if r.Alive {
                        alive = append(alive, r)
                }
        }
        return alive
}

func probeHost(ip string, opts Options) HostResult {
        result := HostResult{IP: ip}

        start := time.Now()
        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, 80), opts.Timeout)
        if err == nil {
                conn.Close()
                result.Alive = true
                result.RTT = time.Since(start)
                result.Method = "tcp-80"
                return result
        }

        if opts.TCPFallback {
                for _, port := range []int{443, 22, 21, 23, 8080} {
                        start = time.Now()
                        conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), opts.Timeout)
                        if err == nil {
                                conn.Close()
                                result.Alive = true
                                result.RTT = time.Since(start)
                                result.Method = fmt.Sprintf("tcp-%d", port)
                                return result
                        }
                }
        }

        return result
}

func GetMACAddress(ip string) string {
        ifaces, err := net.Interfaces()
        if err != nil {
                return ""
        }
        for _, iface := range ifaces {
                addrs, err := iface.Addrs()
                if err != nil {
                        continue
                }
                for _, addr := range addrs {
                        var localIP net.IP
                        switch v := addr.(type) {
                        case *net.IPNet:
                                localIP = v.IP
                        case *net.IPAddr:
                                localIP = v.IP
                        }
                        if localIP != nil && localIP.String() == ip {
                                return iface.HardwareAddr.String()
                        }
                }
        }
        return ""
}
