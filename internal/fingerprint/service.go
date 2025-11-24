package fingerprint

import (
    "bufio"
    "fmt"
    "net"
    "strings"
    "time"

    "github.com/cristophercervantes/GoScanner/pkg/types"
)

type ServiceFingerprinter struct {
    timeout time.Duration
}

func NewServiceFingerprinter(timeout time.Duration) *ServiceFingerprinter {
    return &ServiceFingerprinter{
        timeout: timeout,
    }
}

func (s *ServiceFingerprinter) Fingerprint(host string, port int) types.ScanResult {
    result := types.ScanResult{
        Host:      host,
        Port:      port,
        State:     "closed",
        Service:   "unknown",
        Timestamp: time.Now(),
    }

    address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
    conn, err := net.DialTimeout("tcp", address, s.timeout)
    if err != nil {
        return result
    }
    defer conn.Close()

    result.State = "open"

    switch port {
    case 22:
        result = s.fingerprintSSH(conn, result)
    case 80, 443, 8080, 8443:
        result = s.fingerprintHTTP(conn, result, port)
    case 21:
        result = s.fingerprintFTP(conn, result)
    case 25, 587:
        result = s.fingerprintSMTP(conn, result)
    default:
        result = s.grabGenericBanner(conn, result)
    }

    if result.Service == "unknown" {
        result.Service = s.guessServiceFromPort(port)
    }

    return result
}

func (s *ServiceFingerprinter) fingerprintSSH(conn net.Conn, result types.ScanResult) types.ScanResult {
    conn.SetReadDeadline(time.Now().Add(s.timeout))
    
    reader := bufio.NewReader(conn)
    banner, err := reader.ReadString('\n')
    if err != nil {
        return result
    }

    result.Banner = strings.TrimSpace(banner)
    result.Service = "ssh"

    if strings.Contains(banner, "SSH-2.0") {
        result.Version = "2.0"
    }

    return result
}

func (s *ServiceFingerprinter) fingerprintHTTP(conn net.Conn, result types.ScanResult, port int) types.ScanResult {
    protocol := "http"
    if port == 443 || port == 8443 {
        protocol = "https"
    }

    request := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: GoScan/1.0\r\n\r\n", result.Host)
    conn.SetWriteDeadline(time.Now().Add(s.timeout))
    conn.Write([]byte(request))

    conn.SetReadDeadline(time.Now().Add(s.timeout))
    reader := bufio.NewReader(conn)
    
    var response strings.Builder
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            break
        }
        response.WriteString(line)
        if strings.TrimSpace(line) == "" {
            break
        }
    }

    result.Banner = response.String()
    result.Service = protocol

    lines := strings.Split(result.Banner, "\n")
    for _, line := range lines {
        if strings.HasPrefix(strings.ToLower(line), "server:") {
            result.Version = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
            break
        }
    }

    return result
}

func (s *ServiceFingerprinter) fingerprintFTP(conn net.Conn, result types.ScanResult) types.ScanResult {
    conn.SetReadDeadline(time.Now().Add(s.timeout))
    
    reader := bufio.NewReader(conn)
    banner, err := reader.ReadString('\n')
    if err != nil {
        return result
    }

    result.Banner = strings.TrimSpace(banner)
    result.Service = "ftp"
    return result
}

func (s *ServiceFingerprinter) fingerprintSMTP(conn net.Conn, result types.ScanResult) types.ScanResult {
    conn.SetReadDeadline(time.Now().Add(s.timeout))
    
    reader := bufio.NewReader(conn)
    banner, err := reader.ReadString('\n')
    if err != nil {
        return result
    }

    result.Banner = strings.TrimSpace(banner)
    result.Service = "smtp"
    return result
}

func (s *ServiceFingerprinter) grabGenericBanner(conn net.Conn, result types.ScanResult) types.ScanResult {
    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    
    buffer := make([]byte, 1024)
    n, err := conn.Read(buffer)
    if err != nil {
        return result
    }

    result.Banner = string(buffer[:n])
    return result
}

func (s *ServiceFingerprinter) guessServiceFromPort(port int) string {
    serviceMap := map[int]string{
        21:    "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80:    "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
        995:   "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
        3389:  "rdp", 5432: "postgresql", 6379: "redis", 27017: "mongodb",
    }

    if service, exists := serviceMap[port]; exists {
        return service
    }
    return "unknown"
}
