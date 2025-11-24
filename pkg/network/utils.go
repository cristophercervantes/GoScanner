package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)


func ParsePortRange(portRange string) ([]int, error) {
	var ports []int

	if portRange == "" {
		return ports, nil
	}

	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}

			if start > end {
				return nil, fmt.Errorf("start port cannot be greater than end port: %s", part)
			}

			for port := start; port <= end; port++ {
				if IsValidPort(port) {
					ports = append(ports, port)
				}
			}
		} else {
			
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if IsValidPort(port) {
				ports = append(ports, port)
			}
		}
	}

	return ports, nil
}


func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}


func ResolveHost(host string) ([]string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	return ipStrings, nil
}


func ValidateTarget(target string) bool {
	if target == "" {
		return false
	}

	
	if ip := net.ParseIP(target); ip != nil {
		return true
	}

	
	if IsCIDR(target) {
		return true
	}


	if IsIPRange(target) {
		return true
	}


	if len(target) > 0 && len(target) < 253 {
		return true
	}

	return false
}


func FormatAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}


func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	

	currentIP := make(net.IP, len(ip))
	copy(currentIP, ip)
	currentIP = currentIP.Mask(ipnet.Mask)
	

	for ipnet.Contains(currentIP) {
		ips = append(ips, currentIP.String())
		
	
		inc(currentIP)
		
		
		if len(ips) > 65536 {
			break
		}
	}


	if len(ips) > 2 && ip.To4() != nil {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}


func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}


func IsCIDR(target string) bool {
	_, _, err := net.ParseCIDR(target)
	return err == nil
}


func GetIPVersion(ipStr string) int {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}


func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}


	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 169 && ip4[1] == 254) || // Link-local
			ip4[0] == 127 // Localhost
	}


	if ip[0] == 0xfd {
		return true
	}

	return false
}


func NormalizeTarget(target string) ([]string, error) {
	
	if IsCIDR(target) {
		return ExpandCIDR(target)
	}


	if IsIPRange(target) {
		return ParseIPRange(target)
	}


	if ip := net.ParseIP(target); ip != nil {
		return []string{target}, nil
	}

	
	return ResolveHost(target)
}


func ParseIPRange(ipRange string) ([]string, error) {
	if !strings.Contains(ipRange, "-") {
		return []string{ipRange}, nil
	}

	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format: %s", ipRange)
	}

	baseIP := net.ParseIP(parts[0])
	if baseIP == nil {
		return nil, fmt.Errorf("invalid base IP: %s", parts[0])
	}


	endIP := net.ParseIP(parts[1])
	if endIP != nil {
		return expandIPRange(baseIP, endIP)
	}


	return expandNumericRange(baseIP, parts[1])
}

func expandIPRange(startIP, endIP net.IP) ([]string, error) {
	var ips []string

	if startIP.To4() == nil || endIP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 ranges supported")
	}

	start := binary.BigEndian.Uint32(startIP.To4())
	end := binary.BigEndian.Uint32(endIP.To4())

	if start > end {
		return nil, fmt.Errorf("start IP cannot be greater than end IP")
	}

	for i := start; i <= end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func expandNumericRange(baseIP net.IP, endStr string) ([]string, error) {
	end, err := strconv.Atoi(endStr)
	if err != nil {
		return nil, fmt.Errorf("invalid end range: %s", endStr)
	}

	ip := baseIP.To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", baseIP)
	}

	base := int(ip[3])
	if end < base {
		return nil, fmt.Errorf("end range cannot be less than base IP")
	}

	var ips []string
	for i := base; i <= end; i++ {
		newIP := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], i)
		ips = append(ips, newIP)
	}

	return ips, nil
}


func ParsePortList(portStr string) ([]int, error) {
	if portStr == "" {
		return []int{}, nil
	}
	return ParsePortRange(portStr)
}


func IsIPRange(target string) bool {
	return strings.Contains(target, "-") && net.ParseIP(strings.Split(target, "-")[0]) != nil
}


func GetMACAddress(ip string) string {

	if !IsPrivateIP(ip) && ip != "127.0.0.1" {
		return ""
	}

	var mac string
	
	switch runtime.GOOS {
	case "linux", "darwin":
		mac = getMACUnix(ip)
		if mac == "" {
			mac = getMACViaPing(ip)
		}
	case "windows":
		mac = getMACWindows(ip)
		if mac == "" {
			mac = getMACViaPing(ip)
		}
	default:
		mac = getMACViaPing(ip)
	}
	
	return mac
}


func getMACViaPing(ip string) string {
	
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), 2*time.Second)
	if err == nil {
		conn.Close()
	}
	
	
	time.Sleep(100 * time.Millisecond)
	

	switch runtime.GOOS {
	case "linux", "darwin":
		return getMACUnix(ip)
	case "windows":
		return getMACWindows(ip)
	default:
		return ""
	}
}

func getMACUnix(ip string) string {

	commands := [][]string{
		{"arp", "-n", ip},
		{"arp", "-a", ip},
		{"arp", ip},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, ip) {
				// Parse different ARP output formats
				mac := parseARPMacAddress(line, ip)
				if mac != "" {
					return mac
				}
			}
		}
	}
	return ""
}

func parseARPMacAddress(line, ip string) string {
	// Remove multiple spaces and split
	fields := strings.Fields(line)
	
	// Look for MAC address pattern in all fields
	for _, field := range fields {
		if isValidMAC(field) {
			return formatMAC(strings.ToUpper(field))
		}
	}
	
	
	if len(fields) >= 3 {
		
	
		if fields[0] == ip && isValidMAC(fields[2]) {
			return formatMAC(strings.ToUpper(fields[2]))
		}
		
		
		if isValidMAC(fields[1]) {
			return formatMAC(strings.ToUpper(fields[1]))
		}
	}
	
	return ""
}

func getMACWindows(ip string) string {

	cmd := exec.Command("arp", "-a", ip)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
		
			fields := strings.Fields(line)
			for _, field := range fields {
				if isValidMAC(field) {
					return formatMAC(strings.ToUpper(field))
				}
			}
		}
	}
	return ""
}

func isValidMAC(mac string) bool {
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	if len(mac) != 12 {
		return false
	}
	_, err := net.ParseMAC(mac)
	return err == nil
}

func formatMAC(mac string) string {
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	if len(mac) != 12 {
		return mac
	}
	

	var formatted strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			formatted.WriteString(":")
		}
		formatted.WriteString(mac[i : i+2])
	}
	return formatted.String()
}
