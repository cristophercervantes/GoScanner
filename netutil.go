package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func expandTargets(target string) ([]string, error) {
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}
	if strings.Contains(target, "-") {
		parts := strings.SplitN(target, "-", 2)
		if net.ParseIP(parts[0]) != nil && net.ParseIP(parts[1]) != nil {
			return expandIPRange(parts[0], parts[1])
		}
		segments := strings.Split(parts[0], ".")
		if len(segments) == 4 {
			base := strings.Join(segments[:3], ".")
			start, err1 := strconv.Atoi(segments[3])
			end, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range: %s", target)
			}
			if start > end || end > 255 {
				return nil, fmt.Errorf("invalid range: %s", target)
			}
			var ips []string
			for i := start; i <= end; i++ {
				ips = append(ips, fmt.Sprintf("%s.%d", base, i))
			}
			return ips, nil
		}
	}
	if net.ParseIP(target) != nil {
		return []string{target}, nil
	}
	addrs, err := net.LookupHost(target)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %w", target, err)
	}
	return addrs, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func expandIPRange(start, end string) ([]string, error) {
	startIP := net.ParseIP(start).To4()
	endIP := net.ParseIP(end).To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP range: %s - %s", start, end)
	}
	var ips []string
	for ip := cloneIP(startIP); !ip.Equal(endIP); incrementIP(ip) {
		ips = append(ips, ip.String())
		if len(ips) > 65536 {
			return nil, fmt.Errorf("range too large")
		}
	}
	ips = append(ips, endIP.String())
	return ips, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func parsePorts(portStr string) ([]int, error) {
	if portStr == "" {
		return nil, nil
	}
	var ports []int
	seen := make(map[int]bool)
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", bounds[0])
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", bounds[1])
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("port range out of bounds: %s", part)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			if !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	return ports, nil
}
