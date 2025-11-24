package discovery

import (
	"fmt"
	"net"

	"github.com/cristophercervantes/GoScanner/pkg/network"
	"github.com/cristophercervantes/GoScanner/pkg/types"
)

type Discovery struct {
	config types.ScanConfig
}

func NewDiscovery(config types.ScanConfig) *Discovery {
	return &Discovery{
		config: config,
	}
}

func (d *Discovery) DiscoverHosts(targets []string) ([]types.HostInfo, error) {
	fmt.Printf("Starting host discovery with %d targets\n", len(targets))
	
	var allActiveHosts []types.HostInfo
	
	for _, target := range targets {
		fmt.Printf("Scanning: %s\n", target)
		activeHosts, err := d.scanTarget(target)
		if err != nil {
			fmt.Printf("Warning: Failed to scan %s: %s\n", target, err)
			continue
		}
		allActiveHosts = append(allActiveHosts, activeHosts...)
	}
	
	return allActiveHosts, nil
}

func (d *Discovery) scanTarget(target string) ([]types.HostInfo, error) {
	var ips []string
	
	if network.IsCIDR(target) {
		expandedIPs, err := network.ExpandCIDR(target)
		if err != nil {
			return nil, err
		}
		ips = expandedIPs
	} else if network.IsIPRange(target) {
		expandedIPs, err := network.ParseIPRange(target)
		if err != nil {
			return nil, err
		}
		ips = expandedIPs
	} else if ip := net.ParseIP(target); ip != nil {
		ips = []string{target}
	} else {
		// Hostname - resolve it
		resolvedIPs, err := network.ResolveHost(target)
		if err != nil {
			return nil, err
		}
		ips = resolvedIPs
	}
	
	
	if len(ips) > 1024 {
		ips = ips[:1024]
		fmt.Printf("Limited to first 1024 hosts\n")
	}
	
	var activeHosts []types.HostInfo
	activeCount := 0
	
	for i, ip := range ips {
		if d.isHostActive(ip) {
		
			mac := ""
			if d.isLocalNetworkIP(ip) {
				mac = network.GetMACAddress(ip)
			}
			
			hostInfo := types.HostInfo{
				IP:     ip,
				Status: "UP",
				MAC:    mac,
			}
			activeHosts = append(activeHosts, hostInfo)
			activeCount++
		}
		
		
		if (i+1)%50 == 0 {
			fmt.Printf("Scanned %d/%d hosts, found %d active\n", i+1, len(ips), activeCount)
		}
	}
	
	return activeHosts, nil
}

func (d *Discovery) isHostActive(host string) bool {
	
	if d.config.TCPSynPorts != "" {
		if d.tcpSynPing(host, d.config.TCPSynPorts) {
			return true
		}
	}
	
	
	if d.config.TCPAckPorts != "" {
		if d.tcpAckPing(host, d.config.TCPAckPorts) {
			return true
		}
	}
	

	if d.config.UDPPorts != "" {
		if d.udpPing(host, d.config.UDPPorts) {
			return true
		}
	}
	
	
	if d.config.SCTPPorts != "" {
		if d.sctpPing(host, d.config.SCTPPorts) {
			return true
		}
	}
	
	
	if d.config.ICMPEcho {
		if d.icmpEchoPing(host) {
			return true
		}
	}
	

	if d.config.ICMPTimestamp {
		if d.icmpTimestampPing(host) {
			return true
		}
	}
	

	if d.config.ICMPNetmask {
		if d.icmpNetmaskPing(host) {
			return true
		}
	}
	

	if d.config.IpProtocolPing != "" {
		if d.ipProtocolPing(host) {
			return true
		}
	}
	

	if d.isLocalNetworkIP(host) {
		if d.arpPing(host) {
			return true
		}
	}
	

	if d.config.PingOnly && d.config.TCPSynPorts == "" && d.config.TCPAckPorts == "" && 
	   d.config.UDPPorts == "" && d.config.SCTPPorts == "" && 
	   !d.config.ICMPEcho && !d.config.ICMPTimestamp && !d.config.ICMPNetmask && 
	   d.config.IpProtocolPing == "" {
		return d.tcpSynPing(host, "80,443,22")
	}
	
	return false
}

func (d *Discovery) isLocalNetworkIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	

	if ip.To4() != nil {
	
		return ip[0] == 10 ||
			(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
			(ip[0] == 192 && ip[1] == 168) ||
			(ip[0] == 169 && ip[1] == 254) || 
			(ip[0] == 127) 
	}
	
	return false
}

func (d *Discovery) tcpSynPing(host, portsStr string) bool {
	ports, err := network.ParsePortList(portsStr)
	if err != nil {
		return false
	}
	
	for _, port := range ports {
		address := network.FormatAddress(host, port)
		conn, err := net.DialTimeout("tcp", address, d.config.Timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func (d *Discovery) tcpAckPing(host, portsStr string) bool {
	
	
	return d.tcpSynPing(host, portsStr)
}

func (d *Discovery) tcpConnectPing(host, portsStr string) bool {
	ports, err := network.ParsePortList(portsStr)
	if err != nil {
		return false
	}
	
	for _, port := range ports {
		address := network.FormatAddress(host, port)
		conn, err := net.DialTimeout("tcp", address, d.config.Timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func (d *Discovery) udpPing(host, portsStr string) bool {
	ports, err := network.ParsePortList(portsStr)
	if err != nil {
		return false
	}
	
	for _, port := range ports {
		address := network.FormatAddress(host, port)
		conn, err := net.DialTimeout("udp", address, d.config.Timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func (d *Discovery) sctpPing(host, portsStr string) bool {


	return d.tcpSynPing(host, portsStr)
}

func (d *Discovery) icmpEchoPing(host string) bool {


	return d.tcpSynPing(host, "80")
}

func (d *Discovery) icmpTimestampPing(host string) bool {


	return d.tcpSynPing(host, "80")
}

func (d *Discovery) icmpNetmaskPing(host string) bool {

	
	return d.tcpSynPing(host, "80")
}

func (d *Discovery) ipProtocolPing(host string) bool {
	

	return d.tcpSynPing(host, "80")
}

func (d *Discovery) arpPing(host string) bool {

	mac := d.getMACViaARP(host)
	return mac != ""
}

func (d *Discovery) getMACViaARP(host string) string {
	
	return network.GetMACAddress(host)
}
