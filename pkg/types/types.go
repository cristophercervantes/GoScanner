package types

import "time"

type ScanConfig struct {

	ListScan      bool
	PingOnly      bool
	SkipDiscovery bool
	
	
	TCPSynPorts    string
	TCPAckPorts    string  
	UDPPorts       string
	SCTPPorts      string
	
	
	ICMPEcho      bool
	ICMPTimestamp bool
	ICMPNetmask   bool
	
	
	IpProtocolPing string
	
	
	NoDNS       bool
	AlwaysDNS   bool
	DNSServers  string
	SystemDNS   bool
	Traceroute  bool
	
	
	InputFile string
	Target    string
	

	Ports        string
	ScanType     string
	Timeout      time.Duration
	Threads      int
	OutputFormat string
	Verbose      bool
}

type ScanResult struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	State     string    `json:"state"`
	Service   string    `json:"service"`
	Version   string    `json:"version,omitempty"`
	Banner    string    `json:"banner,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type HostInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	MAC      string `json:"mac,omitempty"`
	Status   string `json:"status"`
}
