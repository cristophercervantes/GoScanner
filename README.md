<div align="center">

```
  ____       ____                                 
 / ___| ___ / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |  _ / _ \ \___ \/ __/ _` | '_ \| '_ \ / _ \ '__|
| |_| | (_) |____) | (_| (_| | | | | | | |  __/ |   
 \____|\___/|______/\___\__,_|_| |_|_| |_|\___|_|   
```

**GoScanner v2.0** — Fast network port scanner written in Go

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Version](https://img.shields.io/badge/version-v2.0-brightgreen?style=flat)](https://github.com/cristophercervantes/GoScanner/releases/tag/v2.0)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat)](#download-binaries)

*By [Tensor Security Academy](https://tensorsecurityacademy.com)*

</div>

---

GoScanner is a concurrent TCP port scanner built as a lightweight alternative to Nmap. Version 2.0 is a full rewrite of v1 — faster, more reliable, with service banner detection, structured JSON output, and a built-in self-updater.

## Download Binaries

No Go installation required. Grab the binary for your platform from the [Releases page](https://github.com/cristophercervantes/GoScanner/releases/tag/v2.0).

| Platform | Architecture | File |
|----------|-------------|------|
| Linux | 64-bit (x86) | `goscanner_linux_amd64` |
| Linux | ARM 64-bit | `goscanner_linux_arm64` |
| Windows | 64-bit (x86) | `goscanner_windows_amd64.exe` |
| Windows | ARM 64-bit | `goscanner_windows_arm64.exe` |
| macOS | Intel | `goscanner_darwin_amd64` |
| macOS | Apple Silicon (M1/M2/M3) | `goscanner_darwin_arm64` |

**Linux / macOS — make it executable after download:**

```bash
chmod +x goscanner_linux_amd64
./goscanner_linux_amd64 -target 192.168.1.1
```

**Windows — run directly from PowerShell or CMD:**

```powershell
.\goscanner_windows_amd64.exe -target 192.168.1.1
```

## Install

**Option 1 — go install (recommended if you have Go):**

```bash
go install github.com/cristophercervantes/GoScanner/cmd/goscanner@latest
```

**Option 2 — install script (Linux / macOS):**

```bash
curl -fsSL https://raw.githubusercontent.com/cristophercervantes/GoScanner/main/install.sh | bash
```

The script detects your OS and architecture, then installs the right binary to `/usr/local/bin`. If Go is available it uses `go install` instead.

**Option 3 — build from source:**

```bash
git clone https://github.com/cristophercervantes/GoScanner.git
cd GoScanner
go build -o goscanner ./cmd/goscanner
```

## Updating from v1

If you installed v1 with `go install`, just run:

```bash
goscanner -update
```

This checks GitHub for the latest release, then updates automatically — using `go install` if Go is available, or downloading the matching binary otherwise. You can also check for updates without installing:

```bash
goscanner -check-update
```

## Usage

```bash
# Scan a single host (uses 18 common ports by default)
goscanner -target 192.168.1.1

# Scan a subnet
goscanner -target 192.168.1.0/24

# Scan specific ports
goscanner -target 192.168.1.1 -ports 22,80,443,8080

# Scan a port range
goscanner -target 192.168.1.1 -ports 1-1000

# Discover live hosts only — no port scan
goscanner -target 192.168.1.0/24 -ping-only

# Skip host discovery and scan all targets directly
goscanner -target 192.168.1.0/24 -skip-discovery -ports 80,443

# Output as JSON
goscanner -target 192.168.1.1 -output json

# Save results to a file
goscanner -target 192.168.1.0/24 -save results.json

# List all expanded targets without scanning
goscanner -list-targets 192.168.1.0/24

# Tune speed — more workers, shorter timeout
goscanner -target 192.168.1.1 -workers 1000 -timeout 1000
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | required | IP, hostname, CIDR, or range |
| `-ports` | 18 common ports | Comma-separated ports or ranges (e.g. `80,443` or `1-1000`) |
| `-workers` | `500` | Number of concurrent scan workers |
| `-timeout` | `2000` | Connection timeout in milliseconds |
| `-ping-only` | `false` | Discover live hosts, skip port scanning |
| `-skip-discovery` | `false` | Skip host discovery, scan all targets directly |
| `-banners` | `true` | Grab service banners from open ports |
| `-output` | `text` | Output format: `text` or `json` |
| `-save` | — | Save results to a JSON file |
| `-list-targets` | `false` | Print expanded target list without scanning |
| `-no-progress` | `false` | Disable the progress bar |
| `-version` | — | Print version and platform info |
| `-update` | — | Update GoScanner to the latest release |
| `-check-update` | — | Check if a newer version is available |

## Supported Target Formats

| Format | Example |
|--------|---------|
| Single IP | `192.168.1.1` |
| Hostname | `example.com` |
| CIDR | `192.168.1.0/24` |
| Full IP range | `192.168.1.1-192.168.1.50` |
| Short range | `192.168.1.1-50` |

## JSON Output

Use `-output json` or `-save file.json` to get structured output — useful for piping into other tools or logging.

```json
{
  "version": "v2.0",
  "started_at": "2025-11-25T10:30:00Z",
  "target": "192.168.1.0/24",
  "duration": "4.2s",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "ports": [
        {
          "port": 22,
          "state": "open",
          "service": "ssh",
          "banner": "SSH-2.0-OpenSSH_8.9p1"
        },
        {
          "port": 80,
          "state": "open",
          "service": "http",
          "banner": "HTTP/1.1 200 OK"
        }
      ]
    }
  ]
}
```

## Default Ports

When no `-ports` flag is provided, GoScanner checks these 18 common ports:

`21` `22` `23` `25` `53` `80` `110` `143` `443` `445` `3306` `3389` `5432` `5900` `6379` `8080` `8443` `27017`

## Project Structure

```
GoScanner/
├── cmd/
│   └── goscanner/
│       └── main.go          # Entry point, CLI flags
├── internal/
│   ├── scanner/
│   │   └── scanner.go       # Port scanning, banner grabbing
│   ├── discovery/
│   │   └── discovery.go     # Host discovery, TCP probing
│   ├── output/
│   │   └── output.go        # Text and JSON formatters
│   └── updater/
│       └── updater.go       # Self-update logic
├── pkg/
│   └── netutil/
│       └── netutil.go       # Target parsing, CIDR/range expansion
├── install.sh               # Universal install script
└── go.mod
```

## Building Your Own Binaries

```bash
# Linux 64-bit
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o goscanner_linux_amd64 ./cmd/goscanner

# Linux ARM
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o goscanner_linux_arm64 ./cmd/goscanner

# Windows 64-bit
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o goscanner_windows_amd64.exe ./cmd/goscanner

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o goscanner_darwin_amd64 ./cmd/goscanner

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o goscanner_darwin_arm64 ./cmd/goscanner
```

The `-ldflags="-s -w"` flag strips debug symbols, keeping binaries around 5MB.

## What Changed in v2

**Bugs fixed from v1:**
- Panic on invalid port input now returns a clear error instead of crashing
- Race conditions in goroutine results collection — fixed with proper channel synchronization
- CIDR expansion was including network and broadcast addresses
- Host discovery failing silently — now falls back through 6 common TCP ports
- Duplicate ports in `-ports` input were accepted and scanned twice

**New in v2:**
- Service banner grabbing — reads first response line from open ports
- Service name detection for 18 well-known ports
- JSON output mode (`-output json`) and file export (`-save`)
- Live progress bar during scans
- `-update` command — self-updates via GitHub Releases
- `-check-update` command — non-destructive version check
- Install script (`install.sh`) for users without Go
- Port results sorted by port number
- Duplicate port deduplication in port list parsing

## Versioning

GoScanner follows a 15-version release roadmap. Each version adds meaningful capabilities. See [Releases](https://github.com/cristophercervantes/GoScanner/releases) for the changelog.

| Version | Status |
|---------|--------|
| v1.0 | Released |
| v2.0 | Released (current) |
| v3.0 — v15.0 | Upcoming |

## Legal

Only scan networks and systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

## Contact

**Tensor Security Academy**
tensorsecurityacademy.com
tensorsecurityacademy@gmail.com

## License

MIT License — see [LICENSE](LICENSE) for details.
