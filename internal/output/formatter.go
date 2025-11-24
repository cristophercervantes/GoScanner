package output

import (
    "encoding/csv"
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "time"

    "github.com/cristophercervantes/GoScanner/pkg/types"
)

type Formatter interface {
    Write(results []types.ScanResult) error
}

type TextFormatter struct{}

func NewTextFormatter() *TextFormatter {
    return &TextFormatter{}
}

func (t *TextFormatter) Write(results []types.ScanResult) error {
    openPorts := filterOpenPorts(results)
    
    fmt.Printf("\nScan Results:\n")
    fmt.Printf("=============\n")
    
    for _, result := range openPorts {
        fmt.Printf("PORT: %5d/tcp\tSTATE: %s\tSERVICE: %s\n", 
            result.Port, result.State, result.Service)
    }
    
    if len(openPorts) == 0 {
        fmt.Printf("No open ports found\n")
    } else {
        fmt.Printf("\nSummary: %d open ports found\n", len(openPorts))
    }
    
    return nil
}

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
    return &JSONFormatter{}
}

func (j *JSONFormatter) Write(results []types.ScanResult) error {
    type ScanReport struct {
        Timestamp time.Time          `json:"timestamp"`
        Results   []types.ScanResult `json:"results"`
        Summary   struct {
            TotalPorts int `json:"total_ports"`
            OpenPorts  int `json:"open_ports"`
        } `json:"summary"`
    }
    
    report := ScanReport{
        Timestamp: time.Now(),
        Results:   results,
    }
    report.Summary.TotalPorts = len(results)
    report.Summary.OpenPorts = len(filterOpenPorts(results))
    
    data, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        return err
    }
    
    fmt.Println(string(data))
    return nil
}

type CSVFormatter struct{}

func NewCSVFormatter() *CSVFormatter {
    return &CSVFormatter{}
}

func (c *CSVFormatter) Write(results []types.ScanResult) error {
    writer := csv.NewWriter(os.Stdout)
    
    header := []string{"Host", "Port", "State", "Service", "Timestamp"}
    if err := writer.Write(header); err != nil {
        return err
    }
    
    for _, result := range results {
        record := []string{
            result.Host,
            fmt.Sprintf("%d", result.Port),
            result.State,
            result.Service,
            result.Timestamp.Format(time.RFC3339),
        }
        if err := writer.Write(record); err != nil {
            return err
        }
    }
    
    writer.Flush()
    return writer.Error()
}

type SimpleFormatter struct{}

func NewSimpleFormatter() *SimpleFormatter {
    return &SimpleFormatter{}
}

func (s *SimpleFormatter) Write(results []types.ScanResult) error {
    openPorts := filterOpenPorts(results)
    
    if len(openPorts) == 0 {
        fmt.Println("No open ports found")
        return nil
    }
    
    var ports []string
    for _, result := range openPorts {
        ports = append(ports, fmt.Sprintf("%d/%s", result.Port, result.Service))
    }
    
    fmt.Println(strings.Join(ports, ", "))
    return nil
}

func filterOpenPorts(results []types.ScanResult) []types.ScanResult {
    var open []types.ScanResult
    for _, result := range results {
        if result.State == "open" {
            open = append(open, result)
        }
    }
    return open
}

func CreateFormatter(format string) Formatter {
    switch format {
    case "json":
        return NewJSONFormatter()
    case "csv":
        return NewCSVFormatter()
    case "simple":
        return NewSimpleFormatter()
    default:
        return NewTextFormatter()
    }
}
