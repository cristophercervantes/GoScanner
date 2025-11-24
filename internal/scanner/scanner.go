package scanner

import (
    "fmt"
    "github.com/cristophercervantes/GoScanner/pkg/types"
)

type Scanner interface {
    Scan() ([]types.ScanResult, error)
}

func CreateScanner(config types.ScanConfig) (Scanner, error) {
    switch config.ScanType {
    case "tcp":
        return NewTCPScanner(config), nil
    case "syn":
        return NewSYNScanner(config), nil
    default:
        return nil, fmt.Errorf("unsupported scan type: %s", config.ScanType)
    }
}
