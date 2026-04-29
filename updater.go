package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	currentVersion = "v2.0"
	releaseAPI     = "https://api.github.com/repos/cristophercervantes/GoScanner/releases/latest"
	modulePath     = "github.com/cristophercervantes/GoScanner"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

func checkForUpdate() (*githubRelease, bool, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(releaseAPI)
	if err != nil {
		return nil, false, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, false, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, false, fmt.Errorf("failed to parse release info: %w", err)
	}

	newer := release.TagName != currentVersion
	return &release, newer, nil
}

func updateViaGoInstall() error {
	fmt.Println("Updating via go install...")
	cmd := exec.Command("go", "install", modulePath+"@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install failed: %w", err)
	}
	fmt.Println("Update complete. Restart goscanner to use the new version.")
	return nil
}

func updateViaBinary(release *githubRelease) error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	assetName := fmt.Sprintf("goscanner_%s_%s", goos, goarch)
	if goos == "windows" {
		assetName += ".exe"
	}

	downloadURL := fmt.Sprintf(
		"https://github.com/cristophercervantes/GoScanner/releases/download/%s/%s",
		release.TagName,
		assetName,
	)

	fmt.Printf("Downloading %s...\n", assetName)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("no binary found for %s/%s — try: go install %s@latest", goos, goarch, modulePath)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find current binary: %w", err)
	}

	tmpPath := execPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("cannot write temp file: %w", err)
	}

	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write failed: %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace failed: %w", err)
	}

	fmt.Println("Update complete. Restart goscanner to use the new version.")
	return nil
}

func printVersionInfo() {
	fmt.Printf("GoScanner %s\n", currentVersion)
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Go module: %s\n", modulePath)
}

func isGoAvailable() bool {
	_, err := exec.LookPath("go")
	return err == nil
}

func parseVersionNumber(v string) int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	total := 0
	mult := 1000000
	for _, p := range parts {
		n := 0
		fmt.Sscanf(p, "%d", &n)
		total += n * mult
		mult /= 1000
	}
	return total
}
