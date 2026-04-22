package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type DAST struct {
	port int
}

func (d *DAST) Scan(target string) (string, error) {
	if target == "" {
		return "", errors.New("DASTScanner: target host:port not provided")
	}

	if _, _, err := net.SplitHostPort(target); err != nil {
		return "", fmt.Errorf("DASTScanner: incorrect format target %q: %w", target, err)
	}

	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", fmt.Errorf("DASTScanner: cannot create report dir: %w", err)
	}

	reportPath := filepath.Join(reportDir,
		fmt.Sprintf("nuclei-%d.sarif", time.Now().UnixNano()))

	// docker run --rm --network host -v "$(pwd)/reports":/zap/wrk zaproxy/zap-stable:latest zap-baseline.py -t http://127.0.0.1:8000 -J zap_report3.sarif -reportformat sarif
	args := []string{
		// "-u", target + path,
		// "-t", "/home/ssemchuk/nuclei-templates/",
		// // "-tags", "cve,flask",
		// "-se", reportPath,
		"-cmd",
		"-quickurl", target,
	}

	fmt.Println(args)
	bin := "zaproxy"
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("DASTScanner: cannot start %s: %w", bin, err)
	}
	if err := cmd.Wait(); err != nil {
		return reportPath, fmt.Errorf("DASTScanner: %s finished with error: %w", bin, err)
	}
	return reportPath, nil
}
