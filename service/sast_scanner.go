package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type SAST struct{}

func (s *SAST) Scan(target string) (string, error) {
	if target == "" {
		return "", errors.New("SASTScanner: целевой путь не указан")
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("SASTScanner: не удалось превратить путь %q в абсолютный: %w", target, err)
	}

	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", fmt.Errorf("SASTScanner: невозможно создать каталог отчётов: %w", err)
	}
	reportPath := filepath.Join(reportDir,
		fmt.Sprintf("semgrep-%d.sarif", time.Now().UnixNano()))

	// semgrep --sarif --config /home/ssemchuk/project/semgrep-rules/python  --output /home/ssemchuk/go/src/github.com/correlator/reports/semgrep-1774518958026545894.sarif /home/ssemchuk/project/src/pygoat

	args := []string{
		"--sarif",
		"--config", "/home/ssemchuk/project/semgrep-rules/python",
		// "--config", "/home/ssemchuk/project/semgrep-rules/html",
		"--output",
		reportPath,
		absTarget,
	}

	fmt.Println(args)

	bin := "semgrep"

	cmd := exec.Command(bin, args...)
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Start(); err != nil {
		return "", fmt.Errorf("SASTScanner: не удалось стартовать %s: %w", bin, err)
	}
	if err = cmd.Wait(); err != nil {
		return reportPath, fmt.Errorf("SASTScanner: %s завершилось с ошибкой: %w", bin, err)
	}
	return reportPath, nil
}
