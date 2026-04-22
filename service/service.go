package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type RunMode uint8

const (
	SimpleRunMode RunMode = iota
	ScanRunMode
)

const reportDir = "/home/ssemchuk/go/src/github.com/correlator/reports/"

type Scanner interface {
	Scan() (string, error)
}

type Service struct {
	DASTScanner DAST
	SASTScanner SAST
}

func New() *Service {
	return &Service{}
}

func (s *Service) Run(
	mode RunMode,
	sastRep, dastRep *string,
	srcPath, hostport *string,
) error {
	var (
		sastReport string
		dastReport string
	)

	switch mode {
	case SimpleRunMode:
		if sastRep == nil || dastRep == nil {
			return errors.New("path to reports not provided")
		}

		sastReport = *sastRep
		dastReport = *dastRep

	case ScanRunMode:
		if srcPath == nil || hostport == nil {
			return errors.New("hostport and/or src path not provided")
		}

		var err error

		sastReport, err = s.SASTScanner.Scan(*srcPath)
		if err != nil {
			return err
		}

		dastReport, err = s.DASTScanner.Scan(*hostport)
		if err != nil {
			return err
		}
	}

	return s.Report(sastReport, dastReport)
}

func (s *Service) Report(sastReport string, dastReport string) error {
	sastFile, err := os.ReadFile(sastReport)
	if err != nil {
		return err
	}

	dastFile, err := os.ReadFile(dastReport)
	if err != nil {
		return err
	}

	var dastData SarifLog
	if err := json.Unmarshal(dastFile, &dastData); err != nil {
		return err
	}

	var sastData SarifLog
	if err := json.Unmarshal(sastFile, &sastData); err != nil {
		return err
	}

	s.SimpleReport(&sastData, &dastData)

	corFinding := s.Correlate(&sastData, &dastData)

	fmt.Println("Подтверждённые находки:")
	for _, cf := range corFinding {
		if cf.CombinedScore > 0.5 {
			println("")
			fmt.Println("Правило в SAST ", cf.SASTResult.RuleID)
			fmt.Println("Пояснение в DAST ", cf.DASTResult.Message.Text)
		}
	}

	return nil
}

func (s *Service) SimpleReport(sast *SarifLog, dast *SarifLog) {
	fmt.Println("=== Простой отчёт ===")
	fmt.Printf("SAST находки : %d\n", CountFindings(sast))
	fmt.Printf("DAST находки : %d\n", CountFindings(dast))
}

// // printResultSample – человекочитаемый вывод одного результата.
func printResultSample(r SarifResult) {
	fmt.Printf("- RuleID   : %s\n", r.RuleID)
	fmt.Printf("- Level    : %s\n", r.Level)
	fmt.Printf("- Message  : %s\n", r.Message.Text)

	if len(r.Locations) > 0 {
		loc := r.Locations[0].PhysicalLocation
		fmt.Printf("- File     : %s\n", normalizePath(loc.ArtifactLocation.URI))
		if loc.Region != nil && loc.Region.StartLine != nil {
			fmt.Printf("- Line     : %d\n", *loc.Region.StartLine)
		}
	}
}

// CorrelatedFinding – объединённый результат после «связывания» SAST и DAST.
type CorrelatedFinding struct {
	RuleID        string       `json:"ruleId"`
	SASTResult    *SarifResult `json:"sast,omitempty"`
	DASTResult    *SarifResult `json:"dast,omitempty"`
	CombinedScore float64      `json:"combinedScore,omitempty"` // место для будущих формул
}

func mapSemgrepToZap(semgrepID string) string {
	idSpl := strings.Split(semgrepID, ".")
	key := idSpl[len(idSpl)-1]

	if zapID, ok := VulnDB[key]; ok {
		return zapID
	}
	return ""
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "http://")
	p = strings.TrimPrefix(p, "https://")
	p = strings.TrimPrefix(p, "file://")
	p = strings.TrimPrefix(p, "%SRCROOT%")
	p = strings.TrimSuffix(p, "/")
	return strings.ToLower(p)
}

func (s *Service) Correlate(sast, dast *SarifLog) []CorrelatedFinding {
	dastIdx := make(map[string]*SarifResult)
	for _, run := range dast.Runs {
		for i := range run.Results {
			r := &run.Results[i]

			path := ""
			if len(r.Locations) > 0 {
				path = normalizePath(r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
			}

			path = ExtractPath(path)

			key := fmt.Sprintf("%s|%s", r.RuleID, path)
			dastIdx[key] = r
		}
	}

	var out []CorrelatedFinding
	usedDAST := make(map[string]bool)

	// Проходим по SAST‑результатам
	for _, run := range sast.Runs {
		for i := range run.Results {
			r := &run.Results[i]

			snippetText := ""
			if len(r.Locations) > 0 {
				region := r.Locations[0].PhysicalLocation.Region
				if region != nil && region.Snippet != nil &&
					region.Snippet.Text != nil {
					snippetText = *region.Snippet.Text
				}
			}

			zapRuleID := mapSemgrepToZap(r.RuleID)
			if zapRuleID == "" {
				continue
			}

			cf := CorrelatedFinding{
				RuleID:     r.RuleID, // оригинальный Semgrep‑RuleID (для вывода)
				SASTResult: r,
			}

			for key, val := range dastIdx {
				keySpl := strings.Split(key, "|")

				if keySpl[0] == zapRuleID &&
					strings.Contains(snippetText, keySpl[1]) {
					cf.DASTResult = val
					usedDAST[key] = true
					cf.CombinedScore = 1.0 // 100 % уверены, что это одна уязвимость
				}
			}

			out = append(out, cf)
		}
	}

	for key, dr := range dastIdx {
		if usedDAST[key] {
			continue // уже использован в паре выше
		}
		cf := CorrelatedFinding{
			RuleID:        dr.RuleID,
			DASTResult:    dr,
			CombinedScore: 0.5, // найдено только в DAST
		}
		out = append(out, cf)
	}
	return out
}

func WriteJSON(v any, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("cannot encode JSON: %w", err)
	}
	return nil
}

func CountFindings(l *SarifLog) int {
	cnt := 0
	for _, r := range l.Runs {
		cnt += len(r.Results)
	}
	return cnt
}

func ExtractPath(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	return strings.TrimPrefix(u.Path, "/")
}
