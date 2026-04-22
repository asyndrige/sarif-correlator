package service

type SarifLog struct {
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SarifRule `json:"rules,omitempty"`
}

type SarifRule struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	ShortDesc  *SarifMessage  `json:"shortDescription,omitempty"`
	FullDesc   *SarifMessage  `json:"fullDescription,omitempty"`
	HelpURI    string         `json:"helpUri,omitempty"`
	Properties map[string]any `json:"properties,omitempty"` // часто сюда кладут CWE, CVSS, severity …
}

type SarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level,omitempty"` // error, warning, note
	Message    SarifMessage    `json:"message"`
	Locations  []SarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"` // любые метаданные сканера
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine   *int `json:"startLine,omitempty"`
	EndLine     *int `json:"endLine,omitempty"`
	StartColumn *int `json:"startColumn,omitempty"`
	EndColumn   *int `json:"endColumn,omitempty"`
	Snippet     *struct {
		Text *string `json:"text,omitempty"`
	} `json:"snippet,omitempty"`
}
