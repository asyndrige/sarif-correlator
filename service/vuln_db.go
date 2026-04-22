package service

// semgrep rule - zap rule
var VulnDB = map[string]string{
	"tainted-sql-string":         "40018",
	"avoid-raw-sql":              "40018",
	"django-secure-set-cookie":   "10010",
	"no-csrf-exempt":             "10202",
	"direct-use-of-httpresponse": "10020",
	"subprocess-injection":       "10038",
	"user-eval":                  "10038",
}
