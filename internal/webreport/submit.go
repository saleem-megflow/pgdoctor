// Package webreport submits a completed audit to pgdoctor-api so it can
// be viewed as a page, not just read from the terminal. If this fails
// (offline, firewall), the CLI still prints its terminal report — a web
// view is a bonus, never a requirement for the audit to be useful.
package webreport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/saleem-megflow/pgdoctor/internal/report"
)

const defaultEndpoint = "https://pgdoctor-api.megflow.com/reports"

type finding struct {
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Headline string   `json:"headline"`
	Metrics  []string `json:"metrics,omitempty"`
	Action   string   `json:"action,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

type submission struct {
	Email           string    `json:"email"`
	Company         string    `json:"company"`
	PostgresVersion string    `json:"postgres_version"`
	Score           int       `json:"score"`
	RiskBand        string    `json:"risk_band"`
	Findings        []finding `json:"findings"`
}

// Submit posts r to pgdoctor-api and returns the shareable URL.
func Submit(email, company string, r *report.Report) (string, error) {
	sub := submission{
		Email:           email,
		Company:         company,
		PostgresVersion: r.PostgresVersion,
		Score:           r.Score(),
		RiskBand:        r.RiskBand(),
	}
	for _, f := range r.Findings {
		metrics := make([]string, 0, len(f.Metrics))
		for _, m := range f.Metrics {
			metrics = append(metrics, m.Value)
		}
		sub.Findings = append(sub.Findings, finding{
			Category: string(f.Category),
			Severity: f.Severity.String(),
			Headline: f.Headline,
			Metrics:  metrics,
			Action:   f.Action,
			Detail:   f.Detail,
		})
	}

	body, err := json.Marshal(sub)
	if err != nil {
		return "", err
	}

	endpoint := os.Getenv("PGDOCTOR_REPORTS_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("reports endpoint returned %d", resp.StatusCode)
	}

	var out struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.URL, nil
}
