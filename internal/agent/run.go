package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/saleem-megflow/titanpostgres/internal/checks"
	"github.com/saleem-megflow/titanpostgres/internal/db"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

const defaultEndpoint = "https://api.titanpostgres.megflow.com/v2/ingest"

type ingestFinding struct {
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Headline string   `json:"headline"`
	Metrics  []string `json:"metrics,omitempty"`
	Action   string   `json:"action,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

type ingestPayload struct {
	Score    int             `json:"score"`
	RiskBand string          `json:"risk_band"`
	Findings []ingestFinding `json:"findings"`
}

// RunOnce executes one collection cycle: connect read-only, run the same
// checks.Run pipeline the one-shot CLI uses, and POST the result to
// titanpostgres-api. Local aggregation (fingerprint+stats, never raw query
// text/rows) already happens inside the checks themselves — this layer
// doesn't add or remove anything from what crosses the network.
func RunOnce(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DSN)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	findings, checkErrs := checks.Run(ctx, pool)
	for _, e := range checkErrs {
		fmt.Println("warning: a check failed:", e)
	}
	r := &report.Report{Findings: findings}

	payload := ingestPayload{Score: r.Score(), RiskBand: r.RiskBand()}
	for _, f := range findings {
		metrics := make([]string, 0, len(f.Metrics))
		for _, m := range f.Metrics {
			metrics = append(metrics, m.Value)
		}
		payload.Findings = append(payload.Findings, ingestFinding{
			Category: string(f.Category), Severity: f.Severity.String(), Headline: f.Headline,
			Metrics: metrics, Action: f.Action, Detail: f.Detail,
		})
	}

	return send(ctx, cfg, payload)
}

func send(ctx context.Context, cfg Config, payload ingestPayload) error {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ingest endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// RunLoop runs RunOnce every interval until ctx is cancelled.
func RunLoop(ctx context.Context, cfg Config, interval time.Duration) {
	for {
		if err := RunOnce(ctx, cfg); err != nil {
			fmt.Println("collection cycle failed:", err)
		} else {
			fmt.Println("collection cycle sent at", time.Now().Format(time.RFC3339))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
