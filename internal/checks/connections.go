package checks

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// Connections checks raw connection utilization against max_connections.
// Per spec, this category is meant to read as the most directly actionable
// one — there's usually a concrete near-term fix (raise max_connections,
// add pooling).
func Connections(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var maxConnStr string
	if err := pool.QueryRow(ctx, "SHOW max_connections").Scan(&maxConnStr); err != nil {
		return nil, fmt.Errorf("read max_connections: %w", err)
	}
	maxConn, err := strconv.Atoi(maxConnStr)
	if err != nil {
		return nil, fmt.Errorf("parse max_connections %q: %w", maxConnStr, err)
	}

	var current int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity").Scan(&current); err != nil {
		return nil, fmt.Errorf("count connections: %w", err)
	}

	util := float64(current) / float64(maxConn) * 100

	severity := report.Healthy
	urgency := report.OptimizeLater
	switch {
	case util >= 90:
		severity, urgency = report.Critical, report.FixNow
	case util >= 75:
		severity, urgency = report.High, report.FixNow
	case util >= 50:
		severity, urgency = report.Medium, report.FixThisWeek
	}

	f := report.Finding{
		Category: report.Connections,
		Severity: severity,
		Urgency:  urgency,
		Metrics: []report.Metric{
			{Value: fmt.Sprintf("%d / %d connections", current, maxConn)},
			{Value: fmt.Sprintf("%.0f%% utilization", util)},
		},
	}

	if severity == report.Healthy {
		f.Headline = fmt.Sprintf("Connection utilization is healthy at %.0f%%.", util)
		f.Action = "No action needed"
	} else {
		f.Headline = fmt.Sprintf("Connection utilization is %.0f%%.", util)
		f.Action = "Review connection pooling"
		f.Detail = "Your database is operating close to its connection ceiling. Sustained growth here risks new connections being refused outright."
	}

	return []report.Finding{f}, nil
}
