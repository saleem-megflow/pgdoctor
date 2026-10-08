package checks

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/pgdoctor/internal/report"
)

// VersionLifecycle is a minor baseline check, deliberately not a
// centerpiece of the report. It flags clearly old major versions as a
// maintenance consideration rather than trying to track exact EOL dates
// (which would need an external, regularly-updated data source pgdoctor
// doesn't have in V1).
func VersionLifecycle(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var version string
	if err := pool.QueryRow(ctx, "SHOW server_version").Scan(&version); err != nil {
		return nil, fmt.Errorf("read server_version: %w", err)
	}
	var versionNumStr string
	if err := pool.QueryRow(ctx, "SHOW server_version_num").Scan(&versionNumStr); err != nil {
		return nil, fmt.Errorf("read server_version_num: %w", err)
	}
	versionNum, err := strconv.Atoi(versionNumStr)
	if err != nil {
		return nil, fmt.Errorf("parse server_version_num %q: %w", versionNumStr, err)
	}
	major := versionNum / 10000

	severity, urgency, status := report.Healthy, report.OptimizeLater, "Current"
	switch {
	case major < 13:
		severity, urgency, status = report.High, report.FixThisWeek, "Likely end-of-life"
	case major < 15:
		severity, urgency, status = report.Medium, report.OptimizeLater, "Maintenance consideration"
	}

	f := report.Finding{
		Category: report.VersionLifecycle,
		Severity: severity,
		Urgency:  urgency,
		Headline: fmt.Sprintf("PostgreSQL %s.", version),
		Metrics:  []report.Metric{{Value: fmt.Sprintf("Version status: %s", status)}},
	}
	if severity == report.Healthy {
		f.Action = "No action needed"
	} else {
		f.Action = "Review supported upgrade path"
	}
	return []report.Finding{f}, nil
}
