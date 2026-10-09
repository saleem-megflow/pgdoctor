package checks

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// StorageGrowth reports current database size and largest tables. It
// deliberately does NOT report a growth rate or a days-until-threshold
// projection — a single audit run has no historical snapshot to derive a
// trend from, and fabricating one would violate the project's core
// accuracy rule. That projection becomes possible once titanpostgres has run
// more than once against the same database (V2, continuous audit).
func StorageGrowth(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var dbSize int64
	if err := pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&dbSize); err != nil {
		return nil, fmt.Errorf("query database size: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT relname, pg_total_relation_size(relid) AS size_bytes
		FROM pg_stat_user_tables
		ORDER BY size_bytes DESC
		LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("query largest tables: %w", err)
	}
	defer rows.Close()

	var tableMetrics []report.Metric
	for rows.Next() {
		var table string
		var size int64
		if err := rows.Scan(&table, &size); err != nil {
			return nil, err
		}
		tableMetrics = append(tableMetrics, report.Metric{Value: fmt.Sprintf("%s: %s", table, formatBytes(size))})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	metrics := append([]report.Metric{{Value: fmt.Sprintf("Current DB size: %s", formatBytes(dbSize))}}, tableMetrics...)

	return []report.Finding{{
		Category: report.StorageGrowth,
		Severity: report.Healthy,
		Headline: fmt.Sprintf("Database size is %s.", formatBytes(dbSize)),
		Metrics:  metrics,
		Action:   "No action needed",
		Detail:   "Growth rate and a days-until-threshold projection require more than one audit run to measure — not available from a single snapshot.",
	}}, nil
}
