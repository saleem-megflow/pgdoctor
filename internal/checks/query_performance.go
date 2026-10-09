package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// excludeSelfClause filters out titanpostgres's own introspection queries (and
// other monitoring tools querying the same catalogs) from pg_stat_statements
// results, so the audit never diagnoses itself instead of the customer's
// actual workload. It also scopes to the current database only —
// pg_stat_statements is cluster-wide by default, so without this a query
// run against an unrelated database on the same instance would otherwise
// leak into this database's report.
const excludeSelfClause = `
	dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
	AND query NOT ILIKE '%pg_stat_statements%'
	AND query NOT ILIKE '%pg_stat_activity%'
	AND query NOT ILIKE '%pg_stat_user_tables%'
	AND query NOT ILIKE '%pg_extension%'
	AND query NOT ILIKE '%pg_locks%'
	AND query NOT ILIKE '%pg_blocking_pids%'
	AND query NOT ILIKE 'SHOW %'`

// QueryPerformance finds the queries dominating total database execution
// time via pg_stat_statements. If the extension isn't installed, that's
// itself a finding (an observability gap) rather than a silent skip.
func QueryPerformance(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var installed bool
	err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&installed)
	if err != nil {
		return nil, fmt.Errorf("check pg_stat_statements: %w", err)
	}
	if !installed {
		return []report.Finding{{
			Category: report.QueryPerformance,
			Severity: report.Medium,
			Urgency:  report.FixThisWeek,
			Headline: "pg_stat_statements is not installed, so query-level performance can't be measured.",
			Action:   "Enable the pg_stat_statements extension",
			Detail:   "Without pg_stat_statements, titanpostgres cannot identify which queries dominate database execution time. This is the single highest-leverage extension for diagnosing performance.",
		}}, nil
	}

	var totalExecTime float64
	if err := pool.QueryRow(ctx, `
		SELECT coalesce(sum(total_exec_time), 0) FROM pg_stat_statements
		WHERE `+excludeSelfClause).Scan(&totalExecTime); err != nil {
		return nil, fmt.Errorf("sum total_exec_time: %w", err)
	}
	if totalExecTime <= 0 {
		return []report.Finding{{
			Category: report.QueryPerformance,
			Severity: report.Healthy,
			Headline: "No meaningful query execution history yet.",
			Action:   "No action needed",
		}}, nil
	}

	rows, err := pool.Query(ctx, `
		SELECT query, calls, total_exec_time, mean_exec_time
		FROM pg_stat_statements
		WHERE `+excludeSelfClause+`
		ORDER BY total_exec_time DESC
		LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_statements: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	rank := 0
	for rows.Next() {
		rank++
		var query string
		var calls int64
		var totalMs, meanMs float64
		if err := rows.Scan(&query, &calls, &totalMs, &meanMs); err != nil {
			return nil, err
		}

		pctOfTotal := totalMs / totalExecTime * 100
		severity, urgency := report.Healthy, report.OptimizeLater
		switch {
		case pctOfTotal >= 30:
			severity, urgency = report.Critical, report.FixNow
		case pctOfTotal >= 15:
			severity, urgency = report.High, report.FixNow
		case pctOfTotal >= 5:
			severity, urgency = report.Medium, report.FixThisWeek
		default:
			// below 5% of total time isn't worth surfacing as its own
			// finding for ranks beyond the top query.
			if rank > 1 {
				continue
			}
		}

		metrics := []report.Metric{
			{Value: formatCalls(calls)},
			{Value: fmt.Sprintf("%.2fs average latency", meanMs/1000)},
			{Value: fmt.Sprintf("%.0f sec total DB time", totalMs/1000)},
		}
		if seqScanPct, table, ok := seqScanRatioForQuery(ctx, pool, query); ok {
			metrics = append(metrics, report.Metric{Value: fmt.Sprintf("%.0f%% sequential scans on %s", seqScanPct, table)})
		}

		findings = append(findings, report.Finding{
			Category: report.QueryPerformance,
			Severity: severity,
			Urgency:  urgency,
			Headline: fmt.Sprintf("A query accounts for %.0f%% of total database execution time.", pctOfTotal),
			Metrics:  metrics,
			Action:   "Investigate query plan",
			Detail:   truncateQuery(query),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			Category: report.QueryPerformance,
			Severity: report.Healthy,
			Headline: "No single query dominates database execution time.",
			Action:   "No action needed",
		})
	}
	return findings, nil
}

// seqScanRatioForQuery makes a best-effort attempt to find the main table
// a query touches (naive "FROM <table>" extraction) and reports its
// sequential-scan ratio. If the table can't be identified or has no scan
// history, it returns ok=false rather than guessing — per the project rule
// to never fabricate a number the data doesn't actually support.
func seqScanRatioForQuery(ctx context.Context, pool *pgxpool.Pool, query string) (pct float64, table string, ok bool) {
	table, ok = extractFirstTable(query)
	if !ok {
		return 0, "", false
	}

	var seqScan, idxScan int64
	err := pool.QueryRow(ctx, `
		SELECT seq_scan, idx_scan FROM pg_stat_user_tables WHERE relname = $1`, table).Scan(&seqScan, &idxScan)
	if err != nil {
		return 0, "", false
	}
	total := seqScan + idxScan
	if total == 0 {
		return 0, "", false
	}
	return float64(seqScan) / float64(total) * 100, table, true
}

var fromTablePattern = regexp.MustCompile(`(?i)\bfrom\s+"?([a-zA-Z_][a-zA-Z0-9_]*)"?`)

func extractFirstTable(query string) (string, bool) {
	m := fromTablePattern.FindStringSubmatch(query)
	if len(m) < 2 {
		return "", false
	}
	return strings.ToLower(m[1]), true
}

func truncateQuery(q string) string {
	q = strings.Join(strings.Fields(q), " ")
	const max = 160
	if len(q) > max {
		return q[:max] + "..."
	}
	return q
}

func formatCalls(calls int64) string {
	switch {
	case calls >= 1_000_000:
		return fmt.Sprintf("%.1fM executions", float64(calls)/1_000_000)
	case calls >= 1_000:
		return fmt.Sprintf("%.1fK executions", float64(calls)/1_000)
	default:
		return fmt.Sprintf("%d executions", calls)
	}
}
