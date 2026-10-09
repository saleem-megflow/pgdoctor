package checks

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// Configuration checks only the parameters that can actually cause
// operational problems — not a full parameter dump. Per the project rule,
// findings are contextualized against what's actually been observed
// elsewhere in the audit (e.g. work_mem against the current connection
// count), never against a fixed "good value" table. vacuumFindings lets
// the autovacuum check use dead-tuple pressure already found by the
// Vacuum & Bloat category, instead of re-deriving it.
func Configuration(ctx context.Context, pool *pgxpool.Pool, vacuumFindings []report.Finding) ([]report.Finding, error) {
	var findings []report.Finding

	workMem, err := workMemVsConnections(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, workMem)

	stmtTimeout, err := statementTimeout(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, stmtTimeout)

	autovac, err := autovacuumConfig(ctx, pool, vacuumFindings)
	if err != nil {
		return nil, err
	}
	findings = append(findings, autovac)

	return findings, nil
}

func workMemVsConnections(ctx context.Context, pool *pgxpool.Pool) (report.Finding, error) {
	workMemKB, err := showBytes(ctx, pool, "work_mem")
	if err != nil {
		return report.Finding{}, err
	}
	var maxConnStr string
	if err := pool.QueryRow(ctx, "SHOW max_connections").Scan(&maxConnStr); err != nil {
		return report.Finding{}, fmt.Errorf("read max_connections: %w", err)
	}
	maxConn, err := strconv.Atoi(maxConnStr)
	if err != nil {
		return report.Finding{}, fmt.Errorf("parse max_connections: %w", err)
	}
	effectiveCacheKB, err := showBytes(ctx, pool, "effective_cache_size")
	if err != nil {
		return report.Finding{}, err
	}

	// Worst case: every connection runs one sort/hash using a full
	// work_mem allocation at once. Compared against effective_cache_size
	// as a rough proxy for "memory this box expects to have available" —
	// imperfect, but it's what's actually derivable from Postgres config
	// alone without OS-level access.
	potentialTotalKB := workMemKB * int64(maxConn)

	if effectiveCacheKB == 0 || potentialTotalKB < effectiveCacheKB/2 {
		return report.Finding{
			Category: report.Configuration,
			Severity: report.Healthy,
			Headline: "work_mem is reasonable for the current connection count.",
			Action:   "No action needed",
		}, nil
	}

	severity, urgency := report.Medium, report.OptimizeLater
	if potentialTotalKB >= effectiveCacheKB {
		severity, urgency = report.High, report.FixThisWeek
	}

	return report.Finding{
		Category: report.Configuration,
		Severity: severity,
		Urgency:  urgency,
		Headline: "work_mem is potentially aggressive for the current connection count.",
		Metrics: []report.Metric{
			{Value: fmt.Sprintf("work_mem: %s", formatKB(workMemKB))},
			{Value: fmt.Sprintf("max_connections: %d", maxConn)},
			{Value: fmt.Sprintf("Worst-case total: %s vs. effective_cache_size %s", formatKB(potentialTotalKB), formatKB(effectiveCacheKB))},
		},
		Action: "Review work_mem relative to your actual concurrent query mix",
		Detail: "If many connections run memory-intensive sorts/hashes simultaneously, this could exceed available memory. This is a worst-case estimate, not a measurement of actual usage.",
	}, nil
}

func statementTimeout(ctx context.Context, pool *pgxpool.Pool) (report.Finding, error) {
	var value string
	if err := pool.QueryRow(ctx, "SHOW statement_timeout").Scan(&value); err != nil {
		return report.Finding{}, fmt.Errorf("read statement_timeout: %w", err)
	}
	if value != "0" {
		return report.Finding{
			Category: report.Configuration,
			Severity: report.Healthy,
			Headline: fmt.Sprintf("statement_timeout is configured (%s).", value),
			Action:   "No action needed",
		}, nil
	}
	return report.Finding{
		Category: report.Configuration,
		Severity: report.Medium,
		Urgency:  report.OptimizeLater,
		Headline: "statement_timeout is not configured.",
		Action:   "Consider setting a statement_timeout appropriate to your workload",
		Detail:   "Without a timeout, a single runaway query can hold resources indefinitely. Whether this matters depends on your workload — OLAP/reporting databases often need long-running queries.",
	}, nil
}

func autovacuumConfig(ctx context.Context, pool *pgxpool.Pool, vacuumFindings []report.Finding) (report.Finding, error) {
	var autovacuumOn string
	if err := pool.QueryRow(ctx, "SHOW autovacuum").Scan(&autovacuumOn); err != nil {
		return report.Finding{}, fmt.Errorf("read autovacuum: %w", err)
	}
	if autovacuumOn != "on" {
		return report.Finding{
			Category: report.Configuration,
			Severity: report.Critical,
			Urgency:  report.FixNow,
			Headline: "autovacuum is disabled.",
			Action:   "Enable autovacuum",
			Detail:   "Without autovacuum, dead tuples and transaction ID age accumulate unchecked — this is a critical reliability risk, not just a performance one.",
		}, nil
	}

	// Cross-category signal: if Vacuum & Bloat already found high-severity
	// dead-tuple pressure, autovacuum's current settings are demonstrably
	// not keeping up for at least some tables — contextualize against
	// that observed evidence rather than guessing at "ideal" thresholds.
	pressureTables := 0
	for _, f := range vacuumFindings {
		if f.Category == report.VacuumBloat && f.Severity >= report.High {
			pressureTables++
		}
	}
	if pressureTables == 0 {
		return report.Finding{
			Category: report.Configuration,
			Severity: report.Healthy,
			Headline: "autovacuum is enabled and keeping up with observed dead-tuple accumulation.",
			Action:   "No action needed",
		}, nil
	}

	return report.Finding{
		Category: report.Configuration,
		Severity: report.High,
		Urgency:  report.FixThisWeek,
		Headline: "autovacuum is potentially insufficient for high-write tables.",
		Metrics: []report.Metric{
			{Value: fmt.Sprintf("%d table(s) showing high dead-tuple pressure despite autovacuum running", pressureTables)},
		},
		Action: "Review per-table autovacuum settings (autovacuum_vacuum_scale_factor/cost_limit) for the affected tables",
		Detail: "This is contextual: autovacuum is on, but the Vacuum & Bloat findings above show it isn't keeping pace for at least one high-write table.",
	}, nil
}

// showBytes reads a Postgres memory-unit setting (work_mem,
// effective_cache_size, etc.) and returns it in kilobytes. Postgres
// reports these via SHOW with a unit suffix (e.g. "4MB", "128kB").
func showBytes(ctx context.Context, pool *pgxpool.Pool, setting string) (int64, error) {
	var kb int64
	if err := pool.QueryRow(ctx,
		`SELECT setting::bigint FROM pg_settings WHERE name = $1 AND unit = 'kB'
		 UNION ALL
		 SELECT (setting::bigint * 8) FROM pg_settings WHERE name = $1 AND unit = '8kB'
		 LIMIT 1`, setting).Scan(&kb); err != nil {
		return 0, fmt.Errorf("read %s: %w", setting, err)
	}
	return kb, nil
}

func formatKB(kb int64) string {
	return formatBytes(kb * 1024)
}
