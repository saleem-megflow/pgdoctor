package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/pgdoctor/internal/report"
)

// VacuumBloat checks dead-tuple accumulation and vacuum/analyze staleness
// per table, plus transaction ID wraparound risk. Per the project's
// accuracy rule, this deliberately does NOT compute an exact bloat
// percentage or a growth trend — PostgreSQL's own stats don't support that
// without extensions like pgstattuple, and a single audit run has no
// history to derive growth from. Only dead-tuple %, vacuum/analyze age,
// and transaction ID age are reported, since those are what pg_stat_*
// actually gives us.
func VacuumBloat(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var tableFindings []report.Finding

	rows, err := pool.Query(ctx, `
		SELECT relname, n_live_tup, n_dead_tup,
		       last_vacuum, last_autovacuum, last_analyze, last_autoanalyze
		FROM pg_stat_user_tables
		WHERE n_live_tup + n_dead_tup > 1000
		ORDER BY n_dead_tup DESC
		LIMIT 10`)
	if err != nil {
		return nil, fmt.Errorf("query vacuum stats: %w", err)
	}
	defer rows.Close()

	now := time.Now()
	for rows.Next() {
		var table string
		var liveTup, deadTup int64
		var lastVacuum, lastAutovacuum, lastAnalyze, lastAutoanalyze *time.Time
		if err := rows.Scan(&table, &liveTup, &deadTup, &lastVacuum, &lastAutovacuum, &lastAnalyze, &lastAutoanalyze); err != nil {
			return nil, err
		}

		total := liveTup + deadTup
		if total == 0 {
			continue
		}
		deadPct := float64(deadTup) / float64(total) * 100

		lastVac := latestTime(lastVacuum, lastAutovacuum)
		severity, urgency := report.Healthy, report.OptimizeLater
		switch {
		case deadPct >= 25:
			severity, urgency = report.Critical, report.FixNow
		case deadPct >= 10:
			severity, urgency = report.High, report.FixThisWeek
		case deadPct >= 5:
			severity, urgency = report.Medium, report.OptimizeLater
		default:
			continue // healthy tables don't each need their own finding
		}

		metrics := []report.Metric{
			{Value: fmt.Sprintf("Dead tuples: %.0f%%", deadPct)},
		}
		if lastVac != nil {
			metrics = append(metrics, report.Metric{Value: fmt.Sprintf("Last vacuum: %s ago", humanDuration(now.Sub(*lastVac)))})
		} else {
			metrics = append(metrics, report.Metric{Value: "Last vacuum: never"})
		}

		tableFindings = append(tableFindings, report.Finding{
			Category: report.VacuumBloat,
			Severity: severity,
			Urgency:  urgency,
			Headline: fmt.Sprintf("%s has significant dead-tuple accumulation.", table),
			Metrics:  metrics,
			Action:   "Review autovacuum configuration for this table",
			Detail:   "Risk: performance degradation / table growth. pgdoctor reports dead-tuple percentage and vacuum age only — not an exact bloat estimate, which PostgreSQL's own stats can't reliably provide.",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	wraparound, err := wraparoundRisk(ctx, pool)
	if err != nil {
		return nil, err
	}

	findings := append(tableFindings, wraparound...)
	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			Category: report.VacuumBloat,
			Severity: report.Healthy,
			Headline: "No tables show significant dead-tuple accumulation.",
			Action:   "No action needed",
		})
	}
	return findings, nil
}

func wraparoundRisk(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `SELECT datname, age(datfrozenxid) FROM pg_database WHERE datallowconn`)
	if err != nil {
		return nil, fmt.Errorf("query transaction id age: %w", err)
	}
	defer rows.Close()

	const wraparoundLimit = 2_000_000_000 // ~2.1B transaction ceiling
	var findings []report.Finding
	for rows.Next() {
		var db string
		var age int64
		if err := rows.Scan(&db, &age); err != nil {
			return nil, err
		}
		pctOfLimit := float64(age) / float64(wraparoundLimit) * 100
		if pctOfLimit < 50 {
			continue
		}
		severity, urgency := report.Medium, report.FixThisWeek
		if pctOfLimit >= 80 {
			severity, urgency = report.Critical, report.FixNow
		} else if pctOfLimit >= 65 {
			severity, urgency = report.High, report.FixNow
		}
		findings = append(findings, report.Finding{
			Category: report.VacuumBloat,
			Severity: severity,
			Urgency:  urgency,
			Headline: fmt.Sprintf("Database %s transaction ID age is %.0f%% of the wraparound limit.", db, pctOfLimit),
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Transaction age: %s transactions", formatCalls(age))},
			},
			Action: "Ensure autovacuum is keeping up with transaction ID advancement",
			Detail: "Transaction ID wraparound causes data loss if it occurs. This is one of the few PostgreSQL conditions that can force an outage.",
		})
	}
	return findings, rows.Err()
}

func latestTime(times ...*time.Time) *time.Time {
	var latest *time.Time
	for _, t := range times {
		if t == nil {
			continue
		}
		if latest == nil || t.After(*latest) {
			latest = t
		}
	}
	return latest
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
