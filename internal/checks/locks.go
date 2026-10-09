package checks

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// LocksTransactions checks for long-running transactions, idle-in-
// transaction sessions, and lock contention. Per spec, this is a dedicated
// category (not folded into Connections) because it can surface something
// actively dangerous happening right now, not just a historical pattern.
func LocksTransactions(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var findings []report.Finding

	longRunning, err := longRunningTransactions(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, longRunning...)

	idleInTxn, err := idleInTransaction(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, idleInTxn...)

	blocking, err := blockedQueries(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, blocking...)

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			Category: report.LocksTransactions,
			Severity: report.Healthy,
			Headline: "No long-running transactions, idle-in-transaction sessions, or lock contention detected.",
			Action:   "No action needed",
		})
	}
	return findings, nil
}

func longRunningTransactions(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT pid, usename, datname, EXTRACT(EPOCH FROM (now() - xact_start))::int AS secs
		FROM pg_stat_activity
		WHERE xact_start IS NOT NULL
		  AND state != 'idle'
		  AND pid != pg_backend_pid()
		  AND now() - xact_start > interval '5 minutes'
		ORDER BY secs DESC`)
	if err != nil {
		return nil, fmt.Errorf("query long-running transactions: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var pid int
		var user, db string
		var secs int
		if err := rows.Scan(&pid, &user, &db, &secs); err != nil {
			return nil, err
		}
		mins := secs / 60
		severity, urgency := report.High, report.FixThisWeek
		if mins >= 30 {
			severity, urgency = report.Critical, report.FixNow
		}
		findings = append(findings, report.Finding{
			Category: report.LocksTransactions,
			Severity: severity,
			Urgency:  urgency,
			Headline: fmt.Sprintf("Long-running transaction on %s has been open for %d minutes.", db, mins),
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Duration: %d minutes", mins)},
				{Value: fmt.Sprintf("Database: %s", db)},
				{Value: fmt.Sprintf("User: %s", user)},
				{Value: fmt.Sprintf("PID: %d", pid)},
			},
			Action: "Investigate and consider terminating the session",
			Detail: "Long-running transactions hold back autovacuum from cleaning dead tuples and can block other sessions.",
		})
	}
	return findings, rows.Err()
}

func idleInTransaction(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT pid, usename, datname, EXTRACT(EPOCH FROM (now() - state_change))::int AS secs
		FROM pg_stat_activity
		WHERE state = 'idle in transaction'
		  AND pid != pg_backend_pid()
		  AND now() - state_change > interval '5 minutes'
		ORDER BY secs DESC`)
	if err != nil {
		return nil, fmt.Errorf("query idle-in-transaction sessions: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var pid int
		var user, db string
		var secs int
		if err := rows.Scan(&pid, &user, &db, &secs); err != nil {
			return nil, err
		}
		mins := secs / 60
		severity, urgency := report.High, report.FixThisWeek
		if mins >= 30 {
			severity, urgency = report.Critical, report.FixNow
		}
		findings = append(findings, report.Finding{
			Category: report.LocksTransactions,
			Severity: severity,
			Urgency:  urgency,
			Headline: fmt.Sprintf("Session idle in transaction on %s for %d minutes.", db, mins),
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Idle duration: %d minutes", mins)},
				{Value: fmt.Sprintf("Database: %s", db)},
				{Value: fmt.Sprintf("User: %s", user)},
				{Value: fmt.Sprintf("PID: %d", pid)},
			},
			Action: "Investigate the application connection holding this transaction open",
			Detail: "Idle-in-transaction sessions hold locks and prevent autovacuum from advancing, same risk profile as a long-running transaction.",
		})
	}
	return findings, rows.Err()
}

func blockedQueries(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT pid, pg_blocking_pids(pid)
		FROM pg_stat_activity
		WHERE cardinality(pg_blocking_pids(pid)) > 0`)
	if err != nil {
		return nil, fmt.Errorf("query blocked sessions: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var pid int
		var blockers []int32
		if err := rows.Scan(&pid, &blockers); err != nil {
			return nil, err
		}
		findings = append(findings, report.Finding{
			Category: report.LocksTransactions,
			Severity: report.High,
			Urgency:  report.FixNow,
			Headline: fmt.Sprintf("Session %d is blocked waiting on %v.", pid, blockers),
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Blocked PID: %d", pid)},
				{Value: fmt.Sprintf("Blocking PID(s): %v", blockers)},
			},
			Action: "Investigate the blocking session",
			Detail: "Lock contention between these sessions is actively delaying queries right now.",
		})
	}
	return findings, rows.Err()
}
