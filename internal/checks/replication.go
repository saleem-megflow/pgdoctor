package checks

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// Replication is a diagnostic snapshot, deliberately not a continuous
// replication monitor (that's a later platform-stage feature). It checks
// connected replicas' lag/state and replication slot health.
func Replication(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var findings []report.Finding

	replicas, err := replicaStatus(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, replicas...)

	slots, err := replicationSlots(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, slots...)

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			Category: report.Replication,
			Severity: report.Healthy,
			Headline: "No replicas or replication slots configured.",
			Action:   "No action needed",
			Detail:   "This is informational, not necessarily a problem — not every database needs replication.",
		})
	}
	return findings, nil
}

func replicaStatus(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT application_name, state,
		       EXTRACT(EPOCH FROM replay_lag)
		FROM pg_stat_replication`)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_replication: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var appName, state string
		var lagSecs *float64
		if err := rows.Scan(&appName, &state, &lagSecs); err != nil {
			return nil, err
		}

		severity, urgency := report.Healthy, report.OptimizeLater
		lagDesc := "unknown"
		if lagSecs != nil {
			lagDesc = fmt.Sprintf("%.0f seconds", *lagSecs)
			switch {
			case *lagSecs >= 300:
				severity, urgency = report.Critical, report.FixNow
			case *lagSecs >= 30:
				severity, urgency = report.High, report.FixThisWeek
			case *lagSecs >= 5:
				severity, urgency = report.Medium, report.OptimizeLater
			}
		}

		if severity == report.Healthy {
			findings = append(findings, report.Finding{
				Category: report.Replication,
				Severity: report.Healthy,
				Headline: fmt.Sprintf("Replica %s is healthy.", appName),
				Metrics:  []report.Metric{{Value: fmt.Sprintf("Replay lag: %s", lagDesc)}},
				Action:   "No action needed",
			})
			continue
		}

		findings = append(findings, report.Finding{
			Category: report.Replication,
			Severity: severity,
			Urgency:  urgency,
			Headline: fmt.Sprintf("Replica %s (%s) is lagging.", appName, state),
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Replay lag: %s", lagDesc)},
			},
			Action: "Investigate replica lag before it falls further behind",
			Detail: "Replica may become stale during continued workload.",
		})
	}
	return findings, rows.Err()
}

func replicationSlots(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT slot_name, active,
		       pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS retained_bytes
		FROM pg_replication_slots`)
	if err != nil {
		return nil, fmt.Errorf("query replication slots: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var name string
		var active bool
		var retainedBytes int64
		if err := rows.Scan(&name, &active, &retainedBytes); err != nil {
			return nil, err
		}

		if active && retainedBytes < 1024*1024*1024 {
			continue // healthy, active, not retaining excessive WAL
		}

		severity, urgency := report.Medium, report.FixThisWeek
		headline := fmt.Sprintf("Replication slot %s is retaining WAL.", name)
		if !active {
			severity, urgency = report.High, report.FixThisWeek
			headline = fmt.Sprintf("Replication slot %s is inactive but still retaining WAL.", name)
		}
		if retainedBytes > 10*1024*1024*1024 {
			severity, urgency = report.Critical, report.FixNow
		}

		findings = append(findings, report.Finding{
			Category: report.Replication,
			Severity: severity,
			Urgency:  urgency,
			Headline: headline,
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Retained WAL: %s", formatBytes(retainedBytes))},
				{Value: fmt.Sprintf("Active: %t", active)},
			},
			Action: "Investigate why this slot isn't advancing — an inactive slot can exhaust disk via WAL retention",
			Detail: "An inactive replication slot keeps WAL from being recycled indefinitely, which can fill disk and bring down the primary.",
		})
	}
	return findings, rows.Err()
}
