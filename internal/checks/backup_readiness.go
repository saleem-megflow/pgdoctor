package checks

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// BackupReadiness reports an honest checklist of what can be confirmed
// from PostgreSQL's own settings — never "Backup verified". A read-only
// CLI connected to Postgres cannot prove an external backup system can
// actually restore the database; it can only check the settings that
// would need to be right for backups to be possible at all. This is a
// deliberate scope correction from the original "Backup & Recovery"
// framing, per the project spec.
func BackupReadiness(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var walLevel string
	if err := pool.QueryRow(ctx, "SHOW wal_level").Scan(&walLevel); err != nil {
		return nil, fmt.Errorf("read wal_level: %w", err)
	}
	walOK := walLevel == "replica" || walLevel == "logical"

	var archiveMode string
	if err := pool.QueryRow(ctx, "SHOW archive_mode").Scan(&archiveMode); err != nil {
		return nil, fmt.Errorf("read archive_mode: %w", err)
	}
	archiveOK := archiveMode == "on" || archiveMode == "always"

	var replicaCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_replication").Scan(&replicaCount); err != nil {
		return nil, fmt.Errorf("count replicas: %w", err)
	}
	replicationOK := replicaCount > 0

	checklist := []report.Metric{
		{Value: fmt.Sprintf("WAL configuration: %s", checkMark(walOK))},
		{Value: fmt.Sprintf("Replication: %s", checkMark(replicationOK))},
		{Value: fmt.Sprintf("Archive configuration: %s", warnMark(archiveOK))},
		{Value: "Recovery configuration: ?"},
		{Value: "External backup system: Not verified"},
		{Value: "Restore test: Not verified"},
	}

	severity, urgency := report.Medium, report.FixThisWeek
	if !walOK {
		severity, urgency = report.Critical, report.FixNow
	} else if !archiveOK && !replicationOK {
		severity, urgency = report.High, report.FixThisWeek
	}

	return []report.Finding{{
		Category: report.BackupReadiness,
		Severity: severity,
		Urgency:  urgency,
		Headline: "Backup / Recovery Readiness checklist.",
		Metrics:  checklist,
		Action:   "Verify your external backup system and run a real restore test",
		Detail:   "We cannot verify recoverability from PostgreSQL metadata alone. This checklist only confirms whether the settings needed for backups to be possible are in place — not that a backup exists, is current, or actually restores.",
	}}, nil
}

func checkMark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func warnMark(ok bool) string {
	if ok {
		return "✓"
	}
	return "⚠"
}
