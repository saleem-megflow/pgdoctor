// Package checks implements pgdoctor's individual diagnostic checks. Every
// check is a Checker: given a connection pool, it returns the Findings it
// produced (including Healthy ones, so the report's "healthy checks" count
// is honest rather than inferred).
package checks

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/pgdoctor/internal/report"
)

type Checker func(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error)

// Independent checks, order doesn't matter between them. Configuration is
// run separately (see Run) since it depends on VacuumBloat's findings —
// per the project spec, autovacuum's severity should be judged against
// dead-tuple pressure actually observed elsewhere in the audit, not a
// fixed threshold.
var independent = []Checker{
	QueryPerformance,
	Connections,
	LocksTransactions,
	IndexHealth,
	VacuumBloat,
	Replication,
	StorageGrowth,
	BackupReadiness,
	SecurityBaseline,
	VersionLifecycle,
}

// Run executes every check and returns the combined findings, in a fixed
// order so dependent checks (Configuration) see the results they need.
func Run(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, []error) {
	var all []report.Finding
	var errs []error
	var vacuumFindings []report.Finding

	for _, check := range independent {
		findings, err := check(ctx, pool)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		all = append(all, findings...)
		if len(findings) > 0 && findings[0].Category == report.VacuumBloat {
			vacuumFindings = findings
		}
	}

	configFindings, err := Configuration(ctx, pool, vacuumFindings)
	if err != nil {
		errs = append(errs, err)
	} else {
		all = append(all, configFindings...)
	}

	return all, errs
}
