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

// Milestone 2 set: the three categories flagged in planning as the
// strongest wow / most actionable, used to prove the full pipeline before
// building out the remaining eight categories.
var All = []Checker{
	QueryPerformance,
	Connections,
	LocksTransactions,
}
