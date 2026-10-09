package checks

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/titanpostgres/internal/report"
)

// IndexHealth checks for missing-index candidates (tables scanned
// sequentially far more than via an index), unused indexes, and
// duplicate/overlapping indexes. Per the project's trust rule, overlapping
// indexes are reported as "potentially redundant — verify before removal",
// never as a command to drop anything.
func IndexHealth(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var findings []report.Finding

	missing, err := missingIndexCandidates(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, missing...)

	unused, err := unusedIndexes(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, unused...)

	dupes, err := overlappingIndexes(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, dupes...)

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			Category: report.IndexHealth,
			Severity: report.Healthy,
			Headline: "No missing-index, unused-index, or overlapping-index risks detected.",
			Action:   "No action needed",
		})
	}
	return findings, nil
}

// missingIndexCandidates flags tables that are scanned sequentially far
// more than via an index and read a large number of rows per scan. We
// can't honestly identify which specific columns would help without
// parsing query plans, so this stays table-level rather than guessing
// column names, per the project's no-fabrication rule.
func missingIndexCandidates(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT relname, seq_scan, idx_scan, seq_tup_read,
		       pg_total_relation_size(relid) AS size_bytes
		FROM pg_stat_user_tables
		WHERE seq_scan > 100
		  AND seq_scan > (idx_scan * 3 + 10)
		  AND pg_total_relation_size(relid) > 10 * 1024 * 1024
		ORDER BY seq_tup_read DESC
		LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("query missing-index candidates: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var table string
		var seqScan, idxScan, seqTupRead, sizeBytes int64
		if err := rows.Scan(&table, &seqScan, &idxScan, &seqTupRead, &sizeBytes); err != nil {
			return nil, err
		}
		findings = append(findings, report.Finding{
			Category: report.IndexHealth,
			Severity: report.High,
			Urgency:  report.FixThisWeek,
			Headline: fmt.Sprintf("Table %s is performing repeated sequential scans.", table),
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("%s sequential scans", formatCalls(seqScan))},
				{Value: fmt.Sprintf("%s rows read via sequential scan", formatCalls(seqTupRead))},
				{Value: fmt.Sprintf("Table size: %s", formatBytes(sizeBytes))},
			},
			Action: "Review query patterns against this table for a missing index",
			Detail: "Potential benefit: HIGH. titanpostgres can't identify the exact column(s) without analyzing query plans — review WHERE/JOIN clauses against this table.",
		})
	}
	return findings, rows.Err()
}

func unusedIndexes(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT indexrelname, pg_relation_size(indexrelid) AS size_bytes, idx_scan
		FROM pg_stat_user_indexes
		WHERE idx_scan < 5
		  AND pg_relation_size(indexrelid) > 100 * 1024 * 1024
		  AND indexrelname NOT LIKE '%_pkey'
		ORDER BY size_bytes DESC
		LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("query unused indexes: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var name string
		var sizeBytes, idxScan int64
		if err := rows.Scan(&name, &sizeBytes, &idxScan); err != nil {
			return nil, err
		}
		findings = append(findings, report.Finding{
			Category: report.IndexHealth,
			Severity: report.Medium,
			Urgency:  report.FixThisWeek,
			Headline: fmt.Sprintf("Index %s is large and rarely used.", name),
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Size: %s", formatBytes(sizeBytes))},
				{Value: fmt.Sprintf("Scans: %d", idxScan)},
			},
			Action: "Verify before removal",
			Detail: "Potentially unnecessary — confirm this index isn't required for an infrequent but important query (e.g. a monthly report) before dropping it.",
		})
	}
	return findings, rows.Err()
}

// overlappingIndexes flags indexes on the same table whose leading columns
// are a prefix of another index on the same table — a common source of
// redundant indexes that slow down writes for no read benefit. Always
// phrased as "potentially redundant — verify before removal," never as an
// instruction to drop anything.
func overlappingIndexes(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			t.relname AS table_name,
			i1.relname AS index_a,
			i2.relname AS index_b
		FROM pg_index idx1
		JOIN pg_index idx2 ON idx1.indrelid = idx2.indrelid AND idx1.indexrelid < idx2.indexrelid
		JOIN pg_class t ON t.oid = idx1.indrelid
		JOIN pg_class i1 ON i1.oid = idx1.indexrelid
		JOIN pg_class i2 ON i2.oid = idx2.indexrelid
		WHERE idx1.indkey[0] = idx2.indkey[0]
		  AND t.relnamespace = 'public'::regnamespace
		LIMIT 5`)
	if err != nil {
		return nil, fmt.Errorf("query overlapping indexes: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var table, indexA, indexB string
		if err := rows.Scan(&table, &indexA, &indexB); err != nil {
			return nil, err
		}
		findings = append(findings, report.Finding{
			Category: report.IndexHealth,
			Severity: report.Medium,
			Urgency:  report.OptimizeLater,
			Headline: fmt.Sprintf("%s and %s on %s share a leading column — potential redundancy detected.", indexA, indexB, table),
			Metrics: []report.Metric{
				{Value: indexA},
				{Value: indexB},
			},
			Action: "Verify before removal",
			Detail: "Potentially redundant — verify query patterns actually need both indexes before removing either one.",
		})
	}
	return findings, rows.Err()
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), units[exp])
}
