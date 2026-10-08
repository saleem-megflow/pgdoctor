package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/saleem-megflow/pgdoctor/internal/report"
)

// SecurityBaseline is a sanity pass, not a security scanner — per the
// project spec, a full security product is explicitly a separate future
// direction. Checks: SSL, whether pgdoctor's own connecting role is
// superuser (it shouldn't need to be), privileged roles present, and
// overly permissive pg_hba rules (trust auth, unrestricted source
// addresses).
func SecurityBaseline(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	var findings []report.Finding

	ssl, err := sslCheck(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, ssl)

	roleCheck, err := connectingRoleCheck(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, roleCheck)

	privileged, err := privilegedRoles(ctx, pool)
	if err != nil {
		return nil, err
	}
	findings = append(findings, privileged)

	hba, err := permissiveAuthRules(ctx, pool)
	if err != nil {
		// pg_hba_file_rules requires superuser/pg_read_all_settings in
		// some setups; degrade gracefully rather than failing the whole
		// category over one restricted view.
		findings = append(findings, report.Finding{
			Category: report.SecurityBaseline,
			Severity: report.Medium,
			Headline: "Could not read pg_hba.conf rules with the current credentials.",
			Action:   "Grant pg_read_all_settings to the audit role for full authentication visibility",
		})
	} else {
		findings = append(findings, hba...)
	}

	return findings, nil
}

func sslCheck(ctx context.Context, pool *pgxpool.Pool) (report.Finding, error) {
	var ssl string
	if err := pool.QueryRow(ctx, "SHOW ssl").Scan(&ssl); err != nil {
		return report.Finding{}, fmt.Errorf("read ssl: %w", err)
	}
	if ssl == "on" {
		return report.Finding{
			Category: report.SecurityBaseline,
			Severity: report.Healthy,
			Headline: "SSL is enabled.",
			Action:   "No action needed",
		}, nil
	}
	return report.Finding{
		Category: report.SecurityBaseline,
		Severity: report.High,
		Urgency:  report.FixThisWeek,
		Headline: "SSL is not enabled.",
		Action:   "Enable SSL for encrypted connections",
		Detail:   "Without SSL, traffic between clients and this database is unencrypted.",
	}, nil
}

func connectingRoleCheck(ctx context.Context, pool *pgxpool.Pool) (report.Finding, error) {
	var isSuper bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper); err != nil {
		return report.Finding{}, fmt.Errorf("check current role: %w", err)
	}
	if !isSuper {
		return report.Finding{
			Category: report.SecurityBaseline,
			Severity: report.Healthy,
			Headline: "pgdoctor is connected with a non-superuser role, as recommended.",
			Action:   "No action needed",
		}, nil
	}
	return report.Finding{
		Category: report.SecurityBaseline,
		Severity: report.Medium,
		Urgency:  report.OptimizeLater,
		Headline: "pgdoctor is connected with a superuser role.",
		Action:   "Create a dedicated read-only role for pgdoctor instead of using a superuser credential",
		Detail:   "A reliability audit only needs SELECT access and pg_monitor — using superuser credentials for this is broader access than necessary.",
	}, nil
}

func privilegedRoles(ctx context.Context, pool *pgxpool.Pool) (report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT rolname FROM pg_roles
		WHERE (rolsuper OR rolcreaterole OR rolcreatedb)
		  AND rolname NOT IN ('postgres')
		ORDER BY rolname
		LIMIT 10`)
	if err != nil {
		return report.Finding{}, fmt.Errorf("query privileged roles: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return report.Finding{}, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return report.Finding{}, err
	}

	if len(names) == 0 {
		return report.Finding{
			Category: report.SecurityBaseline,
			Severity: report.Healthy,
			Headline: "No non-default roles have superuser, CREATEROLE, or CREATEDB privileges.",
			Action:   "No action needed",
		}, nil
	}

	return report.Finding{
		Category: report.SecurityBaseline,
		Severity: report.Medium,
		Urgency:  report.OptimizeLater,
		Headline: fmt.Sprintf("%d role(s) hold superuser, CREATEROLE, or CREATEDB privileges.", len(names)),
		Metrics:  []report.Metric{{Value: strings.Join(names, ", ")}},
		Action:   "Review whether each of these roles still needs this level of privilege",
		Detail:   "pgdoctor can't determine whether these roles are actively used — only that they currently hold elevated privileges.",
	}, nil
}

func permissiveAuthRules(ctx context.Context, pool *pgxpool.Pool) ([]report.Finding, error) {
	rows, err := pool.Query(ctx, `
		SELECT type, address, auth_method
		FROM pg_hba_file_rules
		WHERE auth_method = 'trust'
		   OR address IN ('0.0.0.0/0', '::/0')`)
	if err != nil {
		return nil, fmt.Errorf("query pg_hba_file_rules: %w", err)
	}
	defer rows.Close()

	var findings []report.Finding
	for rows.Next() {
		var connType, address, authMethod string
		if err := rows.Scan(&connType, &address, &authMethod); err != nil {
			return nil, err
		}

		severity := report.Medium
		headline := fmt.Sprintf("Authentication rule allows broad access from %s.", address)
		if authMethod == "trust" {
			severity = report.Critical
			headline = fmt.Sprintf("Authentication rule uses 'trust' (no password) for %s.", address)
		}

		findings = append(findings, report.Finding{
			Category: report.SecurityBaseline,
			Severity: severity,
			Urgency:  report.FixNow,
			Headline: headline,
			Metrics: []report.Metric{
				{Value: fmt.Sprintf("Type: %s", connType)},
				{Value: fmt.Sprintf("Address: %s", address)},
				{Value: fmt.Sprintf("Auth method: %s", authMethod)},
			},
			Action: "Review this pg_hba.conf rule",
			Detail: "Verify this rule's scope is intentional before relying on it.",
		})
	}
	return findings, rows.Err()
}
