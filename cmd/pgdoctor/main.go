package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/saleem-megflow/pgdoctor/internal/checks"
	"github.com/saleem-megflow/pgdoctor/internal/db"
	"github.com/saleem-megflow/pgdoctor/internal/lead"
	"github.com/saleem-megflow/pgdoctor/internal/render"
	"github.com/saleem-megflow/pgdoctor/internal/report"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "pgdoctor",
		Short: "PostgreSQL Reliability Audit",
	}

	var dsn string
	audit := &cobra.Command{
		Use:   "audit",
		Short: "Run a PostgreSQL reliability audit and print the report",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(cmd.Context(), dsn)
		},
	}
	audit.Flags().StringVar(&dsn, "dsn", "", "PostgreSQL connection string (read-only credentials recommended)")
	root.AddCommand(audit)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runAudit(ctx context.Context, dsn string) error {
	if dsn == "" {
		return fmt.Errorf("--dsn is required, e.g. postgres://readonly_user:pass@host:5432/dbname")
	}

	if _, _, err := lead.Capture(bufio.NewReader(os.Stdin), os.Stdout); err != nil {
		return fmt.Errorf("email capture: %w", err)
	}

	fmt.Println("\nConnecting to your database (read-only)...")
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("could not connect: %w", err)
	}
	defer pool.Close()

	var version string
	if err := pool.QueryRow(ctx, "SHOW server_version").Scan(&version); err != nil {
		return fmt.Errorf("read server version: %w", err)
	}

	fmt.Println("Running checks...")
	findings, checkErrs := checks.Run(ctx, pool)
	for _, checkErr := range checkErrs {
		fmt.Fprintf(os.Stderr, "(warning: a check failed: %v)\n", checkErr)
	}
	r := &report.Report{PostgresVersion: version, Findings: findings}

	render.Report(os.Stdout, r)
	return nil
}
