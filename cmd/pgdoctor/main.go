package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/saleem-megflow/pgdoctor/internal/agent"
	"github.com/saleem-megflow/pgdoctor/internal/checks"
	"github.com/saleem-megflow/pgdoctor/internal/db"
	"github.com/saleem-megflow/pgdoctor/internal/lead"
	"github.com/saleem-megflow/pgdoctor/internal/render"
	"github.com/saleem-megflow/pgdoctor/internal/report"
	"github.com/saleem-megflow/pgdoctor/internal/webreport"
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
	root.AddCommand(agentCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runAudit(ctx context.Context, dsn string) error {
	if dsn == "" {
		return fmt.Errorf("--dsn is required, e.g. postgres://readonly_user:pass@host:5432/dbname")
	}

	email, company, err := lead.Capture(bufio.NewReader(os.Stdin), os.Stdout)
	if err != nil {
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

	if url, err := webreport.Submit(email, company, r); err == nil {
		fmt.Printf("\nView this report online: %s\n", url)
	}
	return nil
}

// agentCmd wires "pgdoctor agent install" and "pgdoctor agent run" — V2's
// continuous collection, separate from the one-shot "pgdoctor audit"
// above. Reuses the exact same checks.Run pipeline, per the explicit
// decision to build V2 on top of V1's audit engine rather than rewrite it.
func agentCmd() *cobra.Command {
	agentRoot := &cobra.Command{
		Use:   "agent",
		Short: "Continuous PostgreSQL reliability monitoring (V2)",
	}

	var installDSN, apiKey, endpoint string
	install := &cobra.Command{
		Use:   "install",
		Short: "Save agent configuration (DSN + API key)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if installDSN == "" || apiKey == "" {
				return fmt.Errorf("--dsn and --api-key are required (get an API key by registering a database at the pgdoctor dashboard)")
			}
			if err := agent.Save(agent.Config{DSN: installDSN, APIKey: apiKey, Endpoint: endpoint}); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Println("Agent configured. Run `pgdoctor agent run` to start continuous collection.")
			return nil
		},
	}
	install.Flags().StringVar(&installDSN, "dsn", "", "PostgreSQL connection string (read-only credentials recommended)")
	install.Flags().StringVar(&apiKey, "api-key", "", "API key for this database (from the pgdoctor dashboard)")
	install.Flags().StringVar(&endpoint, "endpoint", "", "Override the ingestion endpoint (defaults to pgdoctor-api.megflow.com)")

	var interval time.Duration
	run := &cobra.Command{
		Use:   "run",
		Short: "Run continuous collection using the saved configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := agent.Load()
			if err != nil {
				return fmt.Errorf("no agent configuration found, run `pgdoctor agent install` first: %w", err)
			}
			fmt.Printf("Starting continuous collection every %s...\n", interval)
			agent.RunLoop(cmd.Context(), cfg, interval)
			return nil
		},
	}
	run.Flags().DurationVar(&interval, "interval", 5*time.Minute, "Collection interval")

	agentRoot.AddCommand(install, run)
	return agentRoot
}
