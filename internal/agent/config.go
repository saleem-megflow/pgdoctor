// Package agent implements "pgdoctor agent" — the V2 continuous-collection
// daemon. Unlike the one-shot "pgdoctor audit" CLI, the agent runs
// unattended, reusing the exact same checks.Run pipeline on a timer and
// reporting results to pgdoctor-api's ingestion endpoint instead of
// printing a terminal report.
package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	DSN      string `json:"dsn"`
	APIKey   string `json:"api_key"`
	Endpoint string `json:"endpoint"`
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pgdoctor", "agent.json"), nil
}

func Save(cfg Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// 0600: this file holds a read-only DB credential and an API key.
	return os.WriteFile(path, data, 0o600)
}

func Load() (Config, error) {
	var cfg Config
	path, err := configPath()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}
