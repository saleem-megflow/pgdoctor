// Package lead implements the email-gate lead capture shown once before a
// titanpostgres audit runs. The lead is POSTed to titanpostgres-api (a tiny Megflow-
// owned endpoint — see ~/code/titanpostgres-api) so it actually reaches Megflow,
// not just the customer's own machine. If the API call fails (offline,
// firewall, etc.) the audit still proceeds — a lead-capture outage should
// never block the thing the customer actually asked for.
package lead

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const defaultEndpoint = "https://api.titanpostgres.megflow.com/leads"

var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// Capture prompts for email and company on stdin/stdout, validates the
// email loosely, reports it to titanpostgres-api, and returns it.
func Capture(in *bufio.Reader, out *os.File) (email, company string, err error) {
	fmt.Fprintln(out, "titanpostgres needs an email before running your audit — we'll only use it to follow up about your results.")
	for {
		fmt.Fprint(out, "Email: ")
		line, readErr := in.ReadString('\n')
		if readErr != nil {
			return "", "", readErr
		}
		email = strings.TrimSpace(line)
		if emailPattern.MatchString(email) {
			break
		}
		fmt.Fprintln(out, "That doesn't look like a valid email, try again.")
	}

	fmt.Fprint(out, "Company (optional): ")
	line, readErr := in.ReadString('\n')
	if readErr == nil {
		company = strings.TrimSpace(line)
	}

	if reportErr := report(email, company); reportErr != nil {
		fmt.Fprintln(out, "(note: couldn't reach Megflow to register this run, continuing anyway)")
	}
	return email, company, nil
}

func report(email, company string) error {
	endpoint := os.Getenv("TITANPOSTGRES_LEADS_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	body, err := json.Marshal(struct {
		Email   string `json:"email"`
		Company string `json:"company"`
	}{email, company})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("leads endpoint returned %d", resp.StatusCode)
	}
	return nil
}
