// Package render implements pgdoctor's terminal output: the score header,
// the Top-5 wow cards, the per-category sections, and the urgency-grouped
// action plan. V1 is terminal-only — no HTML/PDF.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/saleem-megflow/pgdoctor/internal/report"
)

const cardWidth = 43

// Report renders the full report to w.
func Report(w io.Writer, r *report.Report) {
	header(w, r)
	executiveSummary(w, r)
	topRisks(w, r)
	categorySections(w, r)
	actionPlan(w, r)
}

// executiveSummary is report section 1: a short plain-English synthesis,
// generated from the same Finding data as every other section rather than
// hand-written per run.
func executiveSummary(w io.Writer, r *report.Report) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "1. Executive Summary")

	counts := r.SeverityCounts()
	critical, high := counts[report.Critical], counts[report.High]
	score, risk := r.Score(), r.RiskBand()

	var headline string
	switch {
	case critical > 0:
		headline = fmt.Sprintf("This database scored %d/100 (%s risk) with %d critical issue(s) that need attention now.", score, risk, critical)
	case high > 0:
		headline = fmt.Sprintf("This database scored %d/100 (%s risk) with %d high-severity issue(s) worth addressing this week.", score, risk, high)
	default:
		headline = fmt.Sprintf("This database scored %d/100 (%s risk) — no critical or high-severity issues were found.", score, risk)
	}
	fmt.Fprintln(w, headline)

	if top := r.TopRisks(1); len(top) > 0 {
		fmt.Fprintf(w, "The most significant finding: %s\n", top[0].Headline)
	}
}

func header(w io.Writer, r *report.Report) {
	score := r.Score()
	counts := r.SeverityCounts()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "PostgreSQL Reliability Report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "            %d / 100\n", score)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s %d Critical\n", report.Critical.Icon(), counts[report.Critical])
	fmt.Fprintf(w, "%s %d High\n", report.High.Icon(), counts[report.High])
	fmt.Fprintf(w, "%s %d Medium\n", report.Medium.Icon(), counts[report.Medium])
	fmt.Fprintf(w, "%s %d Healthy\n", report.Healthy.Icon(), counts[report.Healthy])
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Estimated risk: %s\n", r.RiskBand())
}

// topRisks is the "wow" screen: a card-based feed of the top findings,
// each in its own bordered box, in severity order.
func topRisks(w io.Writer, r *report.Report) {
	risks := r.TopRisks(5)
	if len(risks) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "TOP 5 THINGS TO FIX")
	for _, f := range risks {
		fmt.Fprintln(w)
		card(w, f)
	}
}

func card(w io.Writer, f report.Finding) {
	border := strings.Repeat("─", cardWidth)
	fmt.Fprintf(w, "┌%s┐\n", border)
	writeCardLine(w, fmt.Sprintf("%s %s", f.Severity.Icon(), strings.ToUpper(f.Severity.String())))
	writeCardLine(w, "")
	for _, line := range wrap(f.Headline, cardWidth-2) {
		writeCardLine(w, line)
	}
	if len(f.Metrics) > 0 {
		writeCardLine(w, "")
		for _, m := range f.Metrics {
			writeCardLine(w, m.Value)
		}
	}
	if f.Action != "" {
		writeCardLine(w, "")
		writeCardLine(w, "→ "+f.Action)
	}
	fmt.Fprintf(w, "└%s┘\n", border)
}

func writeCardLine(w io.Writer, text string) {
	padding := cardWidth - 2 - displayWidth(text)
	if padding < 0 {
		padding = 0
	}
	fmt.Fprintf(w, "│ %s%s │\n", text, strings.Repeat(" ", padding))
}

// displayWidth approximates terminal column width: most emoji used in
// pgdoctor's output (🔴🟠🟡🟢) render as double-width, everything else in
// this tool's output is single-width ASCII.
func displayWidth(s string) int {
	width := 0
	for _, r := range s {
		if r >= 0x1F300 {
			width += 2
		} else {
			width++
		}
	}
	return width
}

func wrap(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var cur string
	for _, word := range words {
		if cur == "" {
			cur = word
			continue
		}
		if len(cur)+1+len(word) > width {
			lines = append(lines, cur)
			cur = word
			continue
		}
		cur += " " + word
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

var categoryOrder = []struct {
	Title string
}{
	{"3. Query Performance"}, {"4. Index Health"}, {"5. Connections"},
	{"6. Locks & Transactions"}, {"7. Vacuum & Bloat"}, {"8. Replication"},
	{"9. Storage & Growth"}, {"10. Configuration"}, {"11. Backup/Recovery Readiness"},
	{"12. Security Baseline"}, {"13. PostgreSQL Version"},
}

func categorySections(w io.Writer, r *report.Report) {
	grouped := r.ByCategory()
	for i, g := range grouped {
		if i >= len(categoryOrder) {
			break
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "────────────────────────────────────────────")
		fmt.Fprintln(w, categoryOrder[i].Title)
		if g.Category == report.VacuumBloat && len(g.Findings) > 0 {
			fmt.Fprintf(w, "  Vacuum Health: %d/100\n", report.ScoreFindings(g.Findings))
		}
		if len(g.Findings) == 0 {
			fmt.Fprintln(w, "  (not yet checked in this build)")
			continue
		}
		for _, f := range g.Findings {
			fmt.Fprintf(w, "\n  %s %s\n", f.Severity.Icon(), f.Headline)
			for _, m := range f.Metrics {
				fmt.Fprintf(w, "    %s\n", m.Value)
			}
			if f.Action != "" {
				fmt.Fprintf(w, "    → %s\n", f.Action)
			}
			if f.Detail != "" {
				fmt.Fprintf(w, "    %s\n", f.Detail)
			}
		}
	}
}

func actionPlan(w io.Writer, r *report.Report) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "────────────────────────────────────────────")
	fmt.Fprintln(w, "14. Recommended Action Plan")
	groups := r.ByUrgency()
	n := 0
	any := false
	for _, g := range groups {
		if len(g.Findings) == 0 {
			continue
		}
		any = true
		fmt.Fprintf(w, "\n%s %s\n", severityIconForUrgency(g.Urgency), g.Urgency.Label())
		for _, f := range g.Findings {
			n++
			fmt.Fprintf(w, "%d. %s\n", n, f.Headline)
		}
	}
	if !any {
		fmt.Fprintln(w, "\nNo outstanding risks — nothing to prioritize.")
	}
}

func severityIconForUrgency(u report.Urgency) string {
	switch u {
	case report.FixNow:
		return "🔴"
	case report.FixThisWeek:
		return "🟠"
	default:
		return "🟡"
	}
}
