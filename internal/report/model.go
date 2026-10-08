package report

// Severity is how serious a finding is.
type Severity int

const (
	Healthy Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "Critical"
	case High:
		return "High"
	case Medium:
		return "Medium"
	default:
		return "Healthy"
	}
}

func (s Severity) Icon() string {
	switch s {
	case Critical:
		return "🔴"
	case High:
		return "🟠"
	case Medium:
		return "🟡"
	default:
		return "🟢"
	}
}

// Urgency buckets a finding for the Recommended Action Plan, independent of
// its severity and category.
type Urgency int

const (
	OptimizeLater Urgency = iota
	FixThisWeek
	FixNow
)

func (u Urgency) Label() string {
	switch u {
	case FixNow:
		return "Fix now"
	case FixThisWeek:
		return "Fix this week"
	default:
		return "Optimize later"
	}
}

// Category is one of the report's check categories (report sections 3-13).
type Category string

const (
	QueryPerformance   Category = "Query Performance"
	IndexHealth        Category = "Index Health"
	Connections        Category = "Connections"
	LocksTransactions  Category = "Locks & Transactions"
	VacuumBloat        Category = "Vacuum & Bloat"
	Replication        Category = "Replication"
	StorageGrowth      Category = "Storage & Growth"
	Configuration      Category = "Configuration"
	BackupReadiness    Category = "Backup/Recovery Readiness"
	SecurityBaseline   Category = "Security Baseline"
	VersionLifecycle   Category = "PostgreSQL Version"
)

// Metric is one bare supporting number shown under a finding's headline,
// e.g. "1.82s average latency". Label/Value together render as one line.
type Metric struct {
	Label string
	Value string
}

// Finding is a single diagnosed issue (or healthy confirmation) produced by
// a check. Every check in internal/checks emits Findings into the same
// pipeline — scoring, the Top-5 wow cards, per-category sections, and the
// urgency-grouped action plan are all just different views over this slice.
type Finding struct {
	Category    Category
	Severity    Severity
	Urgency     Urgency
	Headline    string   // one-line plain-English sentence, e.g. "Query Q-184 accounts for 43% of total database execution time."
	Metrics     []Metric // bare supporting numbers, e.g. {"", "1.82s average latency"}
	Action      string   // short imperative-free action line, e.g. "Investigate query plan"
	Detail      string   // optional longer recommendation text for the full category section
}

// Report is the full result of an audit run.
type Report struct {
	PostgresVersion string
	Findings        []Finding
}

// Score computes the overall 0-100 reliability score. Each non-healthy
// finding deducts points by severity; floor at 0.
func (r *Report) Score() int {
	score := 100
	for _, f := range r.Findings {
		switch f.Severity {
		case Critical:
			score -= 8
		case High:
			score -= 4
		case Medium:
			score -= 1
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

// RiskBand maps the score to a plain-English risk level.
func (r *Report) RiskBand() string {
	s := r.Score()
	switch {
	case s >= 90:
		return "LOW"
	case s >= 70:
		return "MEDIUM"
	case s >= 50:
		return "HIGH"
	default:
		return "SEVERE"
	}
}

// SeverityCounts returns the count of findings at each severity level.
func (r *Report) SeverityCounts() map[Severity]int {
	counts := map[Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// TopRisks returns the top n findings ranked by severity (Critical first),
// excluding Healthy findings. Ties keep original (check-run) order.
func (r *Report) TopRisks(n int) []Finding {
	var risky []Finding
	for _, f := range r.Findings {
		if f.Severity > Healthy {
			risky = append(risky, f)
		}
	}
	// stable sort, highest severity first
	for i := 1; i < len(risky); i++ {
		for j := i; j > 0 && risky[j].Severity > risky[j-1].Severity; j-- {
			risky[j], risky[j-1] = risky[j-1], risky[j]
		}
	}
	if len(risky) > n {
		risky = risky[:n]
	}
	return risky
}

// ByCategory groups findings for the per-category report sections, in a
// fixed canonical order matching the 14-section report structure.
func (r *Report) ByCategory() []struct {
	Category Category
	Findings []Finding
} {
	order := []Category{
		QueryPerformance, IndexHealth, Connections, LocksTransactions,
		VacuumBloat, Replication, StorageGrowth, Configuration,
		BackupReadiness, SecurityBaseline, VersionLifecycle,
	}
	grouped := map[Category][]Finding{}
	for _, f := range r.Findings {
		grouped[f.Category] = append(grouped[f.Category], f)
	}
	var out []struct {
		Category Category
		Findings []Finding
	}
	for _, c := range order {
		out = append(out, struct {
			Category Category
			Findings []Finding
		}{c, grouped[c]})
	}
	return out
}

// ByUrgency groups non-healthy findings for the Recommended Action Plan.
func (r *Report) ByUrgency() []struct {
	Urgency  Urgency
	Findings []Finding
} {
	order := []Urgency{FixNow, FixThisWeek, OptimizeLater}
	grouped := map[Urgency][]Finding{}
	for _, f := range r.Findings {
		if f.Severity == Healthy {
			continue
		}
		grouped[f.Urgency] = append(grouped[f.Urgency], f)
	}
	var out []struct {
		Urgency  Urgency
		Findings []Finding
	}
	for _, u := range order {
		out = append(out, struct {
			Urgency  Urgency
			Findings []Finding
		}{u, grouped[u]})
	}
	return out
}
