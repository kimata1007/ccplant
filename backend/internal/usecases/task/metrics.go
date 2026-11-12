package task

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	repo "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
)

type Metrics struct {
	submitted  prometheus.Counter
	claimed    prometheus.Counter
	failed     *prometheus.CounterVec
	wait       prometheus.Histogram
	start      prometheus.Histogram
	conflicts  prometheus.Counter
	reconciled prometheus.Counter
	depth      *prometheus.Desc
	oldest     *prometheus.Desc
	stuck      *prometheus.Desc
	repository repo.TaskRepository
}

func NewMetrics(repository repo.TaskRepository) *Metrics {
	return &Metrics{
		submitted:  prometheus.NewCounter(prometheus.CounterOpts{Name: "tasks_submitted_total", Help: "New tasks accepted."}),
		claimed:    prometheus.NewCounter(prometheus.CounterOpts{Name: "tasks_claimed_total", Help: "Task leases assigned."}),
		failed:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tasks_failed_total", Help: "Terminal task startup failures."}, []string{"reason"}),
		wait:       prometheus.NewHistogram(prometheus.HistogramOpts{Name: "task_queue_wait_seconds", Help: "Time from task submission to first claim.", Buckets: []float64{1, 5, 15, 60, 300, 900, 3600}}),
		start:      prometheus.NewHistogram(prometheus.HistogramOpts{Name: "task_session_start_seconds", Help: "Time from first dispatch to session readiness.", Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 900}}),
		conflicts:  prometheus.NewCounter(prometheus.CounterOpts{Name: "task_claim_conflict_total", Help: "Claim updates rejected by the task record version."}),
		reconciled: prometheus.NewCounter(prometheus.CounterOpts{Name: "task_reconciliation_total", Help: "Task states recovered from session state or queue deadlines."}),
		depth:      prometheus.NewDesc("task_queue_depth", "Pending tasks by scope.", []string{"scope"}, nil),
		oldest:     prometheus.NewDesc("task_queue_oldest_seconds", "Age of the oldest pending task by scope.", []string{"scope"}, nil),
		stuck:      prometheus.NewDesc("task_starting_overdue", "Tasks starting for over ten minutes by scope.", []string{"scope"}, nil),
		repository: repository,
	}
}

func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.submitted, m.claimed, m.failed, m.wait, m.start, m.conflicts, m.reconciled}
}

func (m *Metrics) Describe(out chan<- *prometheus.Desc) {
	for _, collector := range m.collectors() {
		collector.Describe(out)
	}
	out <- m.depth
	out <- m.oldest
	out <- m.stuck
}

func (m *Metrics) Collect(out chan<- prometheus.Metric) {
	for _, collector := range m.collectors() {
		collector.Collect(out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	items, err := m.repository.List(ctx, repo.TaskFilter{Pending: true})
	if err != nil {
		out <- prometheus.NewInvalidMetric(m.depth, err)
		return
	}
	type counts struct{ depth, oldest, stuck float64 }
	scopes := map[entities.ResourceScope]counts{}
	now := time.Now()
	for _, t := range items {
		c := scopes[t.Scope]
		c.depth++
		c.oldest = max(c.oldest, now.Sub(t.CreatedAt).Seconds())
		if t.State == entities.TaskStarting && t.StartedAt != nil && now.Sub(*t.StartedAt) > 10*time.Minute {
			c.stuck++
		}
		scopes[t.Scope] = c
	}
	for _, scope := range []entities.ResourceScope{entities.ScopeUser, entities.ScopeTeam} {
		c := scopes[scope]
		out <- prometheus.MustNewConstMetric(m.depth, prometheus.GaugeValue, c.depth, string(scope))
		out <- prometheus.MustNewConstMetric(m.oldest, prometheus.GaugeValue, c.oldest, string(scope))
		out <- prometheus.MustNewConstMetric(m.stuck, prometheus.GaugeValue, c.stuck, string(scope))
	}
}
