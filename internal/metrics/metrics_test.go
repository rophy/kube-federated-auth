package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

func newTestMetrics(version string, clientMetrics bool) *Metrics {
	reg := prometheus.NewRegistry()
	return newWithFactory(version, clientMetrics, promauto.With(reg))
}

func TestNew(t *testing.T) {
	m := newTestMetrics("v1.0.0", false)

	if m.HTTPRequestsTotal == nil {
		t.Error("HTTPRequestsTotal is nil")
	}
	if m.HTTPRequestDuration == nil {
		t.Error("HTTPRequestDuration is nil")
	}
	if m.TokenReviewRequestsTotal == nil {
		t.Error("TokenReviewRequestsTotal is nil")
	}
	if m.CacheRequestsTotal == nil {
		t.Error("CacheRequestsTotal is nil")
	}
	if m.CacheEntries == nil {
		t.Error("CacheEntries is nil")
	}
	if m.ClusterDegraded == nil {
		t.Error("ClusterDegraded is nil")
	}
	if m.CredentialRenewalTotal == nil {
		t.Error("CredentialRenewalTotal is nil")
	}
	if m.CredentialExpirySeconds == nil {
		t.Error("CredentialExpirySeconds is nil")
	}
	if m.ServerInfo == nil {
		t.Error("ServerInfo is nil")
	}

	gauge, err := m.ServerInfo.GetMetricWithLabelValues("v1.0.0")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	metric := &dto.Metric{}
	if err := gauge.Write(metric); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if metric.Gauge.GetValue() != 1 {
		t.Errorf("server_info = %v, want 1", metric.Gauge.GetValue())
	}
}

func TestRecordTokenReview_WithoutClientMetrics(t *testing.T) {
	m := newTestMetrics("v1.0.0", false)
	m.RecordTokenReview("cluster-a/ns/caller", "cluster-b/ns/app", "200", "cluster-b")

	counter, err := m.TokenReviewRequestsTotal.GetMetricWithLabelValues("cluster-a/ns/caller", "200", "cluster-b")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if metric.Counter.GetValue() != 1 {
		t.Errorf("counter = %v, want 1", metric.Counter.GetValue())
	}
}

func TestRecordTokenReview_WithClientMetrics(t *testing.T) {
	m := newTestMetrics("v1.0.0", true)
	m.RecordTokenReview("cluster-a/ns/caller", "cluster-b/ns/app", "200", "cluster-b")

	counter, err := m.TokenReviewRequestsTotal.GetMetricWithLabelValues("cluster-a/ns/caller", "cluster-b/ns/app", "200", "cluster-b")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if metric.Counter.GetValue() != 1 {
		t.Errorf("counter = %v, want 1", metric.Counter.GetValue())
	}
}

func TestRecordTokenReview_EmptyCaller(t *testing.T) {
	m := newTestMetrics("v1.0.0", false)
	m.RecordTokenReview("", "", "200", "cluster-b")

	counter, err := m.TokenReviewRequestsTotal.GetMetricWithLabelValues("", "200", "cluster-b")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if metric.Counter.GetValue() != 1 {
		t.Errorf("counter = %v, want 1", metric.Counter.GetValue())
	}
}
