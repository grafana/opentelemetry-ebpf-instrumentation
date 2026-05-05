// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package promtest provides some convenience functions for prometheus handling in integration tests.
package promtest // import "go.opentelemetry.io/obi/internal/test/integration/components/promtest"

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

var log = slog.With("component", "prom.Client")

type queryResult struct {
	Status string `json:"status"`
	Data   data   `json:"data"`
}

type data struct {
	Result     []Result `json:"result"`
	ResultType string   `json:"resultType"`
}

// Result structure assumes that resultType is always == "vector"
type Result struct {
	Metric map[string]string `json:"metric"`
	Value  []any
}

type Client struct {
	HostPort string
}

func (c *Client) Query(promQL string) ([]Result, error) {
	qurl := "http://" + c.HostPort + "/api/v1/query?query=" + url.PathEscape(promQL)
	log.Debug("querying prometheus", "query", promQL, "url", qurl)
	resp, err := http.Get(qurl)
	if err != nil {
		return nil, fmt.Errorf("querying prometheus: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read response body: %w", err)
	}
	log.Debug(string(body))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus returned status %q", resp.Status)
	}
	qr := queryResult{}
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	slog.Debug("prometheus query successful",
		"status", qr.Status,
		"resultType", qr.Data.ResultType)
	return qr.Data.Result, nil
}

type ScrapedMetric struct {
	Name   string
	Value  float64
	Labels map[string]string
}

// Scrape implements a simple, synchronous, validation-oriented (non-error-prone)
// scrape of Prometheus metrics towards a /metrics HTTP endpoint
func Scrape(metricsURL string) ([]ScrapedMetric, error) {
	resp, err := http.Get(metricsURL)
	if err != nil {
		return nil, fmt.Errorf("scraping %s: %w", metricsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", metricsURL, resp.Status)
	}

	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing response of %s: %w", metricsURL, err)
	}

	var metrics []ScrapedMetric
	for _, family := range families {
		for _, metric := range family.Metric {
			metrics = append(metrics, scrapedMetrics(family, metric)...)
		}
	}
	sort.Slice(metrics, func(i, j int) bool {
		return scrapedMetricSortKey(metrics[i]) < scrapedMetricSortKey(metrics[j])
	})
	return metrics, nil
}

func FindMetric(metrics []ScrapedMetric, name string, labels map[string]string) (ScrapedMetric, bool) {
	for _, metric := range metrics {
		if metric.Name == name && hasLabels(metric.Labels, labels) {
			return metric, true
		}
	}
	return ScrapedMetric{}, false
}

func scrapedMetrics(family *dto.MetricFamily, metric *dto.Metric) []ScrapedMetric {
	labels := metricLabels(metric)
	name := family.GetName()

	switch family.GetType() {
	case dto.MetricType_HISTOGRAM:
		histogram := metric.GetHistogram()
		metrics := []ScrapedMetric{
			{Name: name + "_count", Value: float64(histogram.GetSampleCount()), Labels: labels},
			{Name: name + "_sum", Value: histogram.GetSampleSum(), Labels: labels},
		}
		for _, bucket := range histogram.Bucket {
			bucketLabels := copyLabels(labels)
			bucketLabels["le"] = formatFloat(bucket.GetUpperBound())
			metrics = append(metrics, ScrapedMetric{
				Name:   name + "_bucket",
				Value:  float64(bucket.GetCumulativeCount()),
				Labels: bucketLabels,
			})
		}
		return metrics
	case dto.MetricType_SUMMARY:
		summary := metric.GetSummary()
		metrics := []ScrapedMetric{
			{Name: name + "_count", Value: float64(summary.GetSampleCount()), Labels: labels},
			{Name: name + "_sum", Value: summary.GetSampleSum(), Labels: labels},
		}
		for _, quantile := range summary.Quantile {
			quantileLabels := copyLabels(labels)
			quantileLabels["quantile"] = formatFloat(quantile.GetQuantile())
			metrics = append(metrics, ScrapedMetric{
				Name:   name,
				Value:  quantile.GetValue(),
				Labels: quantileLabels,
			})
		}
		return metrics
	default:
		return []ScrapedMetric{{
			Name:   name,
			Value:  metricValue(metric),
			Labels: labels,
		}}
	}
}

func metricValue(metric *dto.Metric) float64 {
	switch {
	case metric.Gauge != nil:
		return metric.Gauge.GetValue()
	case metric.Counter != nil:
		return metric.Counter.GetValue()
	case metric.Untyped != nil:
		return metric.Untyped.GetValue()
	case metric.Histogram != nil:
		return float64(metric.Histogram.GetSampleCount())
	case metric.Summary != nil:
		return float64(metric.Summary.GetSampleCount())
	default:
		return 0
	}
}

func metricLabels(metric *dto.Metric) map[string]string {
	labels := map[string]string{}
	for _, label := range metric.Label {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}

func copyLabels(labels map[string]string) map[string]string {
	copied := make(map[string]string, len(labels)+1)
	for name, value := range labels {
		copied[name] = value
	}
	return copied
}

func hasLabels(got, want map[string]string) bool {
	for name, value := range want {
		if got[name] != value {
			return false
		}
	}
	return true
}

func scrapedMetricSortKey(metric ScrapedMetric) string {
	labels := make([]string, 0, len(metric.Labels))
	for name, value := range metric.Labels {
		labels = append(labels, name+"="+value)
	}
	sort.Strings(labels)
	return metric.Name + "{" + strings.Join(labels, ",") + "}"
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}
