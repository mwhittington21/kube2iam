package metrics

import (
	"net/http"

	"github.com/jtblin/kube2iam/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "kube2iam"

var (
	// IamRequestCount counts number of outbound requests made to AWS IAM service.
	IamRequestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "iam",
			Name:      "requests_total",
			Help:      "Number of outbound requests made to AWS IAM service.",
		},

		[]string{
			// The HTTP status code AWS returned
			"code",
			// The arn of the IAM role being requested
			"role_arn",
		},
	)

	// IamRequestSec tracks timing of IAM requests.
	IamRequestSec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "iam",
			Name:      "request_duration_seconds",
			Help:      "Time taken to complete IAM request in seconds.",

			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
		},
		[]string{
			// The HTTP status code AWS returned
			"code",
			// The arn of the IAM role being requested
			"role_arn",
		},
	)

	// HTTPRequestCount counts number of HTTP requests served split by handler.
	HTTPRequestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Number of http requests served by kube2iam.",
		},
		[]string{
			// The HTTP status code kube2iam returned
			"code",
			// The HTTP method being served
			"method",
			// The name of the handler being served
			"handler",
		},
	)

	// HTTPRequestSec tracks timing of served HTTP requests.
	HTTPRequestSec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Time taken for kube2iam to serve HTTP request.",

			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
		},
		[]string{
			// The HTTP status code kube2iam returned
			"code",
			// The HTTP method being served
			"method",
			// The name of the handler being served
			"handler",
		},
	)

	// HealthcheckStatus reports the current healthcheck status of kube2iam.
	HealthcheckStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "healthcheck",
			Name:      "status",
			Help:      "The healthcheck status at scrape time. A value of 1 means it is passing, 0 means it is failing.",
		},
	)

	// Info reports various static information about the running kube2iam binary.
	Info = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "info",
			Help:      "Informational labels about the kube2iam process.",
		},
		[]string{
			// The version of kube2iam running
			"version",
			// The build date of the kube2iam version
			"build_date",
			// The commit hash of the kube2iam version
			"commit_hash",
		},
	)
)

type lvsProducer func() []string

// Init ensures prometheus knows about all the metrics tracked by kube2iam and initializes the values with default
// label sets.
func Init() {
	prometheus.MustRegister(IamRequestCount)
	prometheus.MustRegister(IamRequestSec)
	prometheus.MustRegister(HTTPRequestCount)
	prometheus.MustRegister(HTTPRequestSec)
	prometheus.MustRegister(HealthcheckStatus)
	prometheus.MustRegister(Info)

	for _, val := range []string{"Success", "UnknownError"} {
		IamRequestCount.WithLabelValues(val, "")
		IamRequestSec.WithLabelValues(val, "")
	}
	Info.WithLabelValues(version.Version, version.BuildDate, version.GitCommit).Set(1)
}

// GetHandler creates
func GetHandler() http.Handler {
	return promhttp.Handler()
}

// NewFunctionTimer creates a new timer for a generic function that can be observed to time the duration of the handler.
// The metric is labeled with the values produced by the lvsProducer to allow for late binding of label values.
// If provided, the timer value is stored in storeValue to allow callers access to the reported value.
func NewFunctionTimer(histVec *prometheus.HistogramVec, lvsFn lvsProducer, storeValue *float64) *prometheus.Timer {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		if storeValue != nil {
			*storeValue = v
		}
		histVec.WithLabelValues(lvsFn()...).Observe(v)
	}))
	return timer
}
