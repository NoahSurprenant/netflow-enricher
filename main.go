// netflow-enricher adds names to NetFlow records passing through an OpenTelemetry Collector.
//
// The collector sends OTLP/HTTP JSON log batches to /v1/logs. For each record the service adds:
//
//   - local.name: the reverse DNS name of local.address, through one DNS server (Pi-hole);
//   - remote.country, remote.country_name, remote.as.number, remote.as.name, remote.as.domain:
//     remote.address looked up in IPinfo's free Lite database.
//
// It then forwards the batch to the collector's next OTLP receiver and returns that receiver's
// response, so the collector's retries and failover see the real outcome.
//
// `netflow-enricher download` is the sidecar that keeps the database file fresh.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxBody = 64 << 20

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) > 1 && os.Args[1] == "download" {
		download(os.Args[2:])
		return
	}
	serve(os.Args[1:])
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", env("LISTEN", ":4318"), "address for /v1/logs")
	metricsListen := fs.String("metrics-listen", env("METRICS_LISTEN", ":9090"), "address for /metrics and /healthz")
	forwardURL := fs.String("forward-url", env("FORWARD_URL", ""), "OTLP/HTTP logs endpoint to forward enriched batches to")
	dnsServer := fs.String("dns-server", env("DNS_SERVER", ""), "host:port for reverse DNS of local addresses; empty disables names")
	dbPath := fs.String("geo-database", env("GEO_DATABASE", "/data/ipinfo_lite.mmdb"), "IPinfo Lite database")
	localAttr := fs.String("local-attribute", env("LOCAL_ATTRIBUTE", "local.address"), "attribute holding the local address")
	remoteAttr := fs.String("remote-attribute", env("REMOTE_ATTRIBUTE", "remote.address"), "attribute holding the remote address")
	_ = fs.Parse(args)
	if *forwardURL == "" {
		slog.Error("-forward-url (FORWARD_URL) is required")
		os.Exit(2)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	e := &enricher{
		names:      newNames(*dnsServer, 2*time.Second, time.Hour, 5*time.Minute, reg),
		geo:        newGeo(*dbPath, reg),
		localAttr:  *localAttr,
		remoteAttr: *remoteAttr,
		forwardURL: *forwardURL,
		client:     &http.Client{Timeout: 30 * time.Second},
		records:    prometheus.NewCounter(prometheus.CounterOpts{Name: "netflow_enricher_records_total", Help: "Log records enriched."}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "netflow_enricher_requests_total",
			Help: "Batches received, by the status returned to the sender.",
		}, []string{"code"}),
	}
	reg.MustRegister(e.records, e.requests)
	go e.geo.watch(time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/logs", e.handle)
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })

	servers := []*http.Server{
		{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second},
		{Addr: *metricsListen, Handler: metricsMux, ReadHeaderTimeout: 10 * time.Second},
	}
	for _, s := range servers {
		go func() {
			slog.Info("listening", "address", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("server failed", "address", s.Addr, "error", err)
				os.Exit(1)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
}

type enricher struct {
	names                 *names
	geo                   *geo
	localAttr, remoteAttr string
	forwardURL            string
	client                *http.Client
	records               prometheus.Counter
	requests              *prometheus.CounterVec
}

func (e *enricher) handle(w http.ResponseWriter, r *http.Request) {
	code := http.StatusOK
	defer func() { e.requests.WithLabelValues(strconv.Itoa(code)).Inc() }()
	fail := func(c int, msg string, err error) {
		code = c
		slog.Warn(msg, "error", err)
		http.Error(w, msg, c)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		fail(http.StatusUnsupportedMediaType, "only OTLP JSON is accepted", errors.New(ct))
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, maxBody)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			fail(http.StatusBadRequest, "bad gzip body", err)
			return
		}
		defer gz.Close()
		body = gz
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		fail(http.StatusBadRequest, "reading body", err)
		return
	}
	req, err := decodeLogs(raw)
	if err != nil {
		fail(http.StatusBadRequest, "bad OTLP JSON", err)
		return
	}

	e.records.Add(float64(e.enrich(req)))

	out, err := json.Marshal(req)
	if err != nil {
		fail(http.StatusInternalServerError, "encoding OTLP JSON", err)
		return
	}
	fwd, err := http.NewRequestWithContext(r.Context(), http.MethodPost, e.forwardURL, bytes.NewReader(out))
	if err != nil {
		fail(http.StatusInternalServerError, "building forward request", err)
		return
	}
	fwd.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(fwd)
	if err != nil {
		// 503 is retryable for the collector's otlphttp exporter.
		fail(http.StatusServiceUnavailable, "forwarding to the collector", err)
		return
	}
	defer resp.Body.Close()
	code = resp.StatusCode
	for _, h := range []string{"Content-Type", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// enrich adds the name and geo attributes to every record in req and returns how many it saw.
func (e *enricher) enrich(req object) int {
	return forEachRecord(req, func(attrs, _ []any) []any {
		if addr, err := netip.ParseAddr(stringAttr(attrs, e.localAttr)); err == nil {
			if name := e.names.Name(addr); name != "" {
				attrs = setString(attrs, "local.name", name)
			}
		}
		if addr, err := netip.ParseAddr(stringAttr(attrs, e.remoteAttr)); err == nil {
			if rec, ok := e.geo.Lookup(addr); ok {
				for _, kv := range [][2]string{
					{"remote.country", rec.CountryCode},
					{"remote.country_name", rec.Country},
					{"remote.as.number", rec.ASN},
					{"remote.as.name", rec.ASName},
					{"remote.as.domain", rec.ASDomain},
				} {
					if kv[1] != "" {
						attrs = setString(attrs, kv[0], kv[1])
					}
				}
			}
		}
		return attrs
	})
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
