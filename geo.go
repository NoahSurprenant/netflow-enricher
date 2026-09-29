package main

import (
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/prometheus/client_golang/prometheus"
)

// geoRecord is one network in IPinfo's free Lite database (ipinfo_lite.mmdb).
type geoRecord struct {
	Country     string `maxminddb:"country"`
	CountryCode string `maxminddb:"country_code"`
	ASN         string `maxminddb:"asn"` // "AS15169"
	ASName      string `maxminddb:"as_name"`
	ASDomain    string `maxminddb:"as_domain"`
}

// geo looks up public addresses in the database at path, reopening it when the file changes (the
// downloader replaces it daily). A missing or unreadable database is not fatal: flows then go out
// without geo attributes until one appears.
type geo struct {
	path string

	mu      sync.RWMutex
	reader  *maxminddb.Reader
	modTime time.Time

	lookups *prometheus.CounterVec
	age     prometheus.GaugeFunc
}

func newGeo(path string, reg prometheus.Registerer) *geo {
	g := &geo{
		path: path,
		lookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "netflow_enricher_geo_lookups_total",
			Help: "Database lookups of remote addresses, by result (found, not_found, no_database, error).",
		}, []string{"result"}),
	}
	g.age = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "netflow_enricher_geo_database_age_seconds",
		Help: "Time since the loaded database file was written; absent means none is loaded.",
	}, func() float64 {
		g.mu.RLock()
		defer g.mu.RUnlock()
		if g.reader == nil {
			return -1
		}
		return time.Since(g.modTime).Seconds()
	})
	reg.MustRegister(g.lookups, g.age)
	g.reload()
	return g
}

// watch reopens the database whenever its modification time changes.
func (g *geo) watch(interval time.Duration) {
	for range time.Tick(interval) {
		g.reload()
	}
}

func (g *geo) reload() {
	st, err := os.Stat(g.path)
	if err != nil {
		return
	}
	g.mu.RLock()
	unchanged := g.reader != nil && st.ModTime().Equal(g.modTime)
	g.mu.RUnlock()
	if unchanged {
		return
	}
	r, err := maxminddb.Open(g.path)
	if err != nil {
		slog.Warn("cannot open geo database", "path", g.path, "error", err)
		return
	}
	g.mu.Lock()
	old := g.reader
	g.reader, g.modTime = r, st.ModTime()
	g.mu.Unlock()
	if old != nil {
		// In-flight lookups hold the read lock, so none is still using the old reader.
		_ = old.Close()
	}
	slog.Info("loaded geo database", "path", g.path, "built", time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC())
}

// Lookup returns the record for a public address; ok is false for private addresses, misses and
// when no database is loaded.
func (g *geo) Lookup(addr netip.Addr) (rec geoRecord, ok bool) {
	if !addr.IsValid() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return rec, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.reader == nil {
		g.lookups.WithLabelValues("no_database").Inc()
		return rec, false
	}
	res := g.reader.Lookup(addr.Unmap())
	if err := res.Decode(&rec); err != nil {
		g.lookups.WithLabelValues("error").Inc()
		return rec, false
	}
	if !res.Found() {
		g.lookups.WithLabelValues("not_found").Inc()
		return rec, false
	}
	g.lookups.WithLabelValues("found").Inc()
	return rec, true
}
