package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/prometheus/client_golang/prometheus"
)

// testDatabase writes a one-network database in IPinfo Lite's schema.
func testDatabase(t *testing.T) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "ipinfo ipinfo_lite.mmdb", RecordSize: 24})
	if err != nil {
		t.Fatal(err)
	}
	_, network, _ := net.ParseCIDR("8.8.8.0/24")
	if err := w.Insert(network, mmdbtype.Map{
		"country":      mmdbtype.String("United States"),
		"country_code": mmdbtype.String("US"),
		"asn":          mmdbtype.String("AS15169"),
		"as_name":      mmdbtype.String("Google LLC"),
		"as_domain":    mmdbtype.String("google.com"),
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ipinfo_lite.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return path
}

const batch = `{"resourceLogs":[{"resource":{"attributes":[{"key":"cluster","value":{"stringValue":"home"}}]},
"scopeLogs":[{"scope":{"name":"netflow"},"logRecords":[
 {"timeUnixNano":"1790651109922000000","body":{"stringValue":"outbound tcp"},"attributes":[
  {"key":"local.address","value":{"stringValue":"10.14.12.199"}},
  {"key":"remote.address","value":{"stringValue":"8.8.8.8"}},
  {"key":"flow.io.bytes","value":{"intValue":"167"}}]},
 {"timeUnixNano":"1790651109923000000","attributes":[
  {"key":"local.address","value":{"stringValue":"10.14.12.5"}},
  {"key":"remote.address","value":{"stringValue":"10.14.7.10"}}]}]}]}]}`

// testEnricher returns an enricher forwarding to a fake collector, which records what it received
// and answers with status.
func testEnricher(t *testing.T, status int) (*enricher, *[]byte) {
	t.Helper()
	var got []byte
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"partialSuccess":{}}`)
	}))
	t.Cleanup(collector.Close)

	reg := prometheus.NewRegistry()
	e := &enricher{
		// A server is needed for Name() to consult the cache; nothing listens on port 1.
		names:      newNames("127.0.0.1:1", time.Second, time.Hour, time.Minute, reg),
		geo:        newGeo(testDatabase(t), reg),
		localAttr:  "local.address",
		remoteAttr: "remote.address",
		forwardURL: collector.URL,
		client:     collector.Client(),
		records:    prometheus.NewCounter(prometheus.CounterOpts{Name: "records"}),
		requests:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "requests"}, []string{"code"}),
	}
	// A known name, as if a lookup had already completed.
	e.names.cache[netip.MustParseAddr("10.14.12.199")] = nameEntry{name: "noah-desktop", expires: time.Now().Add(time.Hour)}
	return e, &got
}

func attrsOf(t *testing.T, body []byte) []map[string]string {
	t.Helper()
	req, err := decodeLogs(body)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	forEachRecord(req, func(attrs, _ []any) []any {
		m := map[string]string{}
		for _, a := range attrs {
			kv := a.(object)
			v := kv["value"].(object)
			for _, s := range []string{"stringValue", "intValue"} {
				if x, ok := v[s]; ok {
					m[kv["key"].(string)] = toString(x)
				}
			}
		}
		out = append(out, m)
		return attrs
	})
	return out
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}

func post(e *enricher, body []byte, gz bool) *httptest.ResponseRecorder {
	if gz {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		_ = zw.Close()
		body = buf.Bytes()
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if gz {
		r.Header.Set("Content-Encoding", "gzip")
	}
	w := httptest.NewRecorder()
	e.handle(w, r)
	return w
}

func TestEnrichAndForward(t *testing.T) {
	for _, gz := range []bool{false, true} {
		e, got := testEnricher(t, http.StatusOK)
		if w := post(e, []byte(batch), gz); w.Code != http.StatusOK {
			t.Fatalf("gzip=%v: status %d: %s", gz, w.Code, w.Body)
		}
		recs := attrsOf(t, *got)
		if len(recs) != 2 {
			t.Fatalf("forwarded %d records, want 2", len(recs))
		}
		want := map[string]string{
			"local.name":          "noah-desktop",
			"remote.country":      "US",
			"remote.country_name": "United States",
			"remote.as.number":    "AS15169",
			"remote.as.name":      "Google LLC",
			"remote.as.domain":    "google.com",
			"flow.io.bytes":       "167",
		}
		for k, v := range want {
			if recs[0][k] != v {
				t.Errorf("gzip=%v: record 0 %s = %q, want %q", gz, k, recs[0][k], v)
			}
		}
		// Unknown name and a private remote address: nothing added.
		for _, k := range []string{"local.name", "remote.country", "remote.as.name"} {
			if _, ok := recs[1][k]; ok {
				t.Errorf("gzip=%v: record 1 has %s", gz, k)
			}
		}
		// Fields the service does not touch pass through.
		for _, s := range []string{`"timeUnixNano":"1790651109922000000"`, `"body":{"stringValue":"outbound tcp"}`, `"scope":{"name":"netflow"}`, `"cluster"`} {
			if !strings.Contains(string(*got), s) {
				t.Errorf("gzip=%v: forwarded batch lost %s", gz, s)
			}
		}
	}
}

func TestCollectorStatusPassesThrough(t *testing.T) {
	e, _ := testEnricher(t, http.StatusServiceUnavailable)
	if w := post(e, []byte(batch), false); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

func TestCollectorDownIsRetryable(t *testing.T) {
	e, _ := testEnricher(t, http.StatusOK)
	e.forwardURL = "http://127.0.0.1:1/v1/logs"
	if w := post(e, []byte(batch), false); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

func TestRejectsNonJSON(t *testing.T) {
	e, _ := testEnricher(t, http.StatusOK)
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader("x"))
	r.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	e.handle(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d, want 415", w.Code)
	}
}

func TestNoDatabaseIsNotFatal(t *testing.T) {
	g := newGeo(filepath.Join(t.TempDir(), "missing.mmdb"), prometheus.NewRegistry())
	if _, ok := g.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("lookup succeeded without a database")
	}
}

func TestNameOnlyForPrivateAddresses(t *testing.T) {
	// Nothing listens on port 1, so every lookup fails fast and is cached as a miss.
	n := newNames("127.0.0.1:1", 100*time.Millisecond, time.Hour, time.Minute, prometheus.NewRegistry())
	public, private := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.1.2.3")
	n.Name(public)
	n.Name(private)
	deadline := time.Now().Add(2 * time.Second)
	for {
		n.mu.Lock()
		_, privateDone := n.cache[private]
		_, publicDone := n.cache[public]
		n.mu.Unlock()
		if publicDone {
			t.Fatal("looked up a public address")
		}
		if privateDone {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no lookup made for a private address")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShortName(t *testing.T) {
	for in, want := range map[string]string{
		"noah-desktop.gurnt.com.": "noah-desktop",
		"k2.":                     "k2",
		"plain":                   "plain",
	} {
		if got := shortName(in); got != want {
			t.Errorf("shortName(%q) = %q, want %q", in, got, want)
		}
	}
}
