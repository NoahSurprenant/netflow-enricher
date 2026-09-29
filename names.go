package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// names resolves local addresses to hostnames by reverse DNS, through one DNS server (Pi-hole,
// which forwards PTR lookups for the LAN to the UniFi gateways and so answers with DHCP names).
//
// Lookups never block a request: an address not in the cache is resolved in the background and its
// flows go out unnamed until the answer is cached.
type names struct {
	resolver    *net.Resolver
	timeout     time.Duration
	positiveTTL time.Duration
	negativeTTL time.Duration

	mu       sync.Mutex
	cache    map[netip.Addr]nameEntry
	inflight map[netip.Addr]bool

	lookups *prometheus.CounterVec
}

type nameEntry struct {
	name    string // "" for "no name"
	expires time.Time
}

func newNames(server string, timeout, positiveTTL, negativeTTL time.Duration, reg prometheus.Registerer) *names {
	n := &names{
		timeout:     timeout,
		positiveTTL: positiveTTL,
		negativeTTL: negativeTTL,
		cache:       map[netip.Addr]nameEntry{},
		inflight:    map[netip.Addr]bool{},
		lookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "netflow_enricher_name_lookups_total",
			Help: "Reverse DNS lookups of local addresses, by result (found, not_found, error).",
		}, []string{"result"}),
	}
	if server != "" {
		dialer := net.Dialer{Timeout: timeout}
		n.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, server)
			},
		}
	}
	reg.MustRegister(n.lookups)
	return n
}

// Name returns the cached name for addr, if there is one, and starts a lookup if the entry is
// missing or expired. Only private addresses are looked up.
func (n *names) Name(addr netip.Addr) string {
	if n.resolver == nil || !addr.IsPrivate() {
		return ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.cache[addr]
	if (!ok || time.Now().After(e.expires)) && !n.inflight[addr] {
		n.inflight[addr] = true
		go n.lookup(addr)
	}
	return e.name
}

func (n *names) lookup(addr netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()
	ptrs, err := n.resolver.LookupAddr(ctx, addr.String())

	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.inflight, addr)
	switch {
	case err == nil && len(ptrs) > 0:
		n.lookups.WithLabelValues("found").Inc()
		n.cache[addr] = nameEntry{name: shortName(ptrs[0]), expires: time.Now().Add(n.positiveTTL)}
	case err == nil || isNotFound(err):
		n.lookups.WithLabelValues("not_found").Inc()
		n.cache[addr] = nameEntry{expires: time.Now().Add(n.negativeTTL)}
	default:
		// A failed lookup (timeout, server down) keeps a previously known name and retries soon.
		n.lookups.WithLabelValues("error").Inc()
		n.cache[addr] = nameEntry{name: n.cache[addr].name, expires: time.Now().Add(n.negativeTTL)}
	}
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// shortName drops the trailing dot and the domain: "noah-desktop.gurnt.com." becomes
// "noah-desktop". The site is already on every flow as its cluster.
func shortName(ptr string) string {
	ptr = strings.TrimSuffix(ptr, ".")
	if host, _, ok := strings.Cut(ptr, "."); ok && host != "" {
		return host
	}
	return ptr
}
