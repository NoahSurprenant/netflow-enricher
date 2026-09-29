package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// download keeps IPinfo's free Lite database at -output fresh: fetch now, then every -interval.
// The file is written beside the target and renamed over it only once it opens as a valid
// database, so the server never sees a partial file.
func download(args []string) {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	output := fs.String("output", env("GEO_DATABASE", "/data/ipinfo_lite.mmdb"), "where to write the database")
	url := fs.String("url", env("GEO_DATABASE_URL", "https://ipinfo.io/data/ipinfo_lite.mmdb"), "database URL; the token is added as ?token=")
	interval := fs.Duration("interval", 24*time.Hour, "time between downloads")
	_ = fs.Parse(args)
	token := os.Getenv("IPINFO_TOKEN")
	if token == "" {
		slog.Error("IPINFO_TOKEN is not set")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client := &http.Client{Timeout: 10 * time.Minute}
	for {
		wait := *interval
		if err := fetch(ctx, client, *url+"?token="+token, *output); err != nil {
			// Never log the URL: it carries the token.
			slog.Error("database download failed; retrying in 15m", "error", err)
			wait = 15 * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func fetch(ctx context.Context, client *http.Client, url, output string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return errors.New("building request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", errors.Unwrap(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(output), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("writing %s: %w", tmp.Name(), err)
	}
	r, err := maxminddb.Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("downloaded file is not a valid database: %w", err)
	}
	_ = r.Close()
	if err := os.Rename(tmp.Name(), output); err != nil {
		return err
	}
	slog.Info("database updated", "path", output, "bytes", n)
	return nil
}
