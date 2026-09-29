# netflow-enricher

Adds names to NetFlow records passing through an [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/),
without a custom collector build. The collector sends batches to it over OTLP/HTTP; it adds attributes
and forwards the batch to the collector's next receiver.

| Attribute | From |
| --- | --- |
| `local.name` | Reverse DNS of `local.address` through one DNS server, e.g. a Pi-hole that forwards LAN PTR lookups to the DHCP server. Short name only (`noah-desktop`, not `noah-desktop.lan.`) |
| `remote.country`, `remote.country_name` | `remote.address` in [IPinfo's free Lite database](https://ipinfo.io/lite) |
| `remote.as.number`, `remote.as.name`, `remote.as.domain` | Same |

Only private addresses get a name and only public ones a country or AS; anything unknown is left
alone. It never blocks on DNS: an address not yet cached is looked up in the background, and its
flows go out unnamed until the name is known (cached 1h, misses 5m).

`local.address` and `remote.address` are not NetFlow fields; set them in the collector first (the
LAN end and the far end of each flow). The attribute names are configurable.

## Running it

```
netflow-enricher                # the server
netflow-enricher download       # keeps the IPinfo database fresh; run as a sidecar
```

| Variable | Default | |
| --- | --- | --- |
| `FORWARD_URL` | (required) | OTLP/HTTP logs endpoint to forward enriched batches to |
| `LISTEN` | `:4318` | Receives `POST /v1/logs`, OTLP JSON (gzip or not) |
| `METRICS_LISTEN` | `:9090` | `/metrics` and `/healthz` |
| `DNS_SERVER` | (none: no names) | `host:port` for reverse DNS |
| `GEO_DATABASE` | `/data/ipinfo_lite.mmdb` | Shared with the downloader |
| `LOCAL_ATTRIBUTE`, `REMOTE_ATTRIBUTE` | `local.address`, `remote.address` | |
| `IPINFO_TOKEN` | (downloader only) | Free token from ipinfo.io |

The server returns the collector's own response, so the collector sees real failures. A missing
database is not an error: flows go out without geo attributes until the downloader writes one, and
the server reloads it whenever the file changes.

## In the collector

The stock `failover` connector sends flows through the enricher, and straight on if it is down, so
an outage costs names, not flows. The exporter's queue and retries must be off, or its errors never
reach the connector.

```yaml
exporters:
  otlphttp/netflow-enricher:
    logs_endpoint: http://netflow-enricher:4318/v1/logs
    encoding: json
    compression: none
    sending_queue: {enabled: false}
    retry_on_failure: {enabled: false}
receivers:
  otlp/netflow-enriched:
    protocols: {http: {endpoint: 0.0.0.0:4321}}   # FORWARD_URL points here
connectors:
  failover/netflow:
    priority_levels:
      - [logs/netflow-enrich]
      - [logs/netflow-unenriched]
    retry_interval: 1m
service:
  pipelines:
    logs/netflow:                  # where the flows are labelled
      exporters: [failover/netflow]
    logs/netflow-enrich:
      receivers: [failover/netflow]
      exporters: [otlphttp/netflow-enricher]
    logs/netflow-unenriched:
      receivers: [failover/netflow]
      exporters: [loki, ...]       # the same destinations as below
    logs/netflow-enriched:
      receivers: [otlp/netflow-enriched]
      exporters: [loki, ...]
```

## Metrics

`netflow_enricher_records_total`, `netflow_enricher_requests_total{code}`,
`netflow_enricher_name_lookups_total{result}`, `netflow_enricher_geo_lookups_total{result}`, and
`netflow_enricher_geo_database_age_seconds` (-1 when no database is loaded).

## Image

`ghcr.io/noahsurprenant/netflow-enricher`, built for amd64 and arm64 on every push to `master`
(tags `master`, `latest`, `sha-…`) and on `v*` tags.
