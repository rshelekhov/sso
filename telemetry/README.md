# Telemetry Configuration Files

Configuration files for the observability stack used in the SSO application.

## Architecture Overview

```
SSO Application (gRPC)
  ↓ OTLP (ports 4317/4318)
OpenTelemetry Collector (central hub)
  ├─→ Prometheus (metrics)
  ├─→ Loki (logs)
  └─→ Tempo (traces)
  ↓ ↓ ↓
Grafana (unified dashboard)
```

## Data Flow

### Metrics Flow

```
SSO App → OTEL Collector → Prometheus → Grafana
```

### Logs Flow

```
SSO App → OTEL Collector → Loki → Grafana
Other services → Promtail → Loki → Grafana  (legacy/system logs)
```

### Traces Flow

```
SSO App → OTEL Collector → Tempo → Grafana
```

## Configuration Files Overview

### Core Components

#### `otel-collector-config.yaml` - Central Data Router

- **Receivers**: OTLP (gRPC:4317, HTTP:4318)
- **Processors**: Batching, memory limiting, resource enrichment
- **Exporters**:
  - Prometheus (metrics on port 8889)
  - Loki (logs to http://loki:3100)
  - Tempo (traces to tempo:9096)
  - Debug (console output)

#### `prometheus.yml` - Metrics Collection

Scrapes metrics from:

- OTEL Collector (port 8889) - **SSO app metrics**
- Prometheus itself (port 9090)
- Grafana (port 3000)
- Tempo (port 3200)
- Loki (port 3100)
- System services (if exporters added)

#### `loki-config.yaml` - Log Storage

- HTTP API: port 3100, gRPC: port 9096
- Storage: Local filesystem (`/tmp/loki`)
- Schema: v13 with 24h indexing period
- Authentication: disabled (dev environment)

#### `tempo-config.yaml` - Trace Storage

- OTLP receiver: ports 9096 (gRPC), 9097 (HTTP)
- Storage: Local filesystem (`/tmp/tempo`)
- Features: Service graphs, span metrics
- Integration: Forwards metrics to Prometheus

#### `promtail-config.yaml` - Log Collection Agent

Collects logs from:

- Docker containers (with service discovery)
- System logs (`/var/log/*`)
- SSO application files (if configured)
  Parsing: JSON logs, log levels, timestamps

#### `grafana/provisioning/` - Dashboard Setup

- **datasources**: Auto-configures Loki, Prometheus, Tempo
- **dashboards**: Placeholder for custom dashboards

## Access Points

After running `docker compose up -d`:

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Loki**: http://localhost:3100
- **Tempo**: http://localhost:3200
- **Promtail**: http://localhost:9080

## Key Improvements

### Modern Observability

- **OTLP Integration**: SSO sends structured telemetry via OpenTelemetry
- **Correlation**: Logs linked to traces via `trace_id`
- **Unified Pipeline**: All telemetry through OTEL Collector
- **Data Enrichment**: Automatic labels and metadata

### Data Flow Options

1. **Modern**: SSO → OTEL Collector → Backends
2. **Legacy**: Services → Promtail → Loki (for system logs)

## Integration with SSO Application

The SSO application sends telemetry via OTLP to the OpenTelemetry Collector:

### Configuration

```yaml
# In config/config.docker.yaml
App:
  OTLPEndpoint: "otel-collector:4317"  # Inside Docker network

# In config/config.test.yaml
App:
  OTLPEndpoint: "localhost:4317"       # From host to Docker
```

### Telemetry Types

- **Metrics**: HTTP requests, database queries, cache hits
- **Logs**: Structured JSON with levels, correlation IDs
- **Traces**: Request flows through gRPC handlers, database calls

## Development Workflow

### Quick Start

```bash
# Start observability stack (order matters!)
docker compose up -d prometheus loki tempo
docker compose up -d otel-collector
docker compose up -d grafana

# Start SSO with telemetry
docker compose up -d sso

# Check everything is working
./scripts/check-observability.sh

# View in Grafana
open http://localhost:3000
```

### Alternative: Start Everything

```bash
# Start all services at once
docker compose up -d

# Wait for services to be ready (30-60 seconds)
sleep 60

# Check health
./scripts/check-observability.sh
```

### Debugging Telemetry

```bash
# Check OTEL Collector is receiving data
docker compose logs otel-collector | grep "Everything is ready"

# Check specific pipeline logs
docker compose logs otel-collector | grep -E "(loki|prometheus|tempo)"

# Verify SSO is sending data
docker compose logs sso | grep -i otel
```

### Query Examples

**Loki (Logs):**

```
{service="sso"}                          # All SSO logs
{service="sso",level="ERROR"}            # SSO errors only
{container="sso-postgres-1"}             # PostgreSQL logs
```

**Prometheus (Metrics):**

```
http_requests_total                      # HTTP request count
up{job="otel-collector"}                 # Service health
rate(http_requests_total[5m])            # Request rate
```

**Tempo (Traces):**

- Search by service name: `sso`
- Search by trace ID from logs
- View service dependency graph

## Customization

### Adding New Log Sources

Edit `promtail-config.yaml`:

```yaml
scrape_configs:
  - job_name: my-service
    static_configs:
      - targets: [localhost]
        labels:
          job: my-service
          __path__: /var/log/my-service/*.log
```

### Adding New Metrics Targets

Edit `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "my-service"
    static_configs:
      - targets: ["my-service:8080"]
    metrics_path: /metrics
```

### Adding Custom Dashboards

Place JSON files in `grafana/provisioning/dashboards/`

## Troubleshooting

### Common Issues

**No SSO logs in Loki:**

```bash
# Check OTEL Collector Loki exporter
docker compose logs otel-collector | grep loki

# Verify SSO is sending logs via OTLP
docker compose logs sso | grep -i log
```

**Missing correlation between logs and traces:**

- Ensure SSO app includes `trace_id` in log entries
- Check OTEL SDK configuration in SSO application

**High memory usage:**

- Adjust `memory_limiter` in `otel-collector-config.yaml`
- Configure retention policies in Loki and Tempo

For more details, see the main [README.md](../README.md) troubleshooting section.
