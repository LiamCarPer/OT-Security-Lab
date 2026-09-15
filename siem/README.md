# SIEM stack

Grafana + Loki + Promtail + Alertmanager for the lab. Loki stores the lab's
detector alerts, evaluates the alerting rules, and now also evaluates the
generated detection bundle.

## Generated ruler rules (`rules/`)

The files in `rules/` are the lab's Loki ruler rules. `alerting-rules.yml` is
hand-written; the `ot_*.yaml` bundle is generated, not authored here. It is
produced by `pipelines/deploy.py` in
[ot-detection-engineering](https://github.com/LiamCarPer/ot-detection-engineering)
and copied from its `deploy/loki/rules/` output.

- **Source commit:** `da0c8b587ac9bd0048d09700a539b81b77e12dac`
- **Regenerate:** in that repository, `make deploy`, then refresh this directory.
- **Mounted by:** `lab-environment/docker-compose.yml`, read-only, at
  `/etc/loki/rules/fake` (tenant `fake` because `auth_enabled` is false). The
  local ruler reads every file in the tenant directory and does not recurse, so
  all rules sit flat here and no other files may be present.
  `configs/loki-config.yaml` enables the ruler.

The generated rules match normalized events shipped by the lab's telemetry
producers: `detection/rules/firewall_events.py` emits `ot_firewall` events, and
`detection/rules/{dnp3,opcua,s7comm}_dpi.py` emit the `ot_ndr` DNP3/OPC UA/S7comm
contracts (plus `process_safety_violation.py` emitting `ot_process`). All of them
push `logfmt` lines to Loki, so the generated ruler rules fire on live lab
traffic. Do not edit the generated rule files by hand.

## Historian

Grafana also has an **InfluxDB-Historian** datasource (`influxdb` type) pointing
at `http://172.23.0.10:8086` (database `ot_data`). The `grafana-route` sidecar
installs the Level 3 route in Grafana's network namespace so this datasource
traverses conduit C4; the `Process Historian (InfluxDB)` dashboard
(`dashboards/historian_process.json`) plots the `process_state` measurement.
