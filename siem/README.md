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

The generated rules match normalized events shipped by
`detection/rules/firewall_events.py` (`job="ot_firewall"`, logfmt). Do not edit
the generated rule files by hand.
