# Deploying lan-devices as a service

`lan-devices --watch` is a small daemon: it sweeps the LAN every minute, keeps a
record of every device it has ever seen, logs joins and departures, and serves
Prometheus metrics on `:9341`. This directory shows how to run it.

## Container

A multi-arch image (amd64, arm64) is published by CI on every push to master:

```
ghcr.io/jacobsim0/lan-devices:latest
ghcr.io/jacobsim0/lan-devices:<commit sha>
```

It must share the host's network namespace (the sweep lives on the LAN's layer 2,
not a container bridge) and needs exactly one capability, `NET_RAW`:

```bash
docker run -d --name lan-devices --restart unless-stopped \
  --network host --cap-drop ALL --cap-add NET_RAW \
  -v lan-devices:/data \
  ghcr.io/jacobsim0/lan-devices --watch
curl -s localhost:9341/metrics | head
```

State (learned names, first/last seen) is written to `/data`. To label devices,
mount a tab-separated `mac<TAB>name` file and point `LAN_DEVICES_ALIASES` at it.

## Kubernetes

`kubernetes.yaml` is a complete example for a cluster running the Prometheus
Operator (kube-prometheus-stack): Deployment with `hostNetwork`, a PVC for state,
a ConfigMap for aliases, a Service, a ServiceMonitor, and a PrometheusRule with
three alerts:

| Alert | Fires when |
|---|---|
| `UnknownDeviceJoined` | a device with no alias is online and was first seen in the last 10 minutes |
| `LanDevicesScannerStale` | no scan has completed in 5 minutes |
| `LanDevicesScannerDown` | the metrics endpoint is not being scraped |

`grafana-dashboard.json` is a small dashboard: online count, known count, unknown
devices online, scan duration, an online-over-time line, and a device table.
Import it through the Grafana UI, or wrap it in a ConfigMap labelled
`grafana_dashboard: "1"` if you run the kube-prometheus-stack sidecar.

The author's own lab deploys exactly this through Argo CD; see
[platform-gitops](https://github.com/jacobsim0/platform-gitops) for the GitOps wiring.
