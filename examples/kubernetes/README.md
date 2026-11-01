# eudi-dev on Kubernetes

Runs a wallet configured only with YAML files. The files become ConfigMaps, and the wallet reads them at startup. There is no database and no persistent volume. The wallet keeps its state in memory, so a restart goes back to what the files say.

Tested with kind and eudi-dev 3.6.1.

## The files

| Folder | Variable | Content |
|--------|----------|---------|
| `config/templates` | `EUDI_DEV_TEMPLATES_DIR` | The `employee-card` template and `pid-sdjwt`, which overrides the predefined EUDI PID |
| `config/credentials` | `EUDI_DEV_CREDENTIALS` | Alice's employee card, issued from the template on every start |
| `config/catalog` | `EUDI_DEV_CATALOG` | The employee card as an attestation type |
| `config/relying-parties` | `EUDI_DEV_RELYING_PARTIES` | Example Shop and Example Company as verifiers |

The wallet runs with `EUDI_DEV_DEMO=true`, so the credentials are its baseline. The baseline PID uses the template in `config/templates/pid-sdjwt.yaml`, and a demo reset restores everything. All 3 variants below use these files.

The image defaults to memory storage and the public seed `eudi-dev`. The seed keeps the keys the same across restarts, so certificates stay valid. Anyone can derive the same keys, so use this on test systems only.

## Variant 1: your own Helm chart

`chart/` is a small self-contained chart. Its `config` folder is a link to `../config`, because Helm reads only files inside a chart.

```bash
helm install eudi-dev examples/kubernetes/chart
kubectl port-forward deploy/eudi-dev 8085:8085
```

A changed file changes a checksum on the pod, so `helm upgrade` starts a new pod.

## Variant 2: Kustomize

`kustomization.yaml` sits in this folder because Kustomize reads only files below it. Every new file needs a line in `configMapGenerator`.

```bash
kubectl apply -k examples/kubernetes
kubectl port-forward deploy/eudi-dev 8085:8085
```

A changed file changes the hash in the ConfigMap name, so `kubectl apply -k` starts a new pod.

## Variant 3: the published chart

The [eudi-dev chart](https://github.com/eudi-dev/eudi-dev-helm) needs no templates of your own. Create the ConfigMaps from the files, then point the chart at them:

```bash
for name in templates credentials catalog relying-parties; do
  kubectl create configmap eudi-dev-$name --from-file=examples/kubernetes/config/$name
done
helm install eudi-dev oci://ghcr.io/eudi-dev/charts/eudi-dev --version 3.6.1 -f examples/kubernetes/published-chart/values.yaml
kubectl port-forward deploy/eudi-dev 8085:8085
```

The chart can also take the same content inline in its values, without separate ConfigMaps. A changed ConfigMap needs `kubectl rollout restart deploy/eudi-dev`.

## Check it

Open http://localhost:8085. The wallet shows the Example PID and the employee card.

```bash
curl -s localhost:8085/api/credentials
curl -s localhost:8085/api/catalog/attestations
curl -s localhost:8085/api/registrar/wrp
```

For a public URL, set `baseURL` in `chart/values.yaml` or `published-chart/values.yaml`, or `EUDI_DEV_BASE_URL` in `kustomize/deployment.yaml`.
