# Standalone Kubernetes demo

The demo manifest deploys an isolated scia proxy and echo upstream in the
`scia` namespace. It does not modify the existing `scia` deployment.

Create the admin token before applying the manifest:

```sh
kubectl create secret generic scia-demo-admin \
  --namespace scia \
  --from-literal="token=$(openssl rand -hex 24)"
kubectl apply -f deploy/standalone-demo.yaml
```

Access the console without publicly exposing the forward proxy:

```sh
kubectl port-forward --namespace scia service/scia-demo 18082:8080
```

Open <http://localhost:18082/>. Retrieve the admin token with:

```sh
kubectl get secret scia-demo-admin --namespace scia \
  --output jsonpath='{.data.token}' | base64 --decode
```

In the console, store `hello-from-scia` using credential ID `demo-api` and
input ID `token`. Verify injection through the local port-forward:

```sh
curl --noproxy '' --proxy http://localhost:18082 \
  http://scia-demo-upstream/
```

The response contains `Authorization: Bearer hello-from-scia`.

