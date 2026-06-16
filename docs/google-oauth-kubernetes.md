# Google OAuth on Kubernetes

The `scia` deployment in the `scia` namespace is prepared to read a Google OAuth
client from a Kubernetes Secret named `scia-google-oauth`.

Create the Secret yourself with these keys:

```sh
kubectl create secret generic scia-google-oauth \
  -n scia \
  --from-literal=client-id='YOUR_GOOGLE_OAUTH_CLIENT_ID' \
  --from-literal=client-secret='YOUR_GOOGLE_OAUTH_CLIENT_SECRET'
```

The deployment reads those keys into:

- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`

The config references them as:

```yaml
server:
  oauth:
    redirectUrl: "http://localhost:18081/oauth/google/callback"
    google:
      credentialId: google-calendar
      clientId: "env:GOOGLE_OAUTH_CLIENT_ID"
      clientSecret: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      scope: "https://www.googleapis.com/auth/calendar.readonly"
```

Register this redirect URI on the Google OAuth client:

```text
http://localhost:18081/oauth/google/callback
```

After creating or changing the Secret, restart the deployment so the environment
variables are loaded:

```sh
kubectl rollout restart deployment/scia -n scia
kubectl rollout status deployment/scia -n scia
```

For local browser authorization, forward the OAuth service:

```sh
kubectl port-forward -n scia svc/scia-oauth 18081:8081
```

Open:

```text
http://localhost:18081/
```

After authorization, `scia` stores the Google refresh token in the SQLite secret
store on the persistent volume. Requests through `scia-proxy` to
`www.googleapis.com` under `/calendar/v3/*` receive an injected access token.

For a quick proxy test, also forward the proxy service:

```sh
kubectl port-forward -n scia svc/scia-proxy 18080:8080
curl --noproxy '' -x http://localhost:18080 \
  https://www.googleapis.com/calendar/v3/users/me/calendarList
```
