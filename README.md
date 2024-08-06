<p align="center">
<a href="https://github.com/swrm-io/cert-manager-vultr/actions/workflows/github-code-scanning/codeql">
    <img alt="CodeQL Status" src="https://github.com/swrm-io/cert-manager-vultr/actions/workflows/github-code-scanning/codeql/badge.svg">
</a>
<a href="https://github.com/swrm-io/cert-manager-vultr/actions/workflows/go.yaml">
    <img alt="Docker Build" src="https://github.com/swrm-io/cert-manager-vultr/actions/workflows/go.yaml/badge.svg">
</a>
<a href="https://github.com/swrm-io/cert-manager-vultr/actions/workflows/build_docker.yaml">
    <img alt="Docker Build" src="https://github.com/swrm-io/cert-manager-vultr/actions/workflows/build_docker.yaml/badge.svg">
</a>



# Cert-Manager Webhook for Vultr DNS
Cert-Manager Webhook for working with [Vultr](https://www.vultr.com/) DNS.

## Installation

### Helm
```bash
helm repo add swrm-io https://swrm-io.github.io/helm-charts
helm repo update

helm upgrade --install cert-manager-vultr swrm-io/cert-manager-vultr
```

### Secret
Create a secret inside the cert-manager namespace containing your API key.

```yaml
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: vultr-credentials
  namespace: cert-manager
data:
  apiKey: <base64 encoded Vultr API Key>
```

### ClusterIssuer
Create an issuer that references the secret you created.  See [Cert-Manager ACME](https://cert-manager.io/docs/configuration/acme/)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    email: <your email address>
    privateKeySecretRef:
      name: letsencrypt
    server: https://acme-v02.api.letsencrypt.org/directory
    solvers:
    - dns01:
        webhook:
          config:
            apiKeySecretRef:
              key: apiKey
              name: vultr-credentials
          groupName: acme.vultr.com
          solverName: vultr
```