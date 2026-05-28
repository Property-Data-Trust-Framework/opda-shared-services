# opda-shared-services

Shared Go source for the two security components used by all OPDA API deployments. CI builds and publishes versioned Docker images to a shared ECR repository; per-API repos consume these images by tag.

## Binaries

### `cmd/mtls` — mTLS proxy (ECS Fargate)

Terminates TLS on port 443. For hostnames prefixed with `matls-`, enforces mutual TLS: requires a client certificate signed by a CA in the trusted list. Extracts the client certificate from the TLS handshake and injects it as a `Tls-Certificate` header before forwarding the request to the private API Gateway. Also enforces that a Bearer token is present before forwarding.

**Required environment variables:**

| Variable | Description |
|---|---|
| `PROXY_HOST_TARGET` | Private API Gateway invoke URL |
| `SSM_TRANSPORT_KEY_NAME` | SSM parameter name for the server private key PEM |
| `SSM_TRANSPORT_CERTIFICATE_NAME` | SSM parameter name for the server certificate PEM |
| `SSM_CA_TRUSTED_LIST_NAME` | SSM parameter name for the CA trusted list PEM bundle |
| `REGION` | AWS region |

### `authorizer` — Lambda authorizer

Custom API Gateway Lambda authorizer. On each request:
1. Extracts the Bearer token from the `Authorization` header
2. Introspects the token against the OAuth2 authorization server via mTLS
3. Validates certificate binding: computes `x5t#S256` of the `Tls-Certificate` header and checks it matches the `cnf.x5t#S256` claim in the introspection response
4. Returns an IAM Allow policy (with token claims in the Lambda context) or Deny

**Required environment variables:**

| Variable | Description |
|---|---|
| `INTROSPECTION_ENDPOINT` | OAuth2 token introspection URL |
| `CLIENT_ID` | OAuth2 client ID |
| `CLIENT_CERT_HEADER` | Header containing the client certificate (set to `Tls-Certificate`) |
| `SSM_TRANSPORT_KEY_NAME` | SSM parameter name for the mTLS client key PEM |
| `SSM_TRANSPORT_CERTIFICATE_NAME` | SSM parameter name for the mTLS client certificate PEM |
| `SSM_CA_TRUSTED_LIST_NAME` | SSM parameter name for the CA trusted list PEM bundle |

## Development

```bash
go test ./...
go build ./...
```

## Docker images

Both binaries are packaged as container images. The build context is the **repo root** so the full Go module is available.

```bash
# mTLS proxy
docker build -f cmd/mtls/Dockerfile -t opda-shared-services:mtls-<version> .

# Authorizer Lambda
docker build -f authorizer/Dockerfile -t opda-shared-services:authorizer-<version> .
```

CI tags images as `mtls-<git-tag>` and `authorizer-<git-tag>` and pushes to the shared ECR repository.

## Using as a git submodule (local development)

Per-API repos can reference this repo as a submodule to build images locally without pulling from ECR:

```bash
# In a per-API repo
git submodule add https://github.com/Property-Data-Trust-Framework/opda-shared-services shared-services
git submodule update --init
```

Then build with `docker build -f shared-services/cmd/mtls/Dockerfile shared-services/`.
