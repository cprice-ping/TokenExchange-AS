# RFC 8693 Token Exchange Authorization Server

Standalone FastAPI authorization server for OAuth 2.0 Token Exchange (RFC 8693). It cryptographically validates JWTs using each token's OIDC issuer/JWKS, asks PingOne Authorize for the final trust and delegation decision, and mints a short-lived signed JWT for a downstream resource server.

## Delegated Agent semantics

For the initial on-behalf-of exchange, send the human JWT as `subject_token` and the verified Agent/workload JWT as `actor_token`. For follow-on exchanges, `actor_token` is optional: send the previously issued OBO token as the `subject_token` with a new requested audience and scope. P1AZ authorizes both forms. The resulting JWT has:

```json
{
  "sub": "human-id",
  "act": { "sub": "agent-id" }
}
```

`sub` is the delegating human. `act.sub` is the Agent currently acting on their behalf. The server never copies arbitrary roles, groups, or permissions from input tokens.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

The service has no database or admin UI. Configure all credentials and policy through environment variables. JWT validation derives the issuer from each token and performs safe OIDC discovery/JWKS verification. Opaque access tokens use RFC 7662 through `INTROSPECTION_ISSUER`; PingOne Authorize makes the final trust/delegation decision. The development `.env.example` enables HTTP only for local test issuers. Production issuers must use HTTPS and resolve outside private/link-local networks.

## Exchange request

```bash
curl -u "$TOKEN_CLIENT_ID:$TOKEN_CLIENT_SECRET" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  -d 'subject_token=<human-jwt>' \
  -d 'actor_token_type=urn:ietf:params:oauth:token-type:jwt' \
  -d 'actor_token=<agent-jwt>' \
  -d 'audience=gateway' -d 'scope=use_gateway' \
  http://localhost:8000/as/token
```

Metadata is at `/.well-known/oauth-authorization-server`; signing keys are at `/as/jwks`; health is at `/healthz`.

## Security boundary

This is an authorization-server component, not a complete production IAM deployment. Use TLS, environment/KMS-backed secrets, a stable KMS/HSM or mounted signing key, rate limiting, key rotation, and audited deployment configuration in production. The service is stateless and exposes only the token, metadata, JWKS, and health endpoints. Never log or persist bearer tokens.

## Kubernetes deployment

The `k8s/` directory contains templates for a hardened public deployment into an existing application namespace. Replace `REPLACE_WITH_EXISTING_NAMESPACE`, `as.example.com`, the image digest, certificate issuer, PingOne environment/decision values, and secret placeholders before applying. `k8s/namespace.yaml` is documentation only; it does not create a namespace. Do not apply `k8s/secret.example.yaml` with placeholder values.

```bash
kubectl apply --server-side --dry-run=server -f k8s/secret.example.yaml -f k8s/deployment.yaml -f k8s/service.yaml -f k8s/pdb.yaml -f k8s/ingress.yaml
# Replace placeholders first, then apply the Secret through your secret manager.
kubectl apply -f k8s/secret.example.yaml
kubectl apply -f k8s/deployment.yaml k8s/service.yaml k8s/pdb.yaml k8s/ingress.yaml
kubectl -n <existing-namespace> rollout status deploy/token-as --timeout=5m
```

Set `AS_ISSUER` to the exact public HTTPS URL used by the Ingress. Mount the same stable RSA private key into every replica and set a stable `SIGNING_KEY_ID`; otherwise resource servers will not be able to validate tokens consistently. Prefer External Secrets/KMS over committing Secret manifests. During key rotation, publish both old and new public keys for at least the token lifetime plus downstream JWKS cache duration.

### Create the signing-key Secret

For a Kubernetes Secret fallback, generate the RSA private key outside the cluster and keep it out of Git:

```bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing-key.pem
chmod 600 signing-key.pem
```

Create the Secret in the existing target namespace, using the same key ID configured in the Deployment:

```bash
kubectl -n <existing-namespace> create secret generic token-as-signing-key-2026-08 \\
  --from-file=signing-key.pem=./signing-key.pem \\
  --dry-run=client -o yaml | kubectl apply -f -
```

The Deployment mounts that key at `/var/run/token-as/signing-key/signing-key.pem` and sets `SIGNING_KEY_ID=as-2026-08`. Do not put the PEM contents in `k8s/secret.example.yaml`, commit the generated file, or print it in CI logs. For production, prefer KMS/HSM or External Secrets/Secret Store CSI. Keep a versioned Secret during rotation; do not replace a live key until the old public key has remained available for the token lifetime plus downstream JWKS cache duration.

Smoke-test the public surface:

```bash
curl -fsS https://as.example.com/healthz
curl -fsS https://as.example.com/.well-known/oauth-authorization-server
curl -fsS https://as.example.com/as/jwks
```

The standard Kubernetes NetworkPolicy cannot restrict arbitrary public HTTPS destinations by hostname. Use a Cilium FQDN policy or an egress proxy/allowlist for PingOne and OIDC hosts; do not treat unrestricted egress as a production SSRF control.
