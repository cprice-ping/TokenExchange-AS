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

## PingOne Authorize decision request

The token exchange service sends a decision request to the configured PingOne Authorize decision endpoint after validating the inbound token(s). The request uses an isolated `Request.TokenExchange` attribute namespace so the policy can distinguish token-exchange inputs from other policy requests:

```json
{
  "parameters": {
    "Request.TokenExchange.Subject.sub": "2ece0764-93cc-426c-980d-152f824928b1",
    "Request.TokenExchange.Subject.iss": "https://auth.pingone.com/<environment-id>/as",
    "Request.TokenExchange.Subject.token_type": "urn:ietf:params:oauth:token-type:jwt",
    "Request.TokenExchange.Actor.sub": "system:serviceaccount:namespace:agent",
    "Request.TokenExchange.Actor.iss": "https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>",
    "Request.TokenExchange.Actor.token_type": "urn:ietf:params:oauth:token-type:jwt",
    "Request.TokenExchange.aud": "gateway",
    "Request.TokenExchange.scope": "use_gateway"
  }
}
```

The HTTP request is:

```http
POST https://api.pingone.com/v1/environments/<environment-id>/decisionEndpoints/<decision-endpoint-id>
Authorization: Bearer <PingOne Worker token>
Content-Type: application/json
```

The Worker token is obtained with a server-side `client_credentials` request and no requested scope. Only a decision response containing `decision: "PERMIT"` allows the service to mint the exchanged JWT.

For a follow-on exchange using an existing OBO token, `actor_token` is omitted. In that case the request contains the subject and requested `aud`/`scope`, but no `Request.TokenExchange.Actor.*` parameters:

```json
{
  "parameters": {
    "Request.TokenExchange.Subject.sub": "2ece0764-93cc-426c-980d-152f824928b1",
    "Request.TokenExchange.Subject.iss": "https://token-exchange.example.com",
    "Request.TokenExchange.Subject.token_type": "urn:ietf:params:oauth:token-type:jwt",
    "Request.TokenExchange.Actor.token_type": "",
    "Request.TokenExchange.aud": "profile-api",
    "Request.TokenExchange.scope": "read_profile"
  }
}
```

When a token is declared as `urn:ietf:params:oauth:token-type:access_token`, the service sends its raw value as `Request.TokenExchange.Subject.token` (or `Request.TokenExchange.Actor.token`) in the same decision request:

```json
{
  "parameters": {
    "Request.TokenExchange.Subject.sub": "2ece0764-93cc-426c-980d-152f824928b1",
    "Request.TokenExchange.Subject.iss": "https://auth.pingone.com/<environment-id>/as",
    "Request.TokenExchange.Subject.token_type": "urn:ietf:params:oauth:token-type:access_token",
    "Request.TokenExchange.Subject.token": "<raw access token>",
    "Request.TokenExchange.Actor.token_type": "",
    "Request.TokenExchange.aud": "gateway",
    "Request.TokenExchange.scope": "use_gateway"
  }
}
```

The `token_type` parameters are always present (empty string when there is no actor token). The `token` parameters are present only for `access_token`-declared inputs: JWT inputs were already validated locally against their issuer's JWKS and are never sent to PingOne Authorize. The policy introspects declared access tokens at their issuer (RFC 7662) and makes the final trust/delegation decision.

The P1AZ snapshot in [`p1az/TokenExchange.snapshot`](p1az/TokenExchange.snapshot) defines the corresponding `Request.TokenExchange` attributes (including `token_type` and `token`), the token-introspection services the policy calls for `access_token`-declared inputs, and policy checks for trusted issuers, requested audiences, and requested scopes. The snapshot is a policy reference only; the service sends the decision request at runtime and does not make those authorization decisions locally.

## Environment variables

The service is configured entirely through environment variables. Secrets should come from Kubernetes Secrets, External Secrets, KMS/HSM integration, or another secret manager—not from committed files.

| Variable | Required | Description |
|---|---:|---|
| `AS_ISSUER` | Yes | Canonical public issuer URL placed in minted JWTs and authorization-server metadata. Use the HTTPS Ingress FQDN without a trailing slash. |
| `TOKEN_CLIENT_ID` | Yes | OAuth client ID accepted by the RFC 8693 token endpoint. |
| `TOKEN_CLIENT_SECRET` | Yes | OAuth client secret for RFC 8693 HTTP Basic authentication. |
| `TOKEN_TTL_SECONDS` | No | Requested lifetime, in seconds, for minted tokens. Default: `300`. |
| `TOKEN_MAX_TTL_SECONDS` | No | Hard upper bound on minted-token lifetime. Default: `300`. |
| `SIGNING_KEY_PATH` | Yes in production | Read-only path to the RSA private PEM used to sign output JWTs. Mount from a Secret/KMS integration. |
| `SIGNING_KEY_ALGORITHM` | No | Signing algorithm. Currently `RS256`. |
| `SIGNING_KEY_ID` | Yes in production | Stable JWT `kid` published by `/as/jwks`. All replicas must use the same key and ID. |
| `CLOCK_SKEW_SECONDS` | No | Clock-skew allowance for inbound JWT validation. Default: `30`. |
| `ALLOW_INSECURE_HTTP` | No | Allows HTTP issuer discovery for local development only. Set `false` in production. |
| `P1AZ_MODE` | Yes | Must be `enforce` for production; disabled/unavailable policy evaluation fails closed. |
| `P1AZ_AUTH_BASE` | No | PingOne authorization-server base URL used to obtain the Worker token. Default: `https://auth.pingone.com`. |
| `P1AZ_API_BASE` | No | PingOne API base URL used for decision evaluation. Default: `https://api.pingone.com/v1`. |
| `P1AZ_ENVIRONMENT_ID` | Yes | PingOne environment containing the Worker application and decision endpoint. |
| `P1AZ_DECISION_ENDPOINT_ID` | Yes | PingOne Authorize decision endpoint used for token-exchange policy. |
| `P1AZ_WORKER_CLIENT_ID` | Yes | PingOne Worker application client ID. |
| `P1AZ_WORKER_CLIENT_SECRET` | Yes | PingOne Worker application secret. The Worker token request uses `client_credentials` with no scope. |
| `P1AZ_TIMEOUT_SECONDS` | No | Timeout for Worker-token and decision calls. Default: `5`. |
| `P1AZ_TOKEN_SAFETY_SECONDS` | No | Refresh margin before a cached Worker token expires. Default: `60`. |

`P1AZ_WORKER_CLIENT_SECRET`, `TOKEN_CLIENT_SECRET`, and the signing key are sensitive. Never log, commit, or include them in image layers. `P1AZ_WORKER_CLIENT_ID` is also an operational credential and should be injected from deployment secrets where practical.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

The service has no database or admin UI. Configure all credentials and policy through environment variables. JWT validation derives the issuer from each token and performs safe OIDC discovery/JWKS verification. Declared `access_token` inputs are opaque to this service: their raw values are sent to PingOne Authorize, which performs RFC 7662 introspection at the issuer and makes the trust decision. The development `.env.example` enables HTTP only for local test issuers. Production issuers must use HTTPS and resolve outside private/link-local networks.

## Token validation

The declared RFC 8693 token type selects the validation method:

| Token type | Validation |
|---|---|
| `urn:ietf:params:oauth:token-type:jwt` | OIDC discovery, JWKS lookup, algorithm/key selection, signature verification, issuer, expiry, issued-at, and claim-shape checks |
| `urn:ietf:params:oauth:token-type:access_token` | Sent to PingOne Authorize as `Request.TokenExchange.<Subject/Actor>.token`; the policy validates it by introspecting it at the issuer (RFC 7662) and fails closed |

An `access_token` is never validated locally, even when it is JWT-shaped: the service does not use its JWKS path for that declared type. The policy is the sole validator for that token type. The value must still be decodable as a JWT so its claims can be propagated into the minted token; a non-JWT value fails closed locally. Support for fully opaque values (identity resolved from the P1AZ decision response instead of a local decode) is not implemented.

On `PERMIT`, the identity claims in the minted token (`sub`, `act.sub`) come from the service's own decode of the same raw token, not from the decision response — the service never reads claims back from PingOne Authorize. `PERMIT` means the policy validated the token (introspection returned `active` at the token's issuer); the propagated claims are the service's read of those same bytes, which the issuer attests by returning `active: true` for a token it issued. Taking outbound identity from claims returned in the decision response is not implemented.

The service performs authentication and token-shape validation only. It does not locally authorize issuer trust, subject/Agent delegation, requested audience, or requested scope. Those decisions are sent to PingOne Authorize, and only `PERMIT` results in a minted token.


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
