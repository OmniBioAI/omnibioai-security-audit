# OmniBioAI Security Audit System

A high-performance, Redis Streams–based audit logging and event streaming system for the OmniBioAI ecosystem. It provides **zero-trust observability**, **HPC-safe audit trails**, and **real-time security event processing** across distributed services.

---

## Overview

The audit system captures and streams security-relevant events from:

* Authentication service
* IAM client (token validation, cache hits/misses)
* Policy engine (RBAC/ABAC decisions)
* Workflow execution (TES, HPC jobs)
* Control plane operations

It is designed for:

* Low-overhead, non-blocking event publication
* Distributed microservices
* HPC-scale workloads
* Zero-trust architectures

---

## Architecture

```
Services (Auth / IAM / Policy / TES)
            │
            ▼
     Audit Logger (async)
            │
            ▼
   Redis Streams (audit:events)
            │
    ┌───────┴────────┐
    ▼                ▼
Stream Consumers   Sink Layer (implemented today)
(processors)       worker/main.py + consumers/sink.py write into a
                    MySQL-backed store (db/models.py, Alembic-migrated)
                    │
                    ▼
              GET /audit/events — platform-admin-gated query API
              (see "API Endpoints" below)
```

A DB sink and a queryable read API already exist — "Future Sink Layer"
in earlier revisions of this diagram undersold what's shipped; the
Roadmap's remaining "OpenSearch / additional sink backends" item is
about backends *beyond* MySQL, not the first one.

---

## Authentication

This service produces audit events; it does not authenticate end users
itself. It has two touchpoints with the ecosystem's JWT identity layer,
both delegating verification to a local copy of the same shared logic
`omnibioai-control-center` uses (`audit/jwt_verify.py`, structurally
identical to that repo's `core/jwt_verify.py` — see
[omnibioai-auth's README](../omnibioai-auth#jwt) for the token model both
verify against).

### Platform admin authentication

`api/deps.py::require_platform_admin` gates this service's own read APIs
(audit query/search endpoints). It parses the `Authorization` header,
delegates full verification to `jwt_verify.verify_token`, and then makes
its own authorization decision: 401 if the token itself is invalid, 403
if it's valid but lacks the `platform_admin` role. Audit records are
platform-admin only — never exposed to organization admins — since they
contain security-sensitive activity across the whole platform, not scoped
to any one org. Unlike `omnibioai-auth`, this service has no database
access to resolve a *permission* from a role name, so it checks for the
literal seeded `platform_admin` role, the same pattern
`omnibioai-control-center`'s `require_admin` uses for `admin`.

A second, non-HTTP touchpoint exists for audit producers running
in-process rather than behind a FastAPI request: `audit/identity.py::validate_identity_token`
verifies a caller-supplied access token (also via `jwt_verify.verify_token`)
before attributing an audit event to that identity — never raises, a
verification failure just means the event is logged without a verified
identity rather than blocking the caller's request. This is what stops an
in-process caller from attributing an audit event to an arbitrary,
unverified `user_id` string.

### Shared JWT verification

`audit/jwt_verify.py::verify_token` is the single place in this repo that
fully verifies a token — signature, expiry, token type (rejects a
presented refresh token), the required `sub` claim, and Redis
jti-blacklist revocation. Both `require_platform_admin` and
`validate_identity_token` delegate to it rather than each doing their own
partial decode, which is exactly the gap this module closed (see the
module's own docstring for the history).

### Redis blacklist

The same jti-blacklist `omnibioai-auth` writes to on logout
(`blacklist:jti:{jti}`) is checked here directly against the same Redis
instance (`AuditConfig.REDIS_URL`) — **fail-open** on a Redis error,
deliberately matching auth-service's own documented tradeoff: a Redis
blip must not 401 every platform-admin request in this service either.

### HS256 compatibility

HS256 — the production default everywhere in the ecosystem today — is
fully supported and unaffected by RS256 readiness below: an HS256 token's
own `alg` header routes it straight to the existing shared-secret
verification path, exactly as before.

### RS256 compatibility

`jwt_verify.py` also verifies RS256 tokens against `omnibioai-auth`'s
`GET /.well-known/jwks.json`, dispatched by each token's own `alg` header
rather than by local configuration — so this service is ready to verify
RS256 tokens the moment `omnibioai-auth` is switched to issue them,
without a corresponding deploy here. The JWKS client is a cached,
auto-refreshing lookup by `kid` (refreshes once on an unknown `kid`, e.g.
after key rotation); any signature or JWKS-fetch failure fails closed —
there is no path that accepts a token without a verified signature. No
production deployment has switched issuance to RS256 yet — see the
[ecosystem root README](../omnibioai#deployment-notes)'s Deployment Notes.

---

## Key Features

### 🚀 High Performance

* Async non-blocking logging
* Redis Streams backbone
* Minimal overhead on critical paths

### 🔐 Zero Trust Observability

* Every decision is logged
* Full traceability of:

  * user actions
  * policy decisions
  * system events

### 🧬 HPC-Aware Design

* Safe for large-scale distributed compute
* Designed for workflow engines like TES
* Handles thousands of concurrent events

### 📡 Real-time Streaming

* Redis Streams allow replayable audit logs
* Consumer pipeline ready for scaling

---

## Event Types

Examples of events tracked (the event type is extensible):

* `auth_login`
* `auth_failed`
* `iam_cache_hit`
* `iam_cache_miss`
* `policy_decision`
* `tes_submit`
* `tes_complete`

---

## Running

### Via OmniBioAI Studio (recommended)

```bash
cd ~/Desktop/machine/omnibioai-studio
docker compose up -d security-audit
```

Access (internal only):
`http://security-audit:8004` (Docker internal network)

### Health check

```bash
curl http://localhost:8004/health
# {"status": "ok"}
```

### API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | — | Health check |
| `/audit/test` | GET | none today | Write-side ingestion smoke test |
| `/audit/events` | GET | `platform_admin` role | Query audit events — `page`/`page_size`, plus optional `user_id`/`service`/`event_type`/`decision`/`integrity_status`/`from_timestamp`/`to_timestamp` filters |

`/audit/events` is deliberately a separate router from `/audit/test` —
the former is the platform-admin-gated read API (see "Platform admin
authentication" above), the latter has no auth at all today.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis Streams backend |
| `AUDIT_STREAM` | `audit:events` | Stream name |
| `SERVICE_NAME` | `unknown-service` | Service identifier included in emitted events |
| `AUDIT_MAXLEN` | `1000000` | Max stream length |
| `AUDIT_DATABASE_URL` | `mysql+pymysql://root:root@localhost:3306/omnibioai_audit` | Durable audit-event store the consumer writes into and `/audit/events` queries |
| `AUDIT_CONSUMER_GROUP` | `audit-workers` | Redis Streams consumer group name |
| `AUDIT_CONSUMER_NAME` | `worker-{pid}` | Per-process consumer identity within the group |
| `AUDIT_PEL_MIN_IDLE_MS` | `30000` | How long a delivered-but-unacked message must sit idle before any worker (this one or another replica) may reclaim it — see `worker/main.py::sweep_pending` |
| `AUDIT_PEL_MAX_DELIVERIES` | `5` | Delivery attempts (original + reclaims) before an entry is treated as poison and ACKed without further processing |
| `AUDIT_PEL_SWEEP_BATCH` | `100` | Max stale Pending Entries List entries inspected per sweep |
| `JWT_SECRET` | `change-me` *(development only)* | HS256 signing/verification secret; production must set the value used by `omnibioai-auth` |
| `IAM_URL` | `http://omnibioai-auth:8000` | Auth service URL used for RS256/JWKS verification |

`JWT_SECRET=change-me` is for development only. Production deployments
must provide a secure secret consistent with the authentication service's
HS256 signing configuration. Invalid or missing tokens return `401`; valid
tokens without the literal `platform_admin` role return `403` for the audit
query API.

---

## Usage

### Initialize Logger

```python
from audit.logger import AuditLogger
from audit.models import AuditEvent
from audit.config import AuditConfig

logger = AuditLogger()
```

---

### Log an Event

```python
await logger.log(
    AuditEvent(
        service="auth-service",
        event_type="auth_login",
        user_id="user_123",
        action="login",
        decision="success",
    )
)
```

---

## FastAPI Integration

```python
from fastapi import APIRouter
from audit.logger import AuditLogger

router = APIRouter()
logger = AuditLogger()

@router.post("/login")
async def login():
    await logger.log(...)
```

---

## Stream Consumer

Read audit events:

```python
from consumers.stream_reader import StreamReader

reader = StreamReader()

data = reader.read()
print(data)
```

### Run the worker locally

The durable consumer runs separately from the FastAPI application:

```bash
python -m worker.main
```

It creates the configured Redis consumer group, reads new events, persists
them to MySQL, acknowledges successfully handled messages, and reclaims
stale Pending Entries List messages. Configure `REDIS_URL` and
`AUDIT_DATABASE_URL` before starting it.

---

## Consumer Pipeline

You can extend consumers for:

* anomaly detection
* security alerts
* analytics dashboards
* compliance reporting

---

## Testing

```bash
cd ~/Desktop/machine/omnibioai-security-audit
pytest tests/ -v --cov=.

# Covers the audit logger, stream reader, decorators, context management,
# event types, API routes, and worker behavior. Review the measured coverage
# output rather than relying on a fixed percentage claim.
```

---

## Design Principles

### 1. Never block core execution

Audit failure must NOT break system flow.

### 2. Append-only logs

Redis Streams provide append-only event delivery, while the MySQL sink is the
durable source of truth for retained audit history.

### 3. Distributed-first

Works across:

* local dev
* HPC clusters
* cloud microservices

### 4. Traceability-first design

Every event supports:

* trace_id
* user_id
* service context

---

## Integration with OmniBioAI Ecosystem

This service integrates with:

* omnibioai-auth
* omnibioai-iam-client
* omnibioai-policy-engine

---

## Roadmap

| Feature | Status |
|---------|--------|
| Redis Streams audit backbone | ✓ Stable |
| Async non-blocking logging | ✓ Stable |
| Fail-open design | ✓ Stable |
| Distributed trace ID support | ✓ Stable |
| Broad automated test coverage | ✓ Stable |
| MySQL sink + queryable read API (`worker/`, `db/`, `/audit/events`) | ✓ Stable |
| OpenSearch / additional sink backends | Planned |
| Real-time security dashboard | Planned |
| AI-based anomaly detection | Planned v0.5 |
| Compliance reporting engine | Planned v0.5 |

---

## Related Services

| Service | Role |
|---------|------|
| `omnibioai-api-gateway` | Fires audit events on every request |
| `omnibioai-auth` | Fires auth_login / auth_failed events |
| `omnibioai-policy-engine` | Fires policy_decision events |
| `omnibioai-iam-client` | Fires iam_cache_hit / iam_cache_miss events |
| `omnibioai-security-sdk` | Provides fire_audit() helper used by all services |
| `omnibioai-studio` | Manages security-audit container lifecycle |

---

## License

Apache 2.0
