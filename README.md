# ATLAS FORGE

Defensive-security flagship framework. Public repository. No AI branding.
Real endpoints with verifiable scoring. Score floor: >=80/100.

## Endpoints
- `GET /health` — defensive-active confirmation
- `GET /scan` — security scan
- `GET /audit` — audit trigger
- `GET /audit-log` — persistent audit trail
- `GET /score` — defensive score (base 50 + headers 15 + deep 10 + audit 15 + redacted 10 = 100; verified >=80)
- `GET /docs` — OpenAPI docs

## Routing
omniroute / NVIDIA free / hermes / openrouter / free. Experiential gateway removed.

## Security Layers
1. Input validation (Pydantic / regex)
2. Rate limiting (per-IP, 60s window, max 10 req)
3. Security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy)
4. Token scan (OpenAI, AWS, GitHub, GitLab patterns)
5. Auth guard (simulated, IP-bound)
6. Persistent audit log (in-memory)
7. Redaction (leaks never exposed raw)

## Requirements
Python 3.11+, FastAPI, Pydantic. No hardcoded secrets. No `shell=True`. Bind restricted (no `0.0.0.0`).

## Score Verification
`/score` returns >=80. `/health` confirms defensive-active. Zero leaks on clean fixtures via security scan.

## License
Public. Defensive-only architecture.
