# Atlas Forge — Security Audit
Defensive flagship, public repo, no AI branding, score >=80.

Layers:
1. Input validation (regex, Pydantic)
2. Rate limiting (per-IP, 60s window, 10 req max)
3. Security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy)
4. Token-scan (OpenAI, AWS, GitHub, GitLab patterns)
5. Auth guard (simulated, IP-bound)
6. Audit log (persistent in-memory)
7. Redaction (leaks never exposed raw)

Score calculation: base 50 + headers 15 + deep 10 + audit 15 + redacted 10 = 100 max.
Actual: >=80.
Routing: omniroute / NVIDIA / hermes / openrouter / free (Experiential removed).
