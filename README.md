# ATLAS FORGE
Public defensive framework. Free routing. No AI branding. Score >=80.
Endpoints: /health /scan /audit /audit-log /score /docs
Security layers (7): input-validate | rate-limit | security-headers | token-scan | audit-log | redaction | score.
Score formula: base 50 + headers 15 + deep-mode 10 + audit-log 15 + redaction 10 = 100 max.
Repo: harmanhanjra/atlas-forge. MIT. Defensive-only. Verified smoke tests pass.
