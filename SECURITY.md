# Security Policy

## Scope

Artic handles sensitive material: exchange API keys, private keys for on-chain transactions, JWT secrets, and database credentials. Security issues in this project can directly result in financial loss, account takeover, or unauthorised trading.

### In-scope

- Authentication bypass (JWT, API key, internal secret)
- Secret leakage (encrypted secrets, env vars, logs)
- Private key exposure in on-chain logging code (`app/onchain_logger.py`, `app/onchain_trade_logger.py`)
- SQL injection or ORM query bypass in hub endpoints
- Unauthorised cross-tenant data access (agent queries not scoped to `user_id`)
- Command injection via Docker container spawn parameters
- Smart contract vulnerabilities (`contracts/DecisionLogger.sol`, `contracts/TradeLogger.sol`)
- Dependency vulnerabilities with a clear exploit path

### Out-of-scope

- Issues in third-party services (Pyth, TwelveData, HashKey Global, LLM providers)
- Theoretical vulnerabilities with no practical exploit
- Missing rate limiting on non-auth endpoints
- Security issues in the web client (Next.js landing + docs) — it has no auth or user data
- Social engineering

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | Yes |
| Older releases | No |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via email: **sounak.dey2468@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected file(s) and line numbers
- Potential impact (what an attacker could do)
- Your suggested fix (optional but appreciated)

### Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 48 hours |
| Triage + severity assessment | Within 5 business days |
| Fix or mitigation | Within 30 days for critical, 90 days for moderate/low |
| Public disclosure | After fix is released and users have time to update |

We follow coordinated disclosure. If you have a hard deadline, let us know in the report.

---

## Bug Bounty Reward Guidelines (USD)

Rewards are discretionary and based on impact, exploitability, and report quality.

- **Low:** $50–$150
- **Medium:** $200–$500
- **High:** $750–$2,000
- **Critical:** $3,000–$10,000

---

## Known Sensitive Areas

If you are auditing or contributing, pay extra attention to:

| Area | Risk | File(s) |
|------|------|---------|
| Private key handling | Funds loss if leaked | `app/onchain_logger.py`, `app/onchain_trade_logger.py`, `contracts/deploy.py` |
| Secret encryption/decryption | API key exposure | `hub/secrets/service.py` |
| JWT validation | Auth bypass | `hub/auth/deps.py`, `hub/auth/service.py` |
| Internal secret auth | Agent impersonation | `hub/internal/router.py`, `app/hub_callback.py` |
| Docker container spawn | Command injection via symbol/params | `hub/docker/manager.py`, `hub/agents/service.py` |
| Multi-tenant queries | Cross-user data access | All `hub/db/` query sites — must filter by `user_id` |
| Smart contract `onlyOwner` | Unauthorised event emission | `contracts/DecisionLogger.sol`, `contracts/TradeLogger.sol` |

---

## Security Best Practices for Contributors

- Never commit `.env` files, private keys, or API keys.
- Run `git log -p | grep -iE "(key|secret|password|token)" ` before opening a PR.
- All secrets stored in DB must go through `hub/secrets/service.py` (AES encryption).
- Docker container env vars injected at spawn must never be logged.
- All hub endpoints that return user data must filter by `user_id` — no exceptions.
- Validate and sanitise all user-supplied values before passing to Docker or shell.

---

## Hall of Fame

Researchers who responsibly disclose valid vulnerabilities will be acknowledged here (with permission).
