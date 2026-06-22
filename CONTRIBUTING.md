# Contributing to IIITA-Crypt

Thank you for your interest in contributing! Please read the guidelines below before opening a PR.

## Ground Rules

- **Never hardcode secrets.** The MSK, JWT secret, and API keys must always be loaded from `.env`. See [rule1.md](.agents/rule1.md).
- **Always compute `source_hash` before encryption.** Every ingested document chunk must have a `source_hash` field set prior to the CP-ABE encrypt call. See [rule2.md](.agents/rule2.md).
- **Handle decryption errors gracefully.** If the Python service returns a 4xx/5xx, redact that chunk — do not crash the request. See [rule3.md](.agents/rule3.md).

## Development Setup

```bash
# 1. Clone and install
git clone https://github.com/karthikeyan2535/IIITA-Crypt.git
cd IIITA-Crypt
cp .env.template .env
# Fill in MONGODB_URL, OPENAI_API_KEY, GROQ_API_KEY, JWT_SECRET, MSK

# 2. Start the crypto service
cd services/encryption && pip install -r requirements.txt
python -m uvicorn main:app --port 8000

# 3. Seed the database
cd backend && npm install
node scripts/seedUsers.js
node scripts/ingestData.js
node scripts/ingestProfiles.js

# 4. Run dev servers
npm run dev          # Backend on :3000
cd ../frontend && npm run dev   # Frontend on :5173
```

## Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<short-desc>` | `feat/dean-override-audit-log` |
| Bug Fix | `fix/<short-desc>` | `fix/base64-padding-strip` |
| Docs | `docs/<short-desc>` | `docs/add-api-reference` |
| Security | `security/<short-desc>` | `security/hmac-timing-attack` |

## Pull Request Checklist

- [ ] All existing tests pass: `node scripts/runTests.js`
- [ ] Full ABAC matrix passes: `node scripts/fullAccessTest.js`
- [ ] No secrets committed (run `git grep -r "msk\s*=" --include="*.js" --include="*.py"`)
- [ ] CHANGELOG.md updated with your change under `[Unreleased]`
- [ ] JSDoc headers added to any new `.js` files
- [ ] Module docstrings added to any new `.py` files

## Code Style

- **JavaScript**: ESModules (`import`/`export`), 4-space indent, single quotes.
- **Python**: PEP 8, type hints on all function signatures, Google-style docstrings.

## Reporting Security Issues

Do **not** open a public GitHub Issue for security vulnerabilities. Email the maintainer directly with a detailed description.
