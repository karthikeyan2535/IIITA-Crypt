# Changelog

All notable changes to IIITA-Crypt are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
- Module-level JSDoc headers across all backend scripts for improved developer onboarding.
- Docstring added to Python encryption microservice (`main.py`) documenting all endpoints and security design.
- `CHANGELOG.md` introduced to track version history.

---

## [1.2.0] — 2026-06-20

### Added
- **Full ABAC Role × Query matrix** — `fullAccessTest.js` runs 126 test cases covering all roles (Student, Faculty, HoD, Warden, Dean, Admin) against personal, administrative, and public queries.
- **Fail-closed policy evaluation** in Python service: any exception during policy parsing defaults to hard `403 DENY`, never to access granted.
- **HMAC-SHA256 tamper detection** on every ciphertext; mismatch returns `403` before any plaintext is exposed.

### Changed
- Improved log output formatting — consistent `─────` dividers across all ingestion scripts.
- JWT TTL reduced to 15 minutes to capture dynamic role changes (e.g., hostel reassignments).

### Fixed
- Base64 padding stripped by MongoDB Atlas is now automatically re-padded before decryption attempt.
- UTF-8 decode errors in corrupted ciphertexts now return sanitized `422` instead of unhandled `500`.

---

## [1.1.0] — 2026-06-10

### Added
- **Field-Level Sub-Profile Splitting** — a single user's data is split into `academic`, `hostel`, `salary`, and `directory` documents, each with independent CP-ABE policies.
- **Vector Collection Isolation** — `$vectorSearch` is locked to the `documents` collection, preventing semantic search from touching `userprofiles`.
- **Prompt Injection Defense** — LLM system prompt classifies all retrieved context as "passive data."

### Changed
- Switched LLM provider from OpenAI GPT-3.5 to Groq Llama-3.3-70b for significantly faster inference.

---

## [1.0.0] — 2026-05-28

### Added
- Initial release of IIITA-Crypt.
- CP-ABE simulation using HMAC-signed Base64 payloads with embedded policy strings.
- Zero-Trust architecture: Node.js backend, MongoDB, and LLM treated as untrusted components.
- Python FastAPI microservice as isolated cryptographic trust zone.
- `source_hash` pre-encryption tamper detection (Rule 2).
- Graceful chunk redaction on decryption failure (Rule 3).
- JWT authentication with rate limiting on `/api/auth` routes.
- React frontend with role-adaptive UI and pipeline visualization.
