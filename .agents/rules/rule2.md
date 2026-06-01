---
trigger: always_on
---

Every document chunk in MongoDB must contain a source_hash to prevent tampering. The ingestion script must calculate this hash before encryption.