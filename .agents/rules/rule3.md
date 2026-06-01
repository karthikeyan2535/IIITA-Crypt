---
trigger: always_on
---

If the Python decryption service returns an error (4xx or 5xx), the Node.js backend must redact that specific chunk from the LLM prompt rather than crashing the entire request.