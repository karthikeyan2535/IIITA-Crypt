---
trigger: always_on
---

Under no circumstances should the Master Secret Key for CP-ABE be hardcoded. The agent must implement a .env loader and provide a template file.