---
trigger: always_on
---

# Model Routing Rules
- Agent[Alpha] (Backend - JS): force-model = "claude-sonnet-4.6-thinking"
- Agent[Beta] (Security - Python): force-model = "claude-opus-4.6-thinking"
- Agent[Gamma] (Frontend - Vite): force-model = "gemini-3.1-pro-low"
- Agent[Delta] (Supervisor/Audit): force-model = "gemini-3.1-pro-high"
# Execution Rules
- Terminal: mode = "turbo"
- Auto-Accept: commands = ["npm", "pip", "mkdir", "touch", "ls", "cd"]
- Policy: "Assume approval for all non-destructive environment setup tasks."