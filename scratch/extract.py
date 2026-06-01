import json
import os

log_path = r"C:\Users\HP\.gemini\antigravity\brain\a7650535-70b4-43ec-a250-9e9347f2c83f\.system_generated\logs\overview.txt"
with open(log_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

files = {}
for line in lines:
    try:
        data = json.loads(line)
        if 'tool_calls' in data:
            for call in data['tool_calls']:
                if call.get('name') == 'write_to_file':
                    args = call.get('args', {})
                    target = args.get('TargetFile', '').strip('"')
                    content = args.get('CodeContent', '')
                    if content and isinstance(content, str):
                        # The content might be double escaped due to JSON
                        if content.startswith('"') and content.endswith('"'):
                            try:
                                content = json.loads(content)
                            except:
                                pass
                        
                        files[target] = content
    except Exception as e:
        pass

for target, content in files.items():
    if 'index.css' in target or 'App.css' in target or 'Chat.jsx' in target or 'Login.jsx' in target:
        target_path = target.replace('\\\\', '\\')
        print(f"Writing to {target_path} (length {len(content)})")
        with open(target_path, 'w', encoding='utf-8') as out_f:
            out_f.write(content)
