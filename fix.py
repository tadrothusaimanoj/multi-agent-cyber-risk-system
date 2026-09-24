import re
path = r'c:\Users\Manoj\Downloads\old\multi-agent-cyber-risk-system\src\components\OriginalDashboard.tsx'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

content = content.replace("['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b']", "['#4f46e5', '#3b82f6', '#8b5cf6', '#e5484d', '#ffb224']")
content = content.replace("['#38bdf8', '#818cf8', '#c084fc', '#f472b6', '#fbbf24']", "['#818cf8', '#a5b4fc', '#c7d2fe', '#e0e7ff', '#eef2ff']")
content = content.replace("'#06b6d4'", "'#4f46e5'")
content = content.replace("'rgba(6, 182, 212, 0.14)'", "'rgba(79, 70, 229, 0.14)'")
content = content.replace('rounded-2xl', 'rounded-xl')
content = content.replace('tracking-wider', 'tracking-normal')

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
