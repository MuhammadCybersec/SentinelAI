Project: SentinelAI

Description:
AI-powered security testing framework.

Current Status:

- Secrets Scanner complete
- 33/33 tests passing
- ScanResult refactor completed
- Scanner modules updated
- Request engine integrated

Important folders:

app/modules/scanner/core/
app/modules/scanner/modules/
tests/modules/scanner/

Coding Rules:

- Existing architecture ko follow karo.
- Koi bhi nayi file create karne se pehle search karo.
- Har fix ke sath file, function aur line number do.
- Pehle tests check karo, phir code modify karo.

Commands:

python -m pytest tests/

python -m ruff check app/ --fix