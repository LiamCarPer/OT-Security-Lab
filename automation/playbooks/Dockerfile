# Alert webhook receiver (SOAR-lite) - deterministic, no bind-mounted code
FROM python:3.14-slim

COPY webhook_receiver.py /app/webhook_receiver.py

# Verbose wrapper: every startup step is logged for remote debugging
CMD ["sh", "-c", "echo [WEBHOOK] begin; ls -la /app; python3 -V; python3 -u /app/webhook_receiver.py; echo [WEBHOOK] exit=$?"]
