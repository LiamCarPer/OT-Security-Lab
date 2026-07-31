# Alert webhook receiver (SOAR-lite) - deterministic, no bind-mounted code
FROM python:3.12-slim

COPY webhook_receiver.py /app/webhook_receiver.py

# Receiver persists SIEM alerts to /logs (bind-mounted from detection/logs)
CMD ["sh", "-c", "echo [WEBHOOK] starting; python3 -u /app/webhook_receiver.py"]
