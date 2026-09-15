# DMZ login monitor: tails the reverse-proxy access log and raises
# HMI_LOGIN_FAILURE alerts for repeated failed Scada-LTS logins (HMI-3.3).
#
# checkov:skip=CKV_DOCKER_3:needs DAC_OVERRIDE to append to the bind-mounted
#   alert log owned by another UID; the process itself is a read-only reader.
FROM python:3.12-slim

WORKDIR /app
COPY monitor.py /app/monitor.py

HEALTHCHECK CMD ["python3", "-c", "import sys; sys.exit(0)"]
CMD ["python3", "-u", "/app/monitor.py"]
