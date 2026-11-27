# checkov:skip=CKV_DOCKER_2: The snmpd daemon is the service; health is checked by the poller over UDP, not by an in-image command.
# checkov:skip=CKV_DOCKER_3: net-snmp binds UDP/161 and reads its config at start; it runs as root inside the isolated lab.
FROM alpine:3.20
RUN apk add --no-cache net-snmp net-snmp-tools python3
COPY snmpd.conf /etc/snmp/snmpd.conf
COPY poll.py /app/poll.py
CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"]
