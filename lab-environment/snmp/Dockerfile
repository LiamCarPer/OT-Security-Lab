FROM alpine:3.20
RUN apk add --no-cache net-snmp net-snmp-tools python3
COPY snmpd.conf /etc/snmp/snmpd.conf
COPY poll.py /app/poll.py
CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"]
