# One-shot Scada-LTS provisioner: creates Modbus/TCP datasources + datapoints
FROM alpine:3.24

RUN apk add --no-cache curl jq \
    && adduser -D -u 10001 prov

COPY provision.sh /usr/local/bin/provision.sh
RUN chmod +x /usr/local/bin/provision.sh

USER 10001

# Healthy once the provisioning run has completed (see compose restart policy)
HEALTHCHECK CMD ["sh", "-c", "test -f /tmp/scada-provisioned"]

CMD ["/usr/local/bin/provision.sh"]
