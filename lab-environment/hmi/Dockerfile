# Real Scada-LTS HMI, routed through the zone gateway
#
# checkov:skip=CKV_DOCKER_3:Tomcat/Scada-LTS upstream image runs as root; this
#   is a lab-only HMI with compensating controls (no-new-privileges, only
#   NET_ADMIN for the conduit route, single authorized conduit).
FROM scadalts/scadalts:v2.8.0

# iproute2 provides `ip`, used by the entrypoint to install the Control-zone
# route via the gateway (the image otherwise has no route tooling).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/ot-hmi-entrypoint.sh
RUN chmod +x /usr/local/bin/ot-hmi-entrypoint.sh

# Readiness: Tomcat answers on 8080 once the Scada-LTS webapp is deployed.
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=10 \
    CMD bash -c "exec 3<>/dev/tcp/127.0.0.1/8080"

ENTRYPOINT ["/usr/local/bin/ot-hmi-entrypoint.sh"]
CMD ["/usr/local/tomcat/bin/catalina.sh", "run"]
