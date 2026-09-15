# Generic route sidecar: joins another service's network namespace and installs
# the gateway route that keeps a tier's replies symmetric through the chokepoint
# (the service is otherwise single-homed and its replies would bypass the
# gateway via the Docker host). Used by Grafana (C4) and the historian.
#
# checkov:skip=CKV_DOCKER_3:Root is required to add the route in the shared
#   network namespace (CAP_NET_ADMIN); it runs no other workload.
FROM alpine:3.24

RUN apk add --no-cache iproute2

HEALTHCHECK CMD ["sh", "-c", "ip route | grep -q ' via '"]

CMD ["sh", "-c", "echo 'route-sidecar: no route configured'; exec tail -f /dev/null"]
