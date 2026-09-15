# Corporate workstation (Enterprise zone) used to exercise the DMZ access path.
#
# checkov:skip=CKV_DOCKER_3:Root is required to install the DMZ route via the
#   gateway (CAP_NET_ADMIN); the container runs no service.
FROM alpine:3.24

RUN apk add --no-cache curl iproute2 openssh-client

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

HEALTHCHECK CMD ["sh", "-c", "ip route | grep -q '172.25.0.0/24'"]
CMD ["/usr/local/bin/entrypoint.sh"]
