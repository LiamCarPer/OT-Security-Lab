# Industrial DMZ jump host / bastion - the mandatory entry point for remote
# maintenance (see governance/policies/remote-access-policy.md).
FROM alpine:3.24

# checkov:skip=CKV_DOCKER_3:sshd must run as root to bind port 22 and manage
#   sessions; compensating controls are a documented lab-only credential and a
#   zone conduit restricted to the Enterprise network.
# checkov:skip=CKV2_DOCKER_17:a single documented lab credential, not a secret;
#   the host is isolated in the DMZ.
RUN apk add --no-cache openssh shadow \
    && ssh-keygen -A \
    && adduser -D -s /bin/sh engineer \
    && echo 'engineer:ot-lab-bastion' | chpasswd

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# checkov:skip=CKV_DOCKER_1:exposing SSH is the bastion's entire purpose; the
#   compensating control is the source-restricted DMZ conduit (C9).
EXPOSE 22
HEALTHCHECK CMD ["sh", "-c", "nc -z 127.0.0.1 22 || exit 1"]
CMD ["/usr/local/bin/entrypoint.sh"]
