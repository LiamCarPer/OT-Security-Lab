#!/bin/sh
# DMZ bastion entrypoint.
#
# Generates the bastion -> EWS SSH keypair into the shared `ews_keys` volume
# (never committed to git) and installs the private key for the engineer's
# onward session, then serves sshd. The public half becomes the authorized_keys
# the EWS reads (conduit C11).
set -eu

KEY_DIR=/keys
mkdir -p "$KEY_DIR"

if [ ! -s "$KEY_DIR/id_ed25519" ]; then
    ssh-keygen -t ed25519 -N '' -C 'ot-lab bastion->ews' -f "$KEY_DIR/id_ed25519"
fi
cp "$KEY_DIR/id_ed25519.pub" "$KEY_DIR/authorized_keys"
chmod 600 "$KEY_DIR/id_ed25519"
chmod 644 "$KEY_DIR/id_ed25519.pub" "$KEY_DIR/authorized_keys"

mkdir -p /home/engineer/.ssh
cp "$KEY_DIR/id_ed25519" /home/engineer/.ssh/id_ed25519
chmod 700 /home/engineer/.ssh
chmod 600 /home/engineer/.ssh/id_ed25519
chown -R engineer:engineer /home/engineer/.ssh

exec /usr/sbin/sshd -D -e
