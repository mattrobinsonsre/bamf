#!/bin/sh
if ! getent group bamf >/dev/null 2>&1; then
    groupadd --system bamf
fi
if ! getent passwd bamf >/dev/null 2>&1; then
    useradd --system --gid bamf --home-dir /var/lib/bamf-agent --shell /usr/sbin/nologin bamf
fi
mkdir -p /var/lib/bamf-agent
chown bamf:bamf /var/lib/bamf-agent
