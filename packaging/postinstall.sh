#!/bin/sh
systemctl daemon-reload
echo "BAMF Agent installed. Configure /etc/bamf/agent.yaml then run:"
echo "  systemctl enable --now bamf-agent"
