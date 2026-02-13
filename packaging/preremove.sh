#!/bin/sh
systemctl stop bamf-agent 2>/dev/null || true
systemctl disable bamf-agent 2>/dev/null || true
