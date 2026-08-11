#!/usr/bin/env bash
set -euo pipefail

rule=(-m mark --mark 0x554d/0xffffffff -m comment --comment umat-controlled-egress -j ACCEPT)
case "${1:-}" in
  start)
    /usr/sbin/iptables -w -C DOCKER-USER "${rule[@]}" 2>/dev/null || \
      /usr/sbin/iptables -w -I DOCKER-USER 1 "${rule[@]}"
    ;;
  stop)
    /usr/sbin/iptables -w -D DOCKER-USER "${rule[@]}" 2>/dev/null || true
    ;;
  *) exit 2 ;;
esac
