#!/bin/bash
set -euo pipefail

apply_overrides() {
  if [ ! -d /nsp-overrides ]; then
    return 0
  fi
  mkdir -p /etc/crowdsec/scenarios
  for f in http-probing.yaml http-crawl-non_statics.yaml http-generic-bf.yaml; do
    if [ -f "/nsp-overrides/$f" ]; then
      cp "/nsp-overrides/$f" "/etc/crowdsec/scenarios/$f"
    fi
  done
  if [ -f /nsp-overrides/profiles.yaml ]; then
    cp /nsp-overrides/profiles.yaml /etc/crowdsec/profiles.yaml
  fi
}

# Keep hub index "fresh" so docker_start skips cscli hub update (CDN 403 in lab).
if [ -f /etc/crowdsec/hub/.index.json ]; then
  touch /etc/crowdsec/hub/.index.json || true
fi

# Control-plane agent (REQ-IDS-017): respawn loop + ignore HUP so exec/docker_start
# does not kill the supervisor (prod "agent not responding" / EOF on apply).
start_crowdsec_agent() {
  if [ -z "${CROWDSEC_AGENT_TOKEN:-}" ]; then
    echo "nsp: CROWDSEC_AGENT_TOKEN empty — crowdsec-agent disabled" >&2
    return 0
  fi
  if [ ! -x /usr/local/bin/crowdsec-agent ]; then
    echo "nsp: /usr/local/bin/crowdsec-agent missing — rebuild crowdsec image" >&2
    return 0
  fi
  (
    # Detach from parent HUP when entrypoint exec's docker_start / crowdsec.
    trap '' HUP
    while true; do
      echo "nsp: starting crowdsec-agent on :8091" >&2
      CROWDSEC_AGENT_TOKEN="$CROWDSEC_AGENT_TOKEN" HTTP_ADDR=":8091" \
        /usr/local/bin/crowdsec-agent >>/proc/1/fd/1 2>>/proc/1/fd/2 || true
      code=$?
      echo "nsp: crowdsec-agent exited code=$code — restarting in 2s" >&2
      sleep 2
    done
  ) &
  # Brief readiness wait (do not block CrowdSec boot for long).
  for _ in $(seq 1 20); do
    if wget -qO- --timeout=1 http://127.0.0.1:8091/health >/dev/null 2>&1 \
      || curl -fsS --max-time 1 http://127.0.0.1:8091/health >/dev/null 2>&1; then
      echo "nsp: crowdsec-agent healthy" >&2
      return 0
    fi
    sleep 0.25
  done
  echo "nsp: crowdsec-agent not healthy yet (will keep respawning)" >&2
}

start_crowdsec_agent

# Re-apply overrides after hub/collections settle — do NOT HUP here.
# Early HUP (before CrowdSec installs signal handlers) terminates the process
# and causes a restart loop (exit 2), which also makes the agent unreachable.
(
  trap '' HUP
  for _ in $(seq 1 60); do
    if [ -d /etc/crowdsec/scenarios ] && pgrep -x crowdsec >/dev/null 2>&1; then
      sleep 20
      apply_overrides
      break
    fi
    sleep 2
  done
) &

exec /docker_start.sh
