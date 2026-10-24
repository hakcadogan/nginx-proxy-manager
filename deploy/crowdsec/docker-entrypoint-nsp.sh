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

# Start control-plane agent before CrowdSec (PID1 will be crowdsec after exec).
if [ -n "${CROWDSEC_AGENT_TOKEN:-}" ]; then
  CROWDSEC_AGENT_TOKEN="$CROWDSEC_AGENT_TOKEN" HTTP_ADDR=":8091" \
    /usr/local/bin/crowdsec-agent &
fi

# Re-apply overrides after hub/collections settle — do NOT HUP here.
# Early HUP (before CrowdSec installs signal handlers) terminates the process
# and causes a restart loop (exit 2), which also makes the agent unreachable.
(
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
