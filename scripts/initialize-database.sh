#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

for setting in MAINTENANCE_HOST CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET JWT_SECRET; do
  if [ -z "${!setting:-}" ]; then
    printf 'Missing required setting: %s.\n' "$setting" >&2
    exit 1
  fi
  if [[ "${!setting}" == *$'\r'* || "${!setting}" == *$'\n'* ]]; then
    printf 'Invalid required setting: %s.\n' "$setting" >&2
    exit 1
  fi
done

if ! [[ "$MAINTENANCE_HOST" =~ ^[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev$ ]]; then
  printf 'MAINTENANCE_HOST must be a workers.dev hostname.\n' >&2
  exit 1
fi

if ! init_tmp_dir=$(mktemp -d 2>/dev/null); then
  printf 'Unable to create temporary initialization files.\n' >&2
  exit 1
fi
trap 'rm -rf "$init_tmp_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "$init_tmp_dir"

curl_status=0
http_status=$(curl --disable --silent --show-error \
  --request POST \
  --connect-timeout 10 --max-time 120 \
  --proto '=https' --tlsv1.2 \
  --header "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  --header "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
  --header "X-Init-Secret: $JWT_SECRET" \
  --dump-header "$init_tmp_dir/headers" \
  --output "$init_tmp_dir/body" \
  --write-out '%{http_code}' \
  "https://$MAINTENANCE_HOST/api/maintenance/init" \
  2>"$init_tmp_dir/curl-error") || curl_status=$?

# Treat all response data as untrusted. Never print bodies, curl errors or raw headers.
if ! [[ "$http_status" =~ ^[0-9]{3}$ ]]; then
  http_status=unknown
fi

diagnostic="HTTP: $http_status"
if [ -f "$init_tmp_dir/headers" ]; then
  ray_id=$(awk 'tolower($1) == "cf-ray:" { gsub(/\r/, "", $2); value=$2 } END { print value }' "$init_tmp_dir/headers")
  if [[ "$ray_id" =~ ^[0-9a-fA-F]{16}(-[A-Za-z]{3})?$ ]] &&
    [[ "$ray_id" != *"$CF_ACCESS_CLIENT_ID"* && "$ray_id" != *"$CF_ACCESS_CLIENT_SECRET"* && "$ray_id" != *"$JWT_SECRET"* ]]; then
    diagnostic="$diagnostic; CF-Ray: $ray_id"
  fi
  if awk 'tolower($1) == "cf-mitigated:" { gsub(/\r/, "", $2); if (tolower($2) == "challenge") found=1 } END { exit !found }' "$init_tmp_dir/headers"; then
    diagnostic="$diagnostic; cf-mitigated: challenge"
  fi
fi

if [ "$curl_status" -ne 0 ]; then
  printf 'Initialization transport failed (%s); outcome unknown; inspect state before retry.\n' "$diagnostic" >&2
  exit 1
fi

if [ "$http_status" = 200 ] && printf 'success' | cmp -s - "$init_tmp_dir/body"; then
  printf 'Database initialization completed.\n'
else
  printf 'Database initialization failed (%s); inspect state before retry.\n' "$diagnostic" >&2
  exit 1
fi
