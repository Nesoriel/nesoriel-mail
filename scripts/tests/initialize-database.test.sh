#!/usr/bin/env bash
set -euo pipefail
umask 077

test_tmp_dir=$(mktemp -d)
trap 'rm -rf "$test_tmp_dir"' EXIT
script_dir=$(cd "$(dirname "$0")/.." && pwd)
mkdir "$test_tmp_dir/bin"
export TEST_STATE_DIR="$test_tmp_dir"
export MAINTENANCE_HOST=mail-maintenance.example.workers.dev
export CF_ACCESS_CLIENT_ID=fixture-access-id-not-real
export CF_ACCESS_CLIENT_SECRET=fixture-access-secret-not-real
export JWT_SECRET=fixture-jwt-secret-not-real

cat > "$test_tmp_dir/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf 'called\n' >> "$TEST_STATE_DIR/calls"
args=("$@")
[[ "${args[0]}" = --disable ]]
request= connect_timeout= max_time= proto= write_out= headers_file= body_file= url=
access_id= access_secret= init_secret= tls=false silent=false show_error=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --disable) shift ;;
    --silent) silent=true; shift ;;
    --show-error) show_error=true; shift ;;
    --tlsv1.2) tls=true; shift ;;
    --request) request=$2; shift 2 ;;
    --connect-timeout) connect_timeout=$2; shift 2 ;;
    --max-time) max_time=$2; shift 2 ;;
    --proto) proto=$2; shift 2 ;;
    --write-out) write_out=$2; shift 2 ;;
    --dump-header) headers_file=$2; shift 2 ;;
    --output) body_file=$2; shift 2 ;;
    --header)
      case "$2" in
        "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID") access_id=true ;;
        "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET") access_secret=true ;;
        "X-Init-Secret: $JWT_SECRET") init_secret=true ;;
        *) exit 90 ;;
      esac
      shift 2 ;;
    https://*) url=$1; shift ;;
    *) exit 91 ;;
  esac
done
[[ "$request" = POST && "$connect_timeout" = 10 && "$max_time" = 120 ]]
[[ "$proto" = '=https' && "$write_out" = '%{http_code}' ]]
[[ "$tls" = true && "$silent" = true && "$show_error" = true ]]
[[ "$access_id" = true && "$access_secret" = true && "$init_secret" = true ]]
[[ "$url" = "https://$MAINTENANCE_HOST/api/maintenance/init" ]]
[[ "$(dirname "$body_file")" = "$(dirname "$headers_file")" ]]
printf '%s' "$(dirname "$body_file")" > "$TEST_STATE_DIR/last-request-dir"
[[ "$(ls -ld "$(dirname "$body_file")" | cut -c1-10)" = drwx------ ]]
printf 'HTTP/2 200\r\n' > "$headers_file"
printf 'success' > "$body_file"
case "$TEST_SCENARIO" in
  success) printf 200 ;;
  wrong_body) printf '%s' "$JWT_SECRET" > "$body_file"; printf 200 ;;
  trailing_newline) printf 'success\n' > "$body_file"; printf 200 ;;
  challenge)
    printf 'HTTP/2 403\r\nCF-Ray: a4b64cb7eb22e93c-AMS\r\nCf-Mitigated: challenge\r\n' > "$headers_file"
    printf 'Just a moment %s %s' "$JWT_SECRET" "$CF_ACCESS_CLIENT_SECRET" > "$body_file"
    printf 403 ;;
  redirect)
    printf 'HTTP/2 302\r\nLocation: https://other.example/%s\r\n' "$JWT_SECRET" > "$headers_file"
    printf 302 ;;
  transport)
    printf 'private curl error %s %s\n' "$JWT_SECRET" "$CF_ACCESS_CLIENT_SECRET" >&2
    printf 000
    exit 28 ;;
  reflected_status)
    printf 'HTTP/2 403\r\nCF-Ray: %s\r\nCf-Mitigated: %s\r\n' "$CF_ACCESS_CLIENT_SECRET" "$JWT_SECRET" > "$headers_file"
    printf '%s' "$JWT_SECRET" ;;
  safe_ray_secret)
    printf 'HTTP/2 403\r\nCF-Ray: %s\r\n' "$JWT_SECRET" > "$headers_file"
    printf 403 ;;
  *) exit 92 ;;
esac
printf 'validated\n' >> "$TEST_STATE_DIR/validated"
MOCK
chmod +x "$test_tmp_dir/bin/curl"
export PATH="$test_tmp_dir/bin:$PATH"
test_count=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

run_case() {
  local case_name=$1 expected_exit=$2 expected_text=$3 expected_calls=${4:-1}
  rm -f "$test_tmp_dir/calls" "$test_tmp_dir/validated" "$test_tmp_dir/last-request-dir"
  export TEST_SCENARIO="$case_name"
  local actual_exit=0
  bash "$script_dir/initialize-database.sh" > "$test_tmp_dir/output" 2>&1 || actual_exit=$?
  [ "$actual_exit" -eq "$expected_exit" ] || fail "$case_name exit status"
  grep -Fq "$expected_text" "$test_tmp_dir/output" || fail "$case_name diagnostic"
  for secret_value in "${JWT_SECRET:-}" "${CF_ACCESS_CLIENT_ID:-}" "${CF_ACCESS_CLIENT_SECRET:-}"; do
    if [ -n "$secret_value" ] && grep -Fq -- "$secret_value" "$test_tmp_dir/output"; then
      fail "$case_name exposed a credential"
    fi
  done
  local actual_calls=0
  if [ -f "$test_tmp_dir/calls" ]; then
    actual_calls=$(wc -l < "$test_tmp_dir/calls" | tr -d ' ')
  fi
  [ "$actual_calls" -eq "$expected_calls" ] || fail "$case_name request count"
  if [ -f "$test_tmp_dir/last-request-dir" ]; then
    [ ! -e "$(cat "$test_tmp_dir/last-request-dir")" ] || fail "$case_name temporary files remain"
  fi
  if [ "$expected_calls" -eq 1 ] && [ "$case_name" != transport ]; then
    [ -f "$test_tmp_dir/validated" ] || fail "$case_name request contract"
  fi
  test_count=$((test_count + 1))
}

run_case success 0 'Database initialization completed.'
run_case wrong_body 1 'HTTP: 200'
run_case trailing_newline 1 'HTTP: 200'
run_case challenge 1 'HTTP: 403; CF-Ray: a4b64cb7eb22e93c-AMS; cf-mitigated: challenge'
run_case redirect 1 'HTTP: 302'
run_case transport 1 'outcome unknown; inspect state before retry'
run_case reflected_status 1 'HTTP: unknown'
if grep -Fq 'CF-Ray:' "$test_tmp_dir/output" || grep -Fq 'cf-mitigated:' "$test_tmp_dir/output"; then
  fail 'untrusted header reflection'
fi

saved_jwt_secret=$JWT_SECRET
export JWT_SECRET=a4b64cb7eb22e93c
run_case safe_ray_secret 1 'HTTP: 403'
if grep -Fq 'CF-Ray:' "$test_tmp_dir/output"; then
  fail 'credential reflected as a valid Ray ID'
fi
export JWT_SECRET=$saved_jwt_secret

saved_host=$MAINTENANCE_HOST
for invalid_host in 'https://mail.example.workers.dev' 'mail.example.workers.dev/api/init' 'mail.example.workers.dev?x=y' 'mail.example.workers.dev@evil.example' 'mail.example.com' 'mail.EXAMPLE.workers.dev' $'mail.example.workers.dev\n'; do
  export MAINTENANCE_HOST="$invalid_host"
  run_case invalid_host 1 'MAINTENANCE_HOST' 0
done
export MAINTENANCE_HOST=$saved_host

for setting in MAINTENANCE_HOST CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET JWT_SECRET; do
  saved_value=${!setting}
  export "$setting="
  run_case missing_setting 1 "Missing required setting: $setting." 0
  unset "$setting"
  run_case unset_setting 1 "Missing required setting: $setting." 0
  export "$setting=$saved_value"
done

export CF_ACCESS_CLIENT_SECRET=$'invalid\r\nheader'
run_case invalid_header 1 'Invalid required setting: CF_ACCESS_CLIENT_SECRET.' 0
printf 'Passed %s mocked initialization cases; no network requests made.\n' "$test_count"
