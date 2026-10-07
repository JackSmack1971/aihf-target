#!/bin/bash
# Step 1 of 3 (generate/validate): offline validation of the canonical fund-ops provisioning artifacts. NO system mutation, no root needed.
# Operator-run administrative artifact only (see ops/provision/README.md).
#
# Checks: every file listed in canonical-artifacts.sha256 exists and matches its pinned SHA-256 (line endings normalized to LF);
# the managed requirements contain no secret material; the WSL template matches the layout contract's hardening flags.
# Exit 0 only if every check passes.
set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SRC=$(cd "$HERE/../.." && pwd -P)
. "$HERE/fund-ops-layout.sh"
fails=0
pass() { echo "PASS    $1"; }
fail() { echo "FAIL    $1"; fails=$((fails + 1)); }
lf_sha() { tr -d '\r' < "$1" | sha256sum | cut -d' ' -f1; }

PINS="$HERE/canonical-artifacts.sha256"
[ -f "$PINS" ] || { echo "FAIL    pinned manifest missing: $PINS"; exit 1; }
count=0
while read -r want rel; do
  case "$want" in ''|'#'*) continue ;; esac
  count=$((count + 1))
  f="$SRC/$rel"
  if [ ! -f "$f" ]; then fail "artifact missing: $rel"; continue; fi
  got=$(lf_sha "$f")
  if [ "$got" = "$want" ]; then pass "artifact hash matches pin: $rel"; else fail "artifact differs from pin: $rel (pinned $want, actual $got)"; fi
done < "$PINS"
[ "$count" -ge 4 ] && pass "pinned manifest lists $count artifacts" || fail "pinned manifest lists only $count artifacts"

REQ="$SRC/config/codex/requirements.fund-ops.toml"
if grep -qE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----|0x[0-9a-fA-F]{64}' "$REQ" "$HERE"/*.sh "$HERE/wsl.conf.fund-ops" 2>/dev/null; then fail "secret-like material in provisioning artifacts"; else pass "no secret-like material in provisioning artifacts"; fi
for k in 'allowed_permission_profiles' 'default_permissions = ":read-only"' 'allowed_sandbox_modes = \["read-only"\]' 'allowed_approval_policies = \["on-request"\]' 'allow_managed_hooks_only = true' 'allow_browser_and_computer_use = false'; do
  grep -qE -e "^[[:space:]]*(\[)?$k" "$REQ" && pass "requirements carry: $k" || fail "requirements lack: $k"
done
if grep -qE -e '^[[:space:]]*(approval_policy|sandbox_mode)[[:space:]]*=[[:space:]]*"(never|danger-full-access)"' "$REQ"; then fail "requirements widen approval/sandbox"; else pass "requirements do not widen approval/sandbox"; fi
W="$HERE/wsl.conf.fund-ops"
grep -qE '^enabled[[:space:]]*=[[:space:]]*false' "$W" && pass "wsl template disables automount/interop" || fail "wsl template does not disable automount/interop"
[ "$(grep -cE '^enabled[[:space:]]*=[[:space:]]*false' "$W")" -eq 2 ] && pass "wsl template: automount and interop both disabled" || fail "wsl template: automount and interop must both be disabled"
grep -qE '^appendWindowsPath[[:space:]]*=[[:space:]]*false' "$W" && pass "wsl template: no Windows PATH" || fail "wsl template: Windows PATH not disabled"
grep -qE "^default[[:space:]]*=[[:space:]]*$AIHF_OPS_USER\$" "$W" && pass "wsl template: default user is the unprivileged ops user" || fail "wsl template: default user is not $AIHF_OPS_USER"
echo "SUMMARY validate: failures=$fails"
[ "$fails" -eq 0 ]
