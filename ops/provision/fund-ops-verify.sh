#!/bin/bash
# Step 3 of 3 (verify installed state): read-only verification of the provisioned fund-ops runtime, plus identity-level DENIAL tests
# that attempt the forbidden writes as the real ops identity. Operator-run administrative artifact only (see ops/provision/README.md).
# Run as root inside the dedicated distro. The only writes it performs are inside the ops-writable directories (positive controls) and are removed.
#
#   fund-ops-verify.sh [--expect-hardened-wsl] [--source-tree DIR] [--pe-probe FILE]
#
# Output lines: PASS | FAIL | CONTROL (a positive control that must succeed so a broken harness cannot report a vacuous pass) |
# ROUTE-OPEN / ROUTE-CLOSED (WSL interoperability routes; with --expect-hardened-wsl an open route is a FAIL).
# Exit 0 only if there are no FAIL lines. Scope: filesystem/identity boundary only. Codex-level enforcement is tests/live/verify-ops-runtime.mjs.
set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
. "$HERE/fund-ops-layout.sh"
HARDENED=0; SRC=""; PE=""
while [ $# -gt 0 ]; do
  case "$1" in --expect-hardened-wsl) HARDENED=1; shift ;; --source-tree) SRC="$2"; shift 2 ;; --pe-probe) PE="$2"; shift 2 ;; *) echo "unknown option $1" >&2; exit 64 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "FAIL    run as root (the verifier must be able to inspect everything)"; exit 1; }
fails=0
pass() { echo "PASS    $1"; }
fail() { echo "FAIL    $1"; fails=$((fails + 1)); }
control() { echo "CONTROL $1"; }
OPS_ENV=(env -i PATH=/usr/bin:/bin HOME="$AIHF_OPS_HOME" LANG=C.UTF-8)
as_ops() { runuser -u "$AIHF_OPS_USER" -- "${OPS_ENV[@]}" "$@"; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# ---- 1 identity
id "$AIHF_OPS_USER" >/dev/null 2>&1 || { fail "identity: $AIHF_OPS_USER does not exist"; echo "SUMMARY verify: failures=$fails"; exit 1; }
[ "$(id -u "$AIHF_OPS_USER")" -ne 0 ] && pass "identity: $AIHF_OPS_USER is non-root (uid $(id -u "$AIHF_OPS_USER"))" || fail "identity: uid 0"
[ "$(id -nG "$AIHF_OPS_USER")" = "$AIHF_OPS_GROUP" ] && pass "identity: no supplementary groups" || fail "identity: groups are '$(id -nG "$AIHF_OPS_USER")'"
[ "$(passwd -S "$AIHF_OPS_USER" | cut -d' ' -f2)" = "L" ] && pass "identity: password locked" || fail "identity: password is not locked"
if grep -rEq -e "(^|[^[:alnum:]_-])%?$AIHF_OPS_USER([^[:alnum:]_-]|\$)" /etc/sudoers /etc/sudoers.d 2>/dev/null; then fail "identity: referenced in sudoers"; else pass "identity: not referenced in sudoers"; fi
as_ops sudo -n true >/dev/null 2>&1 && fail "identity: sudo -n succeeded" || pass "identity: cannot sudo"
sudo -n -l -U "$AIHF_OPS_USER" 2>&1 | grep -qi 'not allowed' && pass "identity: sudo -l reports no rights (covers ALL-wildcard and command-scoped rules)" || fail "identity: sudo -l reports rights for $AIHF_OPS_USER"
[ "$(getent passwd "$AIHF_OPS_USER" | cut -d: -f6)" = "$AIHF_OPS_HOME" ] && pass "identity: dedicated home $AIHF_OPS_HOME" || fail "identity: home differs"
for svc in riskd traderd signerd; do getent passwd "$svc" >/dev/null && fail "service identity $svc exists (belongs to a later slice)" || true; done
pass "no premature service identities (riskd/traderd/signerd absent)"

# ---- 2 ownership and modes (layout table + files)
chk() { # path expected_owner expected_group expected_mode(octal as in table) type-flag
  local p="$1" o="$2" g="$3" m="${4#0}"
  [ -e "$p" ] || [ -L "$p" ] || { fail "layout: missing $p"; return; }
  local got; got=$(stat -c '%U:%G %a' "$p")
  [ "$got" = "$o:$g $m" ] && pass "layout: $p $got" || fail "layout: $p is '$got', expected '$o:$g $m'"
}
for row in "${AIHF_DIRS[@]}"; do read -r p o g m <<<"$row"; chk "$p" "$o" "$g" "$m"; done
chk "$AIHF_REQUIREMENTS" root root 0644
chk "$AIHF_LAUNCHER" root root 0755
[ -L "$AIHF_RELEASE_CURRENT" ] && [ "$(stat -c '%U:%G' "$AIHF_RELEASE_CURRENT")" = "root:root" ] && pass "layout: $AIHF_RELEASE_CURRENT is a root-owned symlink" || fail "layout: $AIHF_RELEASE_CURRENT is not a root-owned symlink"
REL=$(readlink -f "$AIHF_RELEASE_CURRENT")
case "$REL" in "$AIHF_RELEASE_ROOT"/*) pass "release: current resolves inside the release root ($REL)" ;; *) fail "release: current resolves to '$REL', outside $AIHF_RELEASE_ROOT" ;; esac
for row in "${AIHF_CODEX_HOME_PROTECTED[@]}"; do read -r n t m <<<"$row"; chk "$AIHF_CODEX_HOME/$n" root root "$m"; done
for row in "${AIHF_OPS_HOME_PROTECTED[@]}"; do read -r n t m <<<"$row"; chk "$AIHF_OPS_HOME/$n" root root "$m"; done
# protected directories hold only root-owned entries, protected files have exactly the provisioned content (a planted name would otherwise pass an owner/mode check)
for h in "$AIHF_CODEX_HOME" "$AIHF_OPS_HOME"; do
  if [ "$h" = "$AIHF_CODEX_HOME" ]; then rows=("${AIHF_CODEX_HOME_PROTECTED[@]}"); else rows=("${AIHF_OPS_HOME_PROTECTED[@]}"); fi
  for row in "${rows[@]}"; do
    read -r n t m <<<"$row"; p="$h/$n"
    if [ "$t" = dir ]; then
      [ -z "$(find "$p" ! -user root -print -quit 2>/dev/null)" ] && [ -z "$(find "$p" -mindepth 1 -print -quit 2>/dev/null)" ] && pass "protected dir $p is empty and root-owned" || fail "protected dir $p contains entries or non-root-owned content"
    else
      case "$p" in
        "$AIHF_CODEX_HOME/fund-ops.config.toml") : ;;
        "$AIHF_CODEX_HOME/hooks.json") [ "$(cat "$p")" = '{"hooks":{}}' ] && pass "protected file $p has the provisioned inert content" || fail "protected file $p content differs" ;;
        "$AIHF_CODEX_HOME/config.toml") cfg_exp='# Root-owned user config for the fund-ops Codex home. Intentionally empty: authority is clamped by the managed requirements.'
          [ "$(cat "$p")" = "$cfg_exp" ] && [ "$(wc -c < "$p")" -eq $(( ${#cfg_exp} + 1 )) ] && pass "protected file $p equals the provisioned comment-only config exactly" || fail "protected file $p content differs" ;;
        *) [ ! -s "$p" ] && pass "protected file $p is empty as provisioned" || fail "protected file $p is not empty" ;;
      esac
    fi
  done
done

# ---- 3 content integrity
PINS="$HERE/canonical-artifacts.sha256"
reqwant=$(awk '$2=="config/codex/requirements.fund-ops.toml"{print $1}' "$PINS" 2>/dev/null)
[ -n "$reqwant" ] && [ "$(sha "$AIHF_REQUIREMENTS")" = "$reqwant" ] && pass "requirements: installed file equals the pinned canonical hash ($reqwant)" || fail "requirements: installed file differs from the pinned canonical hash"
if [ -n "$SRC" ] && [ -f "$SRC/config/codex/requirements.fund-ops.toml" ]; then
  [ "$(tr -d '\r' < "$SRC/config/codex/requirements.fund-ops.toml" | sha256sum | cut -d' ' -f1)" = "$(sha "$AIHF_REQUIREMENTS")" ] && pass "requirements: installed file equals the supplied source tree artifact" || fail "requirements: installed file differs from the supplied source tree"
fi
pwant=$(awk '$2=="config/codex/fund-ops.config.toml"{print $1}' "$PINS" 2>/dev/null)
[ -n "$pwant" ] && [ "$(sha "$AIHF_CODEX_HOME/fund-ops.config.toml")" = "$pwant" ] && pass "profile: installed fund-ops profile equals the pinned canonical hash" || fail "profile: installed fund-ops profile differs from the pin"
if [ -f "$REL/RELEASE-MANIFEST.sha256" ]; then
  ( cd "$REL" && sha256sum --quiet -c RELEASE-MANIFEST.sha256 ) >/dev/null 2>&1 && pass "release: every file matches RELEASE-MANIFEST.sha256" || fail "release: manifest verification failed"
  extra=$(cd "$REL" && find . -type f ! -name RELEASE-MANIFEST.sha256 | LC_ALL=C sort | wc -l)
  [ "$extra" -eq "$(wc -l < "$REL/RELEASE-MANIFEST.sha256")" ] && pass "release: no file outside the manifest" || fail "release: file count differs from the manifest"
else fail "release: RELEASE-MANIFEST.sha256 missing"; fi
[ -z "$(find "$REL" -name .git -print -quit 2>/dev/null)" ] && pass "release: no Git working tree" || fail "release: contains .git"
[ -z "$(find "$REL" -type l -print -quit 2>/dev/null)" ] && pass "release: no symbolic links" || fail "release: contains symbolic links"
w=$(find /opt/aihf ! -type l \( -perm /022 -o ! -user root \) -print -quit 2>/dev/null)
[ -z "$w" ] && pass "release/toolchain: everything under /opt/aihf is root-owned and not group/other-writable" || fail "release/toolchain: writable or non-root path: $w"
[ "$(sha "$AIHF_CODEX_BIN")" = "$AIHF_CODEX_SHA256" ] && pass "toolchain: Codex binary equals the pinned SHA-256" || fail "toolchain: Codex binary differs from the pinned SHA-256"
"$AIHF_CODEX_BIN" --version 2>/dev/null | grep -qx "codex-cli $AIHF_CODEX_PIN" && pass "toolchain: Codex $AIHF_CODEX_PIN at $AIHF_CODEX_BIN" || fail "toolchain: Codex version differs from the pin"
sh -n "$AIHF_LAUNCHER" 2>/dev/null && grep -q 'env -i' "$AIHF_LAUNCHER" && grep -q "$AIHF_CODEX_BIN" "$AIHF_LAUNCHER" && grep -q -- '--profile fund-ops' "$AIHF_LAUNCHER" && grep -q 'never run as root' "$AIHF_LAUNCHER" && pass "launcher: clean environment, absolute toolchain path, explicit fund-ops profile" || fail "launcher: content check failed"
if grep -rIlE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----|\b0x[0-9a-fA-F]{64}\b|\bsk-[A-Za-z0-9_-]{20,}' "$REL" /etc/codex "$AIHF_CODEX_HOME" "$AIHF_LAUNCHER" 2>/dev/null | grep -q .; then fail "secrets: secret-like material under the release, policy or Codex home"; else pass "secrets: no secret-like material under the release, policy or Codex home"; fi

[ -z "$(find "$REL" \( -name auth.json -o -name '.env' -o -name '*.pem' -o -name '*.key' \) -print -quit 2>/dev/null)" ] && pass "secrets: no credential-style files in the release" || fail "secrets: credential-style file in the release"
[ -z "$(find "$REL" ! -type f ! -type d -print -quit 2>/dev/null)" ] && pass "release: only regular files and directories (no devices, FIFOs, sockets)" || fail "release: contains special files"

# ---- 4 identity-level DENIAL tests (the ops identity attempts the forbidden writes)
denied() { # label, command... (must fail)
  local label="$1"; shift
  if as_ops "$@" >/dev/null 2>&1; then fail "denial: $label was ALLOWED"; else pass "denial: $label denied"; fi
}
allowed() { # label, command... (positive control: must succeed)
  local label="$1"; shift
  if as_ops "$@" >/dev/null 2>&1; then control "allowed (intended): $label"; else fail "control: $label failed, the denial tests above could be vacuous"; fi
}
req_before=$(sha "$AIHF_REQUIREMENTS")
denied "append to $AIHF_REQUIREMENTS" bash -c "echo x >> $AIHF_REQUIREMENTS"
denied "overwrite $AIHF_REQUIREMENTS" bash -c "echo x > $AIHF_REQUIREMENTS"
denied "unlink $AIHF_REQUIREMENTS" unlink "$AIHF_REQUIREMENTS"
denied "rename $AIHF_REQUIREMENTS" mv "$AIHF_REQUIREMENTS" "$AIHF_REQUIREMENTS.x"
denied "create a file in /etc/codex" touch /etc/codex/extra.toml
denied "create /etc/codex/config.toml (system config layer)" touch /etc/codex/config.toml
denied "create /etc/codex/managed_config.toml" touch /etc/codex/managed_config.toml
[ "$(sha "$AIHF_REQUIREMENTS")" = "$req_before" ] && pass "requirements unchanged after the attempts" || fail "requirements CHANGED during the attempts"
first=$(cd "$REL" && find . -type f ! -name RELEASE-MANIFEST.sha256 | LC_ALL=C sort | head -1)
denied "modify a file in the activated release ($first)" bash -c "echo x >> '$REL/$first'"
denied "unlink a file in the activated release" unlink "$REL/$first"
denied "create a file in the activated release root" touch "$REL/injected"
denied "create a file in the release directory of releases" touch "$AIHF_RELEASE_ROOT/injected"
denied "replace the current symlink" ln -sfn "$AIHF_SCRATCH" "$AIHF_RELEASE_CURRENT"
denied "replace the current symlink via rename" bash -c "ln -s $AIHF_SCRATCH $AIHF_SCRATCH/lnk && mv -T $AIHF_SCRATCH/lnk $AIHF_RELEASE_CURRENT"
[ "$(readlink -f "$AIHF_RELEASE_CURRENT")" = "$REL" ] && pass "current symlink unchanged after the attempts" || fail "current symlink CHANGED"
rm -f "$AIHF_SCRATCH/lnk"
denied "modify the Codex binary" bash -c ": >> $AIHF_CODEX_BIN"
denied "modify the launcher" bash -c "echo x >> $AIHF_LAUNCHER"
denied "create a file in /opt/aihf" touch /opt/aihf/injected
for row in "${AIHF_CODEX_HOME_PROTECTED[@]}"; do
  read -r n t m <<<"$row"; p="$AIHF_CODEX_HOME/$n"
  if [ "$t" = file ]; then denied "write protected Codex-home file $n" bash -c "echo x >> $p"; else denied "create an entry inside protected Codex-home directory $n" touch "$p/injected"; fi
  denied "unlink protected Codex-home name $n" bash -c "[ -d $p ] && rmdir $p || unlink $p"
  denied "rename protected Codex-home name $n" mv "$p" "$p.moved"
done
for row in "${AIHF_OPS_HOME_PROTECTED[@]}"; do
  read -r n t m <<<"$row"; p="$AIHF_OPS_HOME/$n"
  if [ "$t" = file ]; then denied "write protected HOME file $n" bash -c "echo x >> $p"; else denied "create an entry inside protected HOME directory $n (documented user skill root lives here)" touch "$p/injected"; fi
  denied "unlink protected HOME name $n" bash -c "[ -d $p ] && rmdir $p || unlink $p"
  denied "rename protected HOME name $n" mv "$p" "$p.moved"
done
denied "plant a user skill under HOME/.agents/skills" bash -c "mkdir -p $AIHF_OPS_HOME/.agents/skills/x && echo x > $AIHF_OPS_HOME/.agents/skills/x/SKILL.md"
allowed "create mutable state in the Codex home (Codex's own runtime files)" touch "$AIHF_CODEX_HOME/state_probe.sqlite"
allowed "remove that mutable state again" unlink "$AIHF_CODEX_HOME/state_probe.sqlite"
allowed "write to the runtime scratch directory" bash -c "echo ok > $AIHF_SCRATCH/probe && unlink $AIHF_SCRATCH/probe"
allowed "write to the runtime state directory" bash -c "echo ok > $AIHF_STATE/probe && unlink $AIHF_STATE/probe"
allowed "write mutable files in the ops home (non-protected names)" bash -c "echo ok > $AIHF_OPS_HOME/probe && unlink $AIHF_OPS_HOME/probe"
denied "create a file in the runtime root (parent of scratch/state)" touch "$AIHF_RUNTIME_ROOT/injected"
denied "rename the scratch directory away" mv "$AIHF_SCRATCH" "$AIHF_RUNTIME_ROOT/scratch.moved"
denied "create a file in /var/lib/aihf" touch /var/lib/aihf/injected
denied "create a file in /usr/local/bin" touch /usr/local/bin/injected
denied "modify /etc/passwd" bash -c "echo x >> /etc/passwd"
denied "read another identity's secret-style path (root-only file) /etc/shadow" cat /etc/shadow

# ---- 5 where can the ops identity write at all? (whole root filesystem; mounts are examined separately)
writable=$(as_ops find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt \) -prune -o -writable \( -type d -o -type f \) -print 2>/dev/null)
unexpected=$(printf '%s\n' "$writable" | grep -vE "^($AIHF_SCRATCH|$AIHF_STATE|$AIHF_OPS_HOME|$AIHF_CODEX_HOME)(/|\$)|^/tmp(/|\$)|^/var/tmp(/|\$)|^/var/crash(/|\$)|^/var/lock(/|\$)|^/dev/shm(/|\$)|^\$" || true)
protnames=$(for r in "${AIHF_CODEX_HOME_PROTECTED[@]}"; do read -r n _ <<<"$r"; printf '%s|' "$AIHF_CODEX_HOME/$n"; done; for r in "${AIHF_OPS_HOME_PROTECTED[@]}"; do read -r n _ <<<"$r"; printf '%s|' "$AIHF_OPS_HOME/$n"; done)
protwritable=$(printf '%s\n' "$writable" | grep -E "^(${protnames%|})(/|\$)" || true)
[ -z "$protwritable" ] && pass "writable set: no protected name (or anything beneath one) is writable by the ops identity" || fail "writable set: protected paths writable: $(printf '%s' "$protwritable" | head -3 | tr '\n' ' ')"
if [ -z "$unexpected" ]; then pass "writable set: the ops identity can write only scratch, state, ops home, the Codex home (mutable names) and the standard temporary directories"
else fail "writable set: unexpected writable paths: $(printf '%s' "$unexpected" | head -5 | tr '\n' ' ')"; fi
echo "NOTE    standard world-writable directories (/tmp, /var/tmp, /var/crash, /dev/shm) stay writable at the OS level; Codex's read-only profile does not grant them. Residual R6 in the threat model."

# ---- 6 WSL interoperability routes (report; FAIL if hardening is expected)
route() { # label, open? (0=open)
  if [ "$2" -eq 0 ]; then
    if [ "$HARDENED" -eq 1 ]; then fail "wsl route OPEN: $1"; else echo "ROUTE-OPEN   $1"; fi
  else
    if [ "$HARDENED" -eq 1 ]; then pass "wsl route closed: $1"; else echo "ROUTE-CLOSED $1"; fi
  fi
}
rw9p=$(awk '$3=="9p" || $3=="drvfs" || $3=="virtiofs" { print $2 "(" $4 ")" }' /proc/mounts | grep -v '^/usr/lib/wsl' | cut -c1-60 | head -3 | tr '\n' ' ')
[ -n "$rw9p" ] && route "Windows drives mounted, read-write or read-only (a mounted drive exposes host files and credentials to every uid): $rw9p" 0 || route "no Windows drives mounted" 1
[ -d /mnt/c ] && [ -n "$(ls -A /mnt/c 2>/dev/null | head -1)" ] && route "/mnt/c is populated (developer checkout and host credentials reachable)" 0 || route "/mnt/c is empty or absent" 1
# The WSLInterop binfmt handler stays registered even when [interop] enabled=false (observed on WSL 2.6.1), so registration is informational;
# the behavioral test is --pe-probe: a Windows executable placed inside the Linux filesystem must NOT run for the ops identity.
if [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] && grep -q '^enabled' /proc/sys/fs/binfmt_misc/WSLInterop 2>/dev/null; then echo "NOTE    WSLInterop binfmt handler is registered (informational; see the behavioral PE probe)"; fi
if [ -n "$PE" ]; then
  as_ops test -x "$PE" || fail "pe-probe: $PE is not executable by the ops identity, an empty result would be vacuous"
  peout=$(timeout 40 runuser -u "$AIHF_OPS_USER" -- env -i PATH=/usr/bin:/bin "$PE" 2>/dev/null | head -c 200)
  [ -n "$peout" ] && route "ops identity can execute a Windows executable placed in the Linux filesystem (interop live)" 0 || route "a Windows executable placed in the Linux filesystem does not run for the ops identity" 1
else echo "NOTE    no --pe-probe supplied: interop launch behavior not tested by this run"; fi
launch_assign=$(grep -E '^exec ' "$AIHF_LAUNCHER" | grep -oE '[A-Z_]+=' | tr -d '=' | LC_ALL=C sort | tr '\n' ' ')
[ "$launch_assign" = "CODEX_HOME HOME LANG PATH TERM " ] && pass "launcher: sets exactly CODEX_HOME HOME LANG PATH TERM under env -i (no WSLENV, no inherited variables)" || fail "launcher: environment assignments are '$launch_assign'"
grep -qE "^exec /usr/bin/env -i PATH=$AIHF_LAUNCHER_PATH_ENV " "$AIHF_LAUNCHER" && pass "launcher: PATH is the clean system path" || fail "launcher: PATH differs from the clean system path"
winpath=$(runuser -u "$AIHF_OPS_USER" -- bash -lc 'echo "$PATH"' 2>/dev/null)
echo "$winpath" | grep -q '/mnt/' && route "Windows directories in a plain login-shell PATH of the ops user" 0 || route "no Windows directories in a plain login-shell PATH of the ops user" 1
runuser -u "$AIHF_OPS_USER" -- bash -lc 'command -v cmd.exe powershell.exe >/dev/null' 2>/dev/null && route "cmd.exe/powershell.exe resolvable by the ops user" 0 || route "cmd.exe/powershell.exe not resolvable by the ops user" 1
as_ops bash -c 'ls /mnt/c/Windows/System32/cmd.exe' >/dev/null 2>&1 && route "ops identity can reach cmd.exe through /mnt/c" 0 || route "ops identity cannot reach cmd.exe through /mnt/c" 1
as_ops bash -c 'ls /mnt/c/TEST-repos' >/dev/null 2>&1 && route "ops identity can list the developer checkout location" 0 || route "ops identity cannot list the developer checkout location" 1
if [ "$HARDENED" -eq 1 ]; then
  cmp -s "$HERE/wsl.conf.fund-ops" "$AIHF_WSL_CONF" && pass "wsl.conf equals the canonical template" || fail "wsl.conf differs from the canonical template"
fi
[ -S /var/run/docker.sock ] && route "Docker socket present in the distro" 0 || route "no Docker socket in the distro" 1

echo "SUMMARY verify: hardened_expected=$HARDENED failures=$fails"
[ "$fails" -eq 0 ]
