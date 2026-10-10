#!/bin/bash
# Step 2 of 3 (provision): operator-run, root-only provisioning of the isolated fund-ops runtime on a DEDICATED WSL2 Ubuntu distro.
# Operator-run administrative artifact only (see ops/provision/README.md). It must never be invoked by Codex, a service or any model-facing code.
#
#   fund-ops-provision.sh plan  [options]     default: print every action, change nothing
#   fund-ops-provision.sh apply [options]     explicit system mutation (root required)
#
# Options:
#   --release-id ID        release directory name under the release root (required for apply; letters, digits, . _ -)
#   --codex-dir DIR        extracted official Codex package directory containing bin/codex (version must equal the pin)
#   --node-dir DIR         optional extracted Node directory to install into the root-owned toolchain
#   --configure-wsl        also install the hardened /etc/wsl.conf (per-distro; effective after `wsl --terminate`)
#   --replace-requirements allow replacing a DIFFERENT installed requirements file (after reviewing the diff)
#   --allow-mnt-source     allow a source tree on a Windows mount (proof runs only; production uses a Linux-native tree)
#
# Properties: idempotent; never widens permissions silently; installs the managed requirements byte-for-byte from the reviewed
# canonical artifact after verifying its pinned SHA-256; the activated release is root-owned, has no Git working tree and is switched
# atomically; mutable state lives only under the runtime and ops-home directories. No secret material is handled (the signer sentinel is a fixed non-secret marker).
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SRC=$(cd "$HERE/../.." && pwd -P)
. "$HERE/fund-ops-layout.sh"

ACTION="${1:-plan}"; [ $# -gt 0 ] && shift
RELEASE_ID=""; CODEX_SRC=""; NODE_SRC=""; CONFIGURE_WSL=0; REPLACE_REQ=0; ALLOW_MNT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --release-id) RELEASE_ID="$2"; shift 2 ;;
    --codex-dir) CODEX_SRC="$2"; shift 2 ;;
    --node-dir) NODE_SRC="$2"; shift 2 ;;
    --configure-wsl) CONFIGURE_WSL=1; shift ;;
    --replace-requirements) REPLACE_REQ=1; shift ;;
    --allow-mnt-source) ALLOW_MNT=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
case "$ACTION" in plan) APPLY=0 ;; apply) APPLY=1 ;; *) echo "usage: $0 plan|apply [options]" >&2; exit 64 ;; esac

die() { echo "REFUSED: $*" >&2; exit 1; }
step() { echo "STEP    $*"; }
act() { if [ "$APPLY" -eq 1 ]; then "$@"; else echo "PLAN    $*"; fi; }
lf_sha() { tr -d '\r' < "$1" | sha256sum | cut -d' ' -f1; }
pinned() { awk -v f="$1" '$2 == f { print $1 }' "$HERE/canonical-artifacts.sha256"; }

# ---------------------------------------------------------------- safe privileged path handling (FU-0011 / R15)
# Invariant: privileged mutation never follows or trusts a filesystem object that a lower-trust identity (ops or a service) can replace.
# Every path that root creates, chowns, chmods or renames into is walked component by component. Each component is examined with a NON-following stat,
# opened, and the open descriptor must be the very object that was examined (same type, owner, mode, device and inode). The next component is then
# resolved relative to that descriptor (/proc/self/fd/N), so a swap after the check cannot redirect the walk, and the mutation is applied THROUGH the
# verified descriptor. A symbolic link, any non-directory, a foreign owner or an untrusted ancestor is refused, never repaired through. Nothing is recursive.
unsafe() { die "unsafe path $1: $2"; }
PMETA='%F|%u|%g|%a|%h|%d:%i'
lmeta() { stat -c "$PMETA" -- "$1" 2>/dev/null; }            # does not follow the final component
fdmeta() { stat -L -c "$PMETA" -- "/proc/self/fd/$1" 2>/dev/null; }
SAFE_FDS=(); SAFE_FD=""; SAFE_CREATED=0
safe_close() { local f; for f in "${SAFE_FDS[@]}"; do exec {f}<&-; done; SAFE_FDS=(); SAFE_FD=""; }
table_owner() { local row p o g m; for row in "${AIHF_DIRS[@]}"; do read -r p o g m <<<"$row"; if [ "$p" = "$1" ]; then echo "$o:$g"; return 0; fi; done; return 0; }
getent_exists() { # exit 0 = present, 2 = absent; any other failure is refused, never read as "absent"
  local rc=0; getent "$@" >/dev/null || rc=$?
  case "$rc" in 0) return 0 ;; 2) return 1 ;; *) die "getent $* failed (exit $rc); cannot establish whether the account or group exists" ;; esac
}
safe_walk() { # abs_path create(0|1): sets SAFE_FD to the verified descriptor of the last component; SAFE_CREATED=1 if it was made by this call
  local path="$1" create="$2" cur="" cand prev="" meta type u g mode nl ident fd i n own c
  local -a comps
  SAFE_CREATED=0
  [[ "$path" =~ ^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || unsafe "$path" "is not a normalized absolute path"
  IFS=/ read -ra comps <<<"${path#/}"; n=${#comps[@]}
  for c in "${comps[@]}"; do if [ "$c" = . ] || [ "$c" = .. ]; then unsafe "$path" "contains a dot component"; fi; done
  for ((i = 0; i < n; i++)); do
    cur="$cur/${comps[$i]}"
    if [ -z "$prev" ]; then cand="$cur"; else cand="/proc/self/fd/$prev/${comps[$i]}"; fi
    meta=$(lmeta "$cand") || meta=""
    if [ -z "$meta" ]; then
      if [ "$i" -eq $((n - 1)) ] && [ "$create" -eq 1 ]; then
        mkdir -m 0700 -- "$cand" || unsafe "$cur" "cannot be created"
        SAFE_CREATED=1; meta=$(lmeta "$cand") || unsafe "$cur" "vanished right after creation"
      else unsafe "$cur" "does not exist"; fi
    fi
    IFS='|' read -r type u g mode nl ident <<<"$meta"
    [ "$type" != "symbolic link" ] || unsafe "$cur" "is a symbolic link"
    [ "$type" = directory ] || unsafe "$cur" "is not a directory (type: $type)"
    exec {fd}<"$cand" || unsafe "$cur" "cannot be opened"
    SAFE_FDS+=("$fd")
    [ "$(fdmeta "$fd")" = "$meta" ] || unsafe "$cur" "changed between inspection and open"
    if [ "$i" -lt $((n - 1)) ]; then # an ancestor must be unreplaceable by a lower-trust identity: root-owned and not group/other-writable, or a layout directory with its layout owner
      if [ "$u" -ne 0 ] || [ $((8#$mode & 8#022)) -ne 0 ]; then
        own=$(table_owner "$cur")
        [ -n "$own" ] && [ "$(stat -L -c '%U:%G' -- "/proc/self/fd/$fd")" = "$own" ] || unsafe "$cur" "is an ancestor that is neither root-owned without group/other write nor a layout directory with its layout owner"
      fi
    fi
    prev="$fd"
  done
  SAFE_FD="$prev"
}
safe_dir() { # path owner group mode: create or verify a real directory; only its mode is converged, through the verified descriptor
  local p="$1" o="$2" g="$3" m="$4" fdp og mode
  safe_walk "$p" 1; fdp="/proc/self/fd/$SAFE_FD"
  if [ "$SAFE_CREATED" -eq 1 ]; then chown -- "$o:$g" "$fdp"
  else
    og=$(stat -L -c '%U:%G' -- "$fdp")
    [ "$og" = "$o:$g" ] || unsafe "$p" "owner:group is $og, the layout requires $o:$g (refusing to chown through it)"
  fi
  mode=$(stat -L -c '%a' -- "$fdp")
  if [ "$mode" != "${m#0}" ]; then
    chmod -- "$m" "$fdp"
    [ "$SAFE_CREATED" -eq 1 ] || echo "WARN    $p mode was $mode, restored to $m"
  fi
  safe_close
}
safe_chmod_root_dir() { # path mode: chmod an existing root-owned real directory through its verified descriptor
  safe_walk "$1" 0
  [ "$(stat -L -c '%U' -- "/proc/self/fd/$SAFE_FD")" = root ] || unsafe "$1" "is not root-owned"
  chmod -- "$2" "/proc/self/fd/$SAFE_FD"; safe_close
}
safe_install_file() { # staged_file dest: atomically replace a regular file inside a verified layout directory; never follows or overwrites anything else
  local src="$1" dest="$2" dir name target meta type u g mode nl ident want
  dir=$(dirname -- "$dest"); name=$(basename -- "$dest")
  want=$(table_owner "$dir"); [ -n "$want" ] || unsafe "$dir" "is not a layout directory"
  safe_walk "$dir" 0
  [ "$(stat -L -c '%U:%G' -- "/proc/self/fd/$SAFE_FD")" = "$want" ] || unsafe "$dir" "owner:group differs from the layout owner $want"
  target="/proc/self/fd/$SAFE_FD/$name"
  if meta=$(lmeta "$target"); then
    IFS='|' read -r type u g mode nl ident <<<"$meta"
    [ "$type" != "symbolic link" ] || unsafe "$dest" "is a symbolic link"
    case "$type" in "regular file"|"regular empty file") ;; *) unsafe "$dest" "is not a regular file (type: $type)" ;; esac
    [ "$nl" -eq 1 ] || unsafe "$dest" "has $nl hard links"
    [ "$(stat -c '%U:%G' -- "$target")" = "$want" ] || unsafe "$dest" "owner:group is $(stat -c '%U:%G' -- "$target"), the layout requires $want"
  fi
  mv -T -- "$src" "$target"; safe_close
}
# processes: matched by NUMERIC uid (real, effective, saved or filesystem), never by name or command line, for the ops identity and every service identity
identity_has_processes() { # uid
  local f line k ru eu su fu rest
  for f in /proc/[0-9]*/status; do
    [ -r "$f" ] || continue
    line=$(grep -m1 '^Uid:' "$f" 2>/dev/null) || continue
    read -r k ru eu su fu rest <<<"$line"
    if [ "$ru" = "$1" ] || [ "$eu" = "$1" ] || [ "$su" = "$1" ] || [ "$fu" = "$1" ]; then return 0; fi
  done
  return 1
}
require_no_identity_processes() {
  local u uid row svc_u svc_h
  [ -r /proc/self/status ] || die "/proc is not readable; cannot check for running ops or service processes"
  local -a names=("$AIHF_OPS_USER")
  for row in "${AIHF_SERVICES[@]}"; do read -r svc_u svc_h <<<"$row"; names+=("$svc_u"); done
  for u in "${names[@]}"; do
    getent_exists passwd "$u" || continue # an account that does not exist yet owns no processes
    uid=$(id -u "$u"); [[ "$uid" =~ ^[0-9]+$ ]] || die "cannot resolve the uid of $u"
    if identity_has_processes "$uid"; then die "processes owned by $u (uid $uid) are running; run 'wsl --terminate <distro>' and provision from a fresh start"; fi
  done
}

# ---------------------------------------------------------------- preflight (read-only)
step "preflight"
[ "$(uname -s)" = "Linux" ] || die "Linux only (the canonical runtime is a dedicated WSL2 Ubuntu distro)"
if [ "$APPLY" -eq 1 ]; then [ "$(id -u)" -eq 0 ] || die "apply requires root (an explicit operator action)"; fi
case "$SRC" in /mnt/*) [ "$ALLOW_MNT" -eq 1 ] || die "source tree is on a Windows mount ($SRC); production provisioning uses a Linux-native tree (override only for proof runs)" ;; esac
bash "$HERE/fund-ops-validate.sh" >/dev/null || { bash "$HERE/fund-ops-validate.sh" || true; die "canonical artifacts failed validation"; }
echo "OK      canonical artifacts validated against pinned hashes"
if [ "$APPLY" -eq 1 ]; then
  [[ "$RELEASE_ID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "--release-id is required and must match [A-Za-z0-9._-]{1,64}"
  [ -n "$CODEX_SRC" ] && [ -x "$CODEX_SRC/bin/codex" ] || die "--codex-dir must contain an executable bin/codex"
  [ "$(sha256sum "$CODEX_SRC/bin/codex" | cut -d' ' -f1)" = "$AIHF_CODEX_SHA256" ] || die "the Codex binary differs from the pinned SHA-256 (it is not executed as root until it matches)"
  [ "$("$CODEX_SRC/bin/codex" --version 2>/dev/null)" = "codex-cli $AIHF_CODEX_PIN" ] || die "Codex version differs from the pin $AIHF_CODEX_PIN"
  # a running ops or service process could race the replacement of protected names or plant a link in its own tree during re-apply: refuse
  # (stop the distro and provision from a fresh start). Keyed on numeric uid; a getent failure is refused, never read as "no such account".
  require_no_identity_processes
  if [ -n "$NODE_SRC" ]; then [ -x "$NODE_SRC/bin/node" ] || die "--node-dir must contain bin/node"; fi
fi

# ---------------------------------------------------------------- identity
step "dedicated unprivileged identity $AIHF_OPS_USER"
if ! getent_exists group "$AIHF_OPS_GROUP"; then act groupadd --system "$AIHF_OPS_GROUP"; fi
if ! getent_exists passwd "$AIHF_OPS_USER"; then
  act useradd --system --gid "$AIHF_OPS_GROUP" --home-dir "$AIHF_OPS_HOME" --no-create-home --shell "$AIHF_OPS_SHELL" --comment "AIHF fund-ops (unprivileged)" "$AIHF_OPS_USER"
else
  [ "$(id -u "$AIHF_OPS_USER")" -ne 0 ] || die "$AIHF_OPS_USER has uid 0"
  [ "$(id -nG "$AIHF_OPS_USER")" = "$AIHF_OPS_GROUP" ] || die "$AIHF_OPS_USER has supplementary groups ($(id -nG "$AIHF_OPS_USER")); refusing to continue"
fi
if grep -rEq -e "(^|[^[:alnum:]_-])%?$AIHF_OPS_USER([^[:alnum:]_-]|\$)" /etc/sudoers /etc/sudoers.d 2>/dev/null; then die "$AIHF_OPS_USER is referenced in sudoers"; fi
if [ "$APPLY" -eq 1 ] && getent_exists passwd "$AIHF_OPS_USER"; then sudo -n -l -U "$AIHF_OPS_USER" 2>&1 | grep -qi 'not allowed' || die "$AIHF_OPS_USER has sudo rights"; fi
act passwd -l "$AIHF_OPS_USER" >/dev/null

# ---------------------------------------------------------------- service identities (P1-S3B; identities and directories only, no service is installed or started)
step "service identities (private group, no supplementary groups, no sudo, locked password, non-login shell)"
for row in "${AIHF_SERVICES[@]}"; do
  read -r svc_user svc_home <<<"$row"
  if ! getent_exists group "$svc_user"; then act groupadd --system "$svc_user"; fi
  if ! getent_exists passwd "$svc_user"; then
    act useradd --system --gid "$svc_user" --home-dir "$svc_home" --no-create-home --shell "$AIHF_SERVICE_SHELL" --comment "AIHF service identity (unprivileged)" "$svc_user"
  else
    [ "$(id -u "$svc_user")" -ne 0 ] || die "$svc_user has uid 0"
    [ "$(id -nG "$svc_user")" = "$svc_user" ] || die "$svc_user has supplementary groups ($(id -nG "$svc_user")); refusing to continue"
    [ "$(getent passwd "$svc_user" | cut -d: -f6,7)" = "$svc_home:$AIHF_SERVICE_SHELL" ] || die "$svc_user has a different home or shell than the layout contract"
  fi
  # a private group has no member other than its owner: never shared with aihf-ops or another service
  [ -z "$(getent group "$svc_user" | cut -d: -f4)" ] || die "group $svc_user has explicit members (private groups have none)"
  if grep -rEq -e "(^|[^[:alnum:]_-])%?$svc_user([^[:alnum:]_-]|\$)" /etc/sudoers /etc/sudoers.d 2>/dev/null; then die "$svc_user is referenced in sudoers"; fi
  if [ "$APPLY" -eq 1 ] && getent_exists passwd "$svc_user"; then sudo -n -l -U "$svc_user" 2>&1 | grep -qi 'not allowed' || die "$svc_user has sudo rights"; fi
  act passwd -l "$svc_user" >/dev/null
done

# ---------------------------------------------------------------- directories
step "directory layout (ownership and modes from the layout table; links, foreign owners and untrusted ancestors are refused, never followed)"
for row in "${AIHF_DIRS[@]}"; do
  read -r p o g m <<<"$row"
  act safe_dir "$p" "$o" "$g" "$m"
done

# ---------------------------------------------------------------- toolchain (root-owned)
install_tree() { # src dst
  local s="$1" d="$2" tmp
  tmp="$d.new.$$"
  act rm -rf "$tmp"
  act cp -a "$s" "$tmp"
  act chown -R root:root "$tmp"
  act chmod -R go-w "$tmp"
  [ -e "$d" ] && act mv -T "$d" "$d.old.$$"
  act mv -T "$tmp" "$d"
  act rm -rf "$d.old.$$"
}
step "root-owned toolchain (Codex $AIHF_CODEX_PIN)"
if [ "$APPLY" -eq 0 ] || ! [ -x "$AIHF_CODEX_BIN" ] || [ "$(sha256sum "$CODEX_SRC/bin/codex" | cut -d' ' -f1)" != "$(sha256sum "$AIHF_CODEX_BIN" | cut -d' ' -f1)" ]; then
  install_tree "${CODEX_SRC:-<codex-dir>}" "$AIHF_CODEX_DIR"
else echo "OK      Codex toolchain already installed and identical"; fi
if [ -n "$NODE_SRC" ]; then step "root-owned Node toolchain"; install_tree "$NODE_SRC" "$AIHF_NODE_DIR"; fi

# ---------------------------------------------------------------- managed requirements
step "managed requirements -> $AIHF_REQUIREMENTS"
REQ_SRC="$SRC/config/codex/requirements.fund-ops.toml"
WANT=$(pinned config/codex/requirements.fund-ops.toml)
[ -n "$WANT" ] && [ "$(lf_sha "$REQ_SRC")" = "$WANT" ] || die "canonical requirements differ from the pinned hash"
TMP_REQ="/etc/codex/.requirements.toml.$$"
if [ "$APPLY" -eq 1 ]; then
  tr -d '\r' < "$REQ_SRC" > "$TMP_REQ"; chown root:root "$TMP_REQ"; chmod 0644 "$TMP_REQ"
  [ "$(sha256sum "$TMP_REQ" | cut -d' ' -f1)" = "$WANT" ] || { rm -f "$TMP_REQ"; die "staged requirements hash mismatch"; }
  if [ -e "$AIHF_REQUIREMENTS" ] && ! cmp -s "$TMP_REQ" "$AIHF_REQUIREMENTS"; then
    if [ "$REPLACE_REQ" -ne 1 ]; then diff -u "$AIHF_REQUIREMENTS" "$TMP_REQ" || true; rm -f "$TMP_REQ"; die "a DIFFERENT requirements file is installed; review the diff and pass --replace-requirements"; fi
  fi
  mv -T "$TMP_REQ" "$AIHF_REQUIREMENTS"
  echo "OK      installed requirements sha256=$WANT"
else echo "PLAN    install canonical requirements (sha256 $WANT) to $AIHF_REQUIREMENTS root:root 0644"; fi

# ---------------------------------------------------------------- protected surfaces (Codex home and HOME)
# Both homes are root:aihf-ops 1770 (sticky, group-writable): the ops identity can create its own mutable files but cannot replace or remove
# root-owned names. Every protected name is staged in a ROOT-ONLY directory (its parent is root 0755), so the ops identity can never pre-create or
# race a staging name, and installed with an atomic move that replaces, and never follows, anything planted at the final name.
step "protected surfaces under $AIHF_CODEX_HOME and $AIHF_OPS_HOME"
PROFILE_SRC="$SRC/config/codex/fund-ops.config.toml"
PWANT=$(pinned config/codex/fund-ops.config.toml)
[ -n "$PWANT" ] && [ "$(lf_sha "$PROFILE_SRC")" = "$PWANT" ] || die "canonical fund-ops profile differs from the pinned hash"
STAGE_ROOT="/var/lib/aihf/ops/.stage.$$"
cleanup_stage() { rm -rf --one-file-system -- "$STAGE_ROOT" 2>/dev/null || true; }
trap cleanup_stage EXIT
install_protected() { # home_dir, rows...
  local home="$1"; shift
  local row n t m p tmp
  for row in "$@"; do
    read -r n t m <<<"$row"
    p="$home/$n"
    if [ "$APPLY" -eq 0 ]; then echo "PLAN    root-owned $t $p $m"; continue; fi
    tmp="$STAGE_ROOT/$n"
    if [ "$t" = dir ]; then
      install -d -o root -g root -m "$m" "$tmp"
    else
      case "$p" in
        "$AIHF_CODEX_HOME/fund-ops.config.toml")
          tr -d '\r' < "$PROFILE_SRC" > "$tmp"
          [ "$(sha256sum "$tmp" | cut -d' ' -f1)" = "$PWANT" ] || die "staged profile hash mismatch" ;;
        "$AIHF_CODEX_HOME/hooks.json") printf '{"hooks":{}}\n' > "$tmp" ;;
        "$AIHF_CODEX_HOME/config.toml") printf '# Root-owned user config for the fund-ops Codex home. Intentionally empty: authority is clamped by the managed requirements.\n' > "$tmp" ;;
        *) : > "$tmp" ;;
      esac
      chown root:root "$tmp"
      chmod "$m" "$tmp"
    fi
    # keep an existing root-owned real directory whose whole tree is root-owned; otherwise replace it (it may have been planted)
    if [ "$t" = dir ] && [ -d "$p" ] && [ ! -L "$p" ] && [ "$(stat -c %U "$p")" = root ] && [ -z "$(find "$p" ! -user root -print -quit)" ] && [ -z "$(find "$p" -mindepth 1 -print -quit)" ]; then
      safe_chmod_root_dir "$p" "$m"
      continue
    fi
    if [ -e "$p" ] || [ -L "$p" ]; then
      if ! { [ "$t" = file ] && [ -f "$p" ] && [ ! -L "$p" ]; }; then rm -rf --one-file-system -- "$p"; fi
    fi
    mv -T -- "$tmp" "$p"
  done
}
if [ "$APPLY" -eq 1 ]; then install -d -o root -g root -m 0700 "$STAGE_ROOT"; fi
install_protected "$AIHF_CODEX_HOME" "${AIHF_CODEX_HOME_PROTECTED[@]}"
install_protected "$AIHF_OPS_HOME" "${AIHF_OPS_HOME_PROTECTED[@]}"

# ---------------------------------------------------------------- signer sentinel and inert fundctl (staged in the root-only directory, installed by atomic rename)
step "signer sentinel $AIHF_SIGNER_SENTINEL (fixed non-secret marker, aihf-signerd 0600) and root-only inert fundctl $AIHF_FUNDCTL"
FC_SRC="$SRC/$AIHF_FUNDCTL_SOURCE"
FC_WANT=$(pinned "$AIHF_FUNDCTL_SOURCE")
[ -n "$FC_WANT" ] && [ "$(lf_sha "$FC_SRC")" = "$FC_WANT" ] || die "canonical fundctl differs from the pinned hash"
if [ "$APPLY" -eq 1 ]; then
  printf '%s\n' "$AIHF_SIGNER_SENTINEL_CONTENT" > "$STAGE_ROOT/sentinel"
  chown aihf-signerd:aihf-signerd "$STAGE_ROOT/sentinel"; chmod 0600 "$STAGE_ROOT/sentinel"
  safe_install_file "$STAGE_ROOT/sentinel" "$AIHF_SIGNER_SENTINEL"
  tr -d '\r' < "$FC_SRC" > "$STAGE_ROOT/fundctl"
  [ "$(sha256sum "$STAGE_ROOT/fundctl" | cut -d' ' -f1)" = "$FC_WANT" ] || die "staged fundctl hash mismatch"
  chown root:root "$STAGE_ROOT/fundctl"; chmod 0700 "$STAGE_ROOT/fundctl"
  mv -T -- "$STAGE_ROOT/fundctl" "$AIHF_FUNDCTL"
  echo "OK      installed sentinel and fundctl sha256=$FC_WANT"
else
  echo "PLAN    write the fixed non-secret sentinel marker to $AIHF_SIGNER_SENTINEL aihf-signerd:aihf-signerd 0600"
  echo "PLAN    install canonical fundctl (sha256 $FC_WANT) to $AIHF_FUNDCTL root:root 0700"
fi

# ---------------------------------------------------------------- release (read-only, atomic activation)
tree_manifest() { ( cd "$1" && find . -type f ! -name RELEASE-MANIFEST.sha256 ! -path './.git/*' ! -path './node_modules/*' ! -path './.runtime/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum ); }
step "release ${RELEASE_ID:-<release-id>} -> $AIHF_RELEASE_ROOT (root-owned, no Git working tree)"
REL="$AIHF_RELEASE_ROOT/${RELEASE_ID:-<release-id>}"
if [ "$APPLY" -eq 1 ]; then
  if [ -n "$(cd "$SRC" && find . ! -type f ! -type d ! -path './.git/*' ! -path './node_modules/*' -print -quit)" ]; then die "the source tree contains symbolic links or special files; a release has only regular files and directories"; fi
  if [ -e "$REL" ]; then
    [ "$(tree_manifest "$SRC")" = "$(cat "$REL/RELEASE-MANIFEST.sha256")" ] || die "release $RELEASE_ID exists with different content; releases are immutable, choose a new id"
    echo "OK      release $RELEASE_ID already installed and identical"
  else
    STAGE="$AIHF_RELEASE_ROOT/.stage-$RELEASE_ID-$$"
    mkdir "$STAGE"
    ( cd "$SRC" && tar --exclude=./.git --exclude=./node_modules --exclude=./.runtime -cf - . ) | tar -xf - -C "$STAGE"
    chown -R root:root "$STAGE"
    tree_manifest "$STAGE" > "$STAGE/RELEASE-MANIFEST.sha256"
    chown root:root "$STAGE/RELEASE-MANIFEST.sha256"
    chmod -R u=rX,go=rX "$STAGE"
    mv -T "$STAGE" "$REL"
    echo "OK      release $RELEASE_ID installed ($(wc -l < "$REL/RELEASE-MANIFEST.sha256") files)"
  fi
  LINK_TMP="/opt/aihf/.current.tmp.$$"
  ln -s "releases/$RELEASE_ID" "$LINK_TMP"
  mv -T "$LINK_TMP" "$AIHF_RELEASE_CURRENT"
  echo "OK      activated $AIHF_RELEASE_CURRENT -> releases/$RELEASE_ID (atomic rename)"
else echo "PLAN    copy the source tree (without .git) to $REL, root-owned and read-only, write RELEASE-MANIFEST.sha256, then atomically point $AIHF_RELEASE_CURRENT at it"; fi

# ---------------------------------------------------------------- launcher
step "root-owned launcher $AIHF_LAUNCHER (clean environment, absolute toolchain path, explicit profile)"
if [ "$APPLY" -eq 1 ]; then
  cat > "$AIHF_LAUNCHER.tmp.$$" <<LAUNCH
#!/bin/sh
# Generated by fund-ops-provision.sh; root-owned. Starts Codex for fund-ops with a clean environment (no inherited variables).
[ "\$(id -u)" -ne 0 ] || { echo "fund-ops must never run as root" >&2; exit 1; }
cd $AIHF_RELEASE_CURRENT || exit 1
exec /usr/bin/env -i PATH=$AIHF_LAUNCHER_PATH_ENV HOME=$AIHF_OPS_HOME CODEX_HOME=$AIHF_CODEX_HOME LANG=C.UTF-8 TERM="\${TERM:-dumb}" $AIHF_CODEX_BIN --profile fund-ops "\$@"
LAUNCH
  chown root:root "$AIHF_LAUNCHER.tmp.$$"; chmod 0755 "$AIHF_LAUNCHER.tmp.$$"; mv -T "$AIHF_LAUNCHER.tmp.$$" "$AIHF_LAUNCHER"
else echo "PLAN    write launcher root:root 0755"; fi

# ---------------------------------------------------------------- WSL hardening (per distro)
if [ "$CONFIGURE_WSL" -eq 1 ]; then
  step "WSL hardening -> $AIHF_WSL_CONF"
  if [ "$APPLY" -eq 1 ]; then
    [ ! -e "$AIHF_WSL_CONF" ] || [ -e "$AIHF_WSL_CONF.pre-aihf" ] || cp -p "$AIHF_WSL_CONF" "$AIHF_WSL_CONF.pre-aihf"
    install -o root -g root -m 0644 "$HERE/wsl.conf.fund-ops" "$AIHF_WSL_CONF"
    echo "OK      installed; run 'wsl --terminate <distro>' from Windows for it to take effect"
  else echo "PLAN    install wsl.conf.fund-ops to $AIHF_WSL_CONF"; fi
fi

# ---------------------------------------------------------------- audit
if [ "$APPLY" -eq 1 ]; then
  [ -e "$AIHF_AUDIT_LOG" ] || install -o root -g root -m 0640 /dev/null "$AIHF_AUDIT_LOG"
  printf '%s apply release=%s requirements_sha256=%s profile_sha256=%s codex=%s wsl=%s operator_uid=%s\n' "$(date -u +%FT%TZ)" "$RELEASE_ID" "$WANT" "$PWANT" "$AIHF_CODEX_PIN" "$CONFIGURE_WSL" "${SUDO_UID:-0}" >> "$AIHF_AUDIT_LOG"
fi
echo "DONE    $ACTION (verify with fund-ops-verify.sh)"
