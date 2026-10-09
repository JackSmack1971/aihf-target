#!/bin/bash
# FU-0011 / R15 live hostile harness: privileged provisioner re-apply against planted links and substituted objects.
# Operator/CI tooling, not product code (lives under tests/). Run as root, ONLY inside a disposable WSL distro that is named in AIHF_DISPOSABLE_DISTRO.
# It uses harmless sentinel files only: no key, seed or credential exists or is created. Decoy "secret-like" strings are generated at run time.
#
#   AIHF_DISPOSABLE_DISTRO=<name> provision-reapply-hostile.sh --provisioner <fund-ops-provision.sh> --codex-dir <dir> --release-id <id> --out <dir> [--provisioned] [--only <regex>]
#
# Default: the distro must be FRESH (no /opt/aihf, no /var/lib/aihf); the harness performs the clean first apply itself. --provisioned expects a provisioned distro (used for mutants).
# For every hostile case it proves: (1) the provisioner exits non-zero with the expected refusal reason, (2) the external target is unchanged,
# (3) ownership and modes of every protected path are unchanged, (4) no secret-like material is exposed; and then that unplanting restores a clean re-apply.
# Output lines: PASS | FAIL | CONTROL. Exit 0 only if there are no FAIL lines.
set -u
PROV=""; CODEX=""; RID=""; OUT=""; ONLY=""; PROVISIONED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --provisioner) PROV="$2"; shift 2 ;; --codex-dir) CODEX="$2"; shift 2 ;; --release-id) RID="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;; --only) ONLY="$2"; shift 2 ;; --provisioned) PROVISIONED=1; shift ;;
    *) echo "unknown option $1" >&2; exit 64 ;;
  esac
done
refuse() { echo "REFUSED: $*" >&2; exit 64; }
[ "$(uname -s)" = Linux ] || refuse "Linux only"
[ "$(id -u)" -eq 0 ] || refuse "needs root"
[[ "${AIHF_DISPOSABLE_DISTRO:-}" =~ ^aihf-[a-z0-9-]{3,40}$ ]] || refuse "AIHF_DISPOSABLE_DISTRO must name a disposable aihf-* distro"
[ "${WSL_DISTRO_NAME:-}" = "$AIHF_DISPOSABLE_DISTRO" ] || refuse "WSL_DISTRO_NAME (${WSL_DISTRO_NAME:-unset}) is not the declared disposable distro"
[ -f "$PROV" ] && [ -d "$CODEX" ] && [ -n "$RID" ] && [ -n "$OUT" ] || refuse "--provisioner, --codex-dir, --release-id and --out are required"
mkdir -p "$OUT/cases" || refuse "cannot create $OUT"
if [ "$PROVISIONED" -eq 0 ]; then
  [ ! -e /opt/aihf ] && [ ! -e /var/lib/aihf ] && [ ! -e /etc/codex ] && ! getent passwd aihf-ops >/dev/null || refuse "a FRESH distro is required (aihf state exists); use --provisioned for a provisioned one"
fi
. "$(dirname "$PROV")/fund-ops-layout.sh"

EXT=/var/tmp/fu0011-ext
SD=/var/lib/aihf/signerd; SEC=$SD/secrets; SENT=$SEC/sentinel
VICTIM_MARK="FU0011-EXTERNAL-VICTIM"
npass=0; nfail=0
pass() { echo "PASS    $1"; npass=$((npass + 1)); }
fail() { echo "FAIL    $1"; nfail=$((nfail + 1)); }
control() { echo "CONTROL $1"; }
as_svc() { local u="$1"; shift; runuser -u "$u" -- env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 "$@"; }
selected() { [ -z "$ONLY" ] || [[ "$1" =~ $ONLY ]]; }

RC=0
run_apply() { # logfile [extra env assignments...]
  local log="$1"; shift
  env "$@" bash "$PROV" apply --release-id "$RID" --codex-dir "$CODEX" >"$log" 2>&1 </dev/null; RC=$?
}
run_plan() { env "$@" bash "$PROV" plan --release-id "$RID" --codex-dir "$CODEX" >"$LOG" 2>&1 </dev/null; RC=$?; }

fresh_ext() { # an external world the provisioner must never touch: only harmless sentinels
  rm -rf --one-file-system -- "$EXT"
  install -d -o root -g root -m 0755 "$EXT" "$EXT/victim-dir" "$EXT/fake-runtime" "$EXT/fake-runtime/scratch" "$EXT/fake-runtime/state" "$EXT/fake-ops" "$EXT/fake-ops/home" "$EXT/fake-ops/codex-home"
  printf '%s\n' "$VICTIM_MARK" > "$EXT/victim-dir/victim-file"; chmod 0644 "$EXT/victim-dir/victim-file"
  { printf '%s\n' "FU0011-DECOY secret-like material (synthetic)"; printf '0x%064d\n' 0; printf '%s %s %s\n' '-----BEGIN' 'FAKE' 'PRIVATE KEY-----'; } > "$EXT/victim-dir/decoy"; chmod 0600 "$EXT/victim-dir/decoy"
  chown aihf-ops:aihf-ops "$EXT/fake-runtime/scratch" "$EXT/fake-runtime/state" 2>/dev/null; chmod 0700 "$EXT/fake-runtime/scratch" "$EXT/fake-runtime/state"
  chown root:aihf-ops "$EXT/fake-ops/home" "$EXT/fake-ops/codex-home" 2>/dev/null; chmod 1770 "$EXT/fake-ops/home" "$EXT/fake-ops/codex-home"
}
snap_ext() { # everything a hostile link could be aimed at: the external world and the other services' state directories
  { find "$EXT" /var/lib/aihf/riskd /var/lib/aihf/traderd -printf '%p|%y|%U:%G|%m|%i|%s|%n|%l\n'; find "$EXT" /var/lib/aihf/riskd /var/lib/aihf/traderd -type f -exec sha256sum {} +; } 2>&1 | LC_ALL=C sort
}
snap_prot() { # owner, group, mode (and inode for directories) of every protected path; stat does not follow the final component
  local row p
  for row in "${AIHF_DIRS[@]}"; do read -r p _ <<<"$row"; stat -c '%n|%F|%U:%G|%a|%i' -- "$p" 2>&1; done
  for row in "${AIHF_CODEX_HOME_PROTECTED[@]}"; do read -r p _ <<<"$row"; stat -c '%n|%F|%U:%G|%a' -- "$AIHF_CODEX_HOME/$p" 2>&1; done
  for row in "${AIHF_OPS_HOME_PROTECTED[@]}"; do read -r p _ <<<"$row"; stat -c '%n|%F|%U:%G|%a' -- "$AIHF_OPS_HOME/$p" 2>&1; done
  stat -c '%n|%F|%U:%G|%a' -- "$AIHF_REQUIREMENTS" "$AIHF_LAUNCHER" "$AIHF_FUNDCTL" "$AIHF_RELEASE_CURRENT" "$AIHF_SIGNER_SENTINEL" 2>&1
  sha256sum -- "$AIHF_REQUIREMENTS" "$AIHF_FUNDCTL" 2>&1
}
drop_paths() { # snapshot on stdin, excluded path prefixes as arguments (the planted objects themselves)
  local awkp="" x
  for x in "$@"; do awkp="$awkp index(\$0, \"$x|\") == 1 || index(\$0, \"$x/\") == 1 ||"; done
  awk "!(${awkp} 0)"
}
secret_scan_clean() { # the log and every provisioned tree must hold no decoy or secret-like material
  local log="$1"
  grep -qE -e "FU0011-DECOY|0x[0-9a-fA-F]{64}|-----BEGIN [A-Z ]*PRIVATE KEY-----" "$log" && return 1
  # find -P never follows a link given as a starting point, so a planted link is not itself scanned (the decoy lives only in the external world)
  [ -z "$(find -P /opt/aihf /etc/codex /var/lib/aihf/runtime /var/lib/aihf/ops /var/lib/aihf/riskd /var/lib/aihf/traderd /var/lib/aihf/signerd -xdev -type f -exec grep -lF 'FU0011-DECOY' {} + 2>/dev/null | head -1)" ]
}

# ---------------------------------------------------------------- planting helpers
mvaside() { mv -T -- "$1" "$1.orig"; }
restore_aside() { rm -rf --one-file-system -- "$1"; mv -T -- "$1.orig" "$1"; }
as_owner_of() { local d="$1"; shift; local u; u=$(stat -c %U -- "$d"); as_svc "$u" "$@"; }

hostile() { # id, reason-regex, plant-fn, unplant-fn, excluded-protected-paths...
  local id="$1" reason="$2" plant="$3" unplant="$4"; shift 4
  selected "$id" || return 0
  local L="$OUT/cases/$id.log"; LOG="$L"
  fresh_ext
  $plant >>"$L.plant" 2>&1 || { fail "$id: could not plant (harness error, see $L.plant)"; $unplant >>"$L.plant" 2>&1; return 0; }
  snap_prot | drop_paths "$@" > "$OUT/cases/$id.prot.pre"
  snap_ext > "$OUT/cases/$id.ext.pre"
  run_apply "$L"; local rc=$RC
  snap_prot | drop_paths "$@" > "$OUT/cases/$id.prot.post"
  snap_ext > "$OUT/cases/$id.ext.post"
  if [ "$rc" -ne 0 ]; then pass "$id: provisioner refused (exit $rc)"; else fail "$id: provisioner exited 0 on a hostile tree"; fi
  if grep -qE -e "$reason" "$L"; then pass "$id: refusal reason matches /$reason/"; else fail "$id: no refusal matching /$reason/ ($(grep -E 'REFUSED|install:|chmod:|chown:|mv:|cannot' "$L" | head -2 | tr '\n' ' '))"; fi
  if cmp -s "$OUT/cases/$id.ext.pre" "$OUT/cases/$id.ext.post"; then pass "$id: external target unchanged"; else fail "$id: EXTERNAL TARGET CHANGED: $(diff "$OUT/cases/$id.ext.pre" "$OUT/cases/$id.ext.post" | head -4 | tr '\n' ' ')"; fi
  if cmp -s "$OUT/cases/$id.prot.pre" "$OUT/cases/$id.prot.post"; then pass "$id: ownership and modes of protected paths unchanged"; else fail "$id: PROTECTED PATH CHANGED: $(diff "$OUT/cases/$id.prot.pre" "$OUT/cases/$id.prot.post" | head -4 | tr '\n' ' ')"; fi
  if secret_scan_clean "$L"; then pass "$id: no secret-like material exposed"; else fail "$id: secret-like material exposed"; fi
  $unplant >>"$L.plant" 2>&1
  run_apply "$L.recover"
  if [ "$RC" -eq 0 ]; then pass "$id: after unplanting, re-apply succeeds"; else fail "$id: re-apply after unplanting failed (exit $RC): $(tail -2 "$L.recover" | tr '\n' ' ')"; fi
  snap_prot > "$OUT/cases/$id.golden-after" 2>&1
  if cmp -s "$OUT/golden.snap" "$OUT/cases/$id.golden-after"; then pass "$id: protected state equals the golden state after recovery"; else fail "$id: state differs from golden after recovery: $(diff "$OUT/golden.snap" "$OUT/cases/$id.golden-after" | head -4 | tr '\n' ' ')"; fi
}

# plants (each has an exact unplant). Service-owned locations are planted BY the service identity; root-owned parents can only be changed by root,
# which models offline tampering or a prior misconfiguration (the provisioner must refuse whoever planted it).
plant_sec_link_ext()   { as_svc aihf-signerd bash -c "mv -T -- $SEC $SEC.orig && ln -s $EXT/victim-dir $SEC"; }
plant_sec_link_trader(){ as_svc aihf-signerd bash -c "mv -T -- $SEC $SEC.orig && ln -s /var/lib/aihf/traderd $SEC"; }
plant_sec_dangling()   { as_svc aihf-signerd bash -c "mv -T -- $SEC $SEC.orig && ln -s $EXT/missing-secret-dir $SEC"; }
plant_sec_file()       { as_svc aihf-signerd bash -c "mv -T -- $SEC $SEC.orig && : > $SEC"; }
plant_sec_foreign()    { mvaside "$SEC" && install -d -o aihf-ops -g aihf-ops -m 0700 "$SEC"; }
unplant_sec_svc()      { as_svc aihf-signerd bash -c "rm -rf --one-file-system -- $SEC; mv -T -- $SEC.orig $SEC"; }
unplant_sec_root()     { restore_aside "$SEC"; }
plant_sent_link()      { as_svc aihf-signerd bash -c "mv -T -- $SENT $SENT.orig && ln -s $EXT/victim-dir/decoy $SENT"; }
plant_sent_dangling()  { as_svc aihf-signerd bash -c "mv -T -- $SENT $SENT.orig && ln -s $EXT/missing-sentinel-target $SENT"; }
plant_sent_dir()       { as_svc aihf-signerd bash -c "mv -T -- $SENT $SENT.orig && mkdir $SENT && : > $SENT/x"; }
plant_sent_hl_own()    { as_svc aihf-signerd bash -c "mv -T -- $SENT $SENT.orig && echo own > $SEC/other && ln $SEC/other $SENT"; }
plant_sent_hl_ext()    { mvaside "$SENT" && ln -- "$EXT/victim-dir/victim-file" "$SENT"; }
plant_sent_foreign()   { chown aihf-ops:aihf-ops "$SENT"; }
unplant_sent_foreign() { chown aihf-signerd:aihf-signerd "$SENT"; }
plant_sent_fifo()      { as_svc aihf-signerd bash -c "mv -T -- $SENT $SENT.orig && mkfifo $SENT"; }
unplant_sent_svc()     { as_svc aihf-signerd bash -c "rm -rf --one-file-system -- $SENT $SEC/other; mv -T -- $SENT.orig $SENT"; }
unplant_sent_root()    { rm -f -- "$SENT"; mv -T -- "$SENT.orig" "$SENT"; }
linkdir() { # path -> external dir (planted by root: the parent is root-owned, so no service identity could do this)
  local p="$1" t="$2"; mv -T -- "$p" "$p.orig" && ln -s "$t" "$p"
}
unlinkdir() { rm -f -- "$1"; mv -T -- "$1.orig" "$1"; }
plant_file_for() { mv -T -- "$1" "$1.orig" && : > "$1"; }
unplant_file_for() { rm -f -- "$1"; mv -T -- "$1.orig" "$1"; }

# ================================================================ N01 clean first apply (or confirm provisioned state)
LOG="$OUT/N01.log"
if [ "$PROVISIONED" -eq 0 ]; then
  run_apply "$OUT/N01.log"
  if [ "$RC" -eq 0 ]; then pass "N01: clean first apply succeeds on a fresh distro"; else fail "N01: clean first apply failed (exit $RC): $(tail -3 "$OUT/N01.log" | tr '\n' ' ')"; echo "SUMMARY hostile: pass=$npass fail=$nfail"; exit 1; fi
else
  run_apply "$OUT/N01.log"; [ "$RC" -eq 0 ] && pass "N01: re-apply on the provisioned distro succeeds" || { fail "N01: provisioned distro does not re-apply (exit $RC)"; echo "SUMMARY hostile: pass=$npass fail=$nfail"; exit 1; }
fi
# independent expectation (the layout table, not the provisioner's own logic)
bad=0
for row in "${AIHF_DIRS[@]}"; do
  read -r p o g m <<<"$row"
  [ "$(stat -c '%F|%U:%G|%a' -- "$p")" = "directory|$o:$g|${m#0}" ] || { bad=1; echo "  layout mismatch: $p $(stat -c '%F|%U:%G|%a' -- "$p")"; }
done
[ "$(stat -c '%U:%G|%a' -- "$SENT")" = "aihf-signerd:aihf-signerd|600" ] && [ "$(cat "$SENT")" = "$AIHF_SIGNER_SENTINEL_CONTENT" ] || bad=1
[ "$bad" -eq 0 ] && pass "N01: every directory, the sentinel and its fixed non-secret content match the layout table" || fail "N01: layout table mismatch after first apply"
snap_prot > "$OUT/golden.snap" 2>&1

# ================================================================ N02/N03/N04 legitimate re-apply
if selected N02; then
  LOG="$OUT/cases/N02.log"; run_apply "$LOG"; snap_prot > "$OUT/cases/N02.snap" 2>&1
  [ "$RC" -eq 0 ] && pass "N02: immediate re-apply on an untampered installation succeeds" || fail "N02: re-apply failed (exit $RC): $(tail -2 "$LOG" | tr '\n' ' ')"
  cmp -s "$OUT/golden.snap" "$OUT/cases/N02.snap" && pass "N02: re-apply is idempotent (identical owners, modes, directory inodes)" || fail "N02: re-apply changed state: $(diff "$OUT/golden.snap" "$OUT/cases/N02.snap" | head -3 | tr '\n' ' ')"
fi
if selected N03; then
  LOG="$OUT/cases/N03.log"
  as_svc aihf-riskd bash -c "mkdir -p /var/lib/aihf/riskd/data/sub && echo risk-state > /var/lib/aihf/riskd/data/sub/db && ln -s data /var/lib/aihf/riskd/current && ln -s /nonexistent /var/lib/aihf/riskd/dangling-own"
  as_svc aihf-traderd bash -c "mkdir -p /var/lib/aihf/traderd/spool && echo trade-state > /var/lib/aihf/traderd/spool/q && ln /var/lib/aihf/traderd/spool/q /var/lib/aihf/traderd/spool/q2"
  as_svc aihf-signerd bash -c "echo benign-note > $SEC/note && chmod 0640 $SEC/note && echo not-the-marker > $SENT && chmod 0644 $SENT && ln -s note $SEC/note-link"
  as_svc aihf-ops bash -c "echo scratch > $AIHF_SCRATCH/s && echo state > $AIHF_STATE/t && echo mutable > $AIHF_CODEX_HOME/state_probe.sqlite && echo m > $AIHF_OPS_HOME/probe"
  before=$(sha256sum /var/lib/aihf/riskd/data/sub/db /var/lib/aihf/traderd/spool/q $SEC/note | sort)
  run_apply "$LOG"
  [ "$RC" -eq 0 ] && pass "N03: re-apply after ordinary service- and ops-owned file activity succeeds" || fail "N03: re-apply refused ordinary activity (exit $RC): $(grep REFUSED "$LOG" | head -1)"
  after=$(sha256sum /var/lib/aihf/riskd/data/sub/db /var/lib/aihf/traderd/spool/q $SEC/note | sort)
  [ "$before" = "$after" ] && pass "N03: service-owned files were not touched" || fail "N03: service-owned files changed"
  [ "$(cat "$SENT")" = "$AIHF_SIGNER_SENTINEL_CONTENT" ] && [ "$(stat -c '%U:%G|%a|%h|%F' -- "$SENT")" = "aihf-signerd:aihf-signerd|600|1|regular file" ] && pass "N03: a rewritten sentinel is restored to the fixed marker, owner and mode" || fail "N03: sentinel not restored"
  [ "$(readlink /var/lib/aihf/riskd/current)" = data ] && [ -L /var/lib/aihf/riskd/dangling-own ] && [ -L $SEC/note-link ] && pass "N03: the services' own symlinks inside their trees were neither followed nor removed" || fail "N03: service symlinks disturbed"
  rm -f -- "$AIHF_CODEX_HOME/state_probe.sqlite" "$AIHF_OPS_HOME/probe"
  snap_prot | drop_paths "$SENT" > "$OUT/cases/N03.snap"; drop_paths "$SENT" < "$OUT/golden.snap" > "$OUT/cases/N03.golden"
  cmp -s "$OUT/cases/N03.golden" "$OUT/cases/N03.snap" && pass "N03: protected owners/modes unchanged" || fail "N03: protected state differs: $(diff "$OUT/cases/N03.golden" "$OUT/cases/N03.snap" | head -3 | tr '\n' ' ')"
fi
if selected N04; then
  LOG="$OUT/cases/N04.log"
  as_svc aihf-signerd bash -c "chmod 0777 $SEC; chmod 0755 $SD"
  run_apply "$LOG"
  [ "$RC" -eq 0 ] && [ "$(stat -c %a -- "$SEC")" = 700 ] && [ "$(stat -c %a -- "$SD")" = 700 ] && pass "N04: service-chosen mode drift on its own directories is narrowed back to the layout modes" || fail "N04: mode drift not repaired (exit $RC, secrets $(stat -c %a -- "$SEC"), signer $(stat -c %a -- "$SD"))"
fi

# ================================================================ hostile cases: signer secret directory
hostile H01-secret-dir-symlink-to-external "unsafe path $SEC: is a symbolic link" plant_sec_link_ext unplant_sec_svc "$SEC" "$SENT"
hostile H02-secret-dir-symlink-to-other-service "unsafe path $SEC: is a symbolic link" plant_sec_link_trader unplant_sec_svc "$SEC" "$SENT"
hostile H03-secret-dir-dangling-symlink "unsafe path $SEC: is a symbolic link" plant_sec_dangling unplant_sec_svc "$SEC" "$SENT"
hostile H04-secret-dir-replaced-by-file "unsafe path $SEC: is not a directory" plant_sec_file unplant_sec_svc "$SEC" "$SENT"
hostile H05-secret-dir-owned-by-another-identity "unsafe path $SEC: owner:group is aihf-ops:aihf-ops" plant_sec_foreign unplant_sec_root "$SEC" "$SENT"
# sentinel substitution
hostile H06-sentinel-symlink-to-external "unsafe path $SENT: is a symbolic link" plant_sent_link unplant_sent_svc "$SENT"
hostile H07-sentinel-dangling-symlink "unsafe path $SENT: is a symbolic link" plant_sent_dangling unplant_sent_svc "$SENT"
hostile H08-sentinel-replaced-by-directory "unsafe path $SENT: is not a regular file" plant_sent_dir unplant_sent_svc "$SENT"
hostile H09-sentinel-hardlink-service-file "unsafe path $SENT: has 2 hard links" plant_sent_hl_own unplant_sent_svc "$SENT"
hostile H10-sentinel-hardlink-external-file "unsafe path $SENT: has 2 hard links" plant_sent_hl_ext unplant_sent_root "$SENT"
hostile H11-sentinel-fifo "unsafe path $SENT: is not a regular file" plant_sent_fifo unplant_sent_svc "$SENT"
hostile H22-sentinel-owned-by-another-identity "unsafe path $SENT: owner:group is aihf-ops:aihf-ops" plant_sent_foreign unplant_sent_foreign "$SENT"
# an ancestor above the layout table (/usr/local holds /usr/local/sbin) that a lower-trust identity could rename through is refused, not walked
p_anc_mode() { stat -c %a /usr/local > "$OUT/usr-local.mode"; chmod 0775 /usr/local; }; u_anc_mode() { chmod "$(cat "$OUT/usr-local.mode")" /usr/local; }
hostile H23-ancestor-group-writable "unsafe path /usr/local: is an ancestor that is neither" p_anc_mode u_anc_mode
p_anc_owner() { stat -c %U:%G /usr/local > "$OUT/usr-local.owner"; chown aihf-ops:aihf-ops /usr/local; }; u_anc_owner() { chown "$(cat "$OUT/usr-local.owner")" /usr/local; }
hostile H24-ancestor-owned-by-another-identity "unsafe path /usr/local: is an ancestor that is neither" p_anc_owner u_anc_owner

# state directories replaced by a link to an external directory, a file, or a foreign owner
for d in riskd traderd signerd; do
  P=/var/lib/aihf/$d
  p_link() { linkdir "$P" "$EXT/victim-dir"; }; u_link() { unlinkdir "$P"; }
  hostile "H12-state-dir-$d-symlink" "unsafe path $P: is a symbolic link" p_link u_link "$P" "$P/secrets" "$SENT"
  p_dang() { linkdir "$P" "$EXT/missing-state-dir"; }
  hostile "H13-state-dir-$d-dangling-symlink" "unsafe path $P: is a symbolic link" p_dang u_link "$P" "$P/secrets" "$SENT"
  p_file() { plant_file_for "$P"; }; u_file() { unplant_file_for "$P"; }
  hostile "H14-state-dir-$d-replaced-by-file" "unsafe path $P: is not a directory" p_file u_file "$P" "$P/secrets" "$SENT"
  p_own() { chown aihf-ops:aihf-ops "$P"; }; u_own() { chown "aihf-$d:aihf-$d" "$P"; }
  hostile "H15-state-dir-$d-foreign-owner" "unsafe path $P: owner:group is aihf-ops:aihf-ops" p_own u_own "$P"
done
for P in "$AIHF_SCRATCH" "$AIHF_STATE" "$AIHF_OPS_HOME" "$AIHF_CODEX_HOME"; do
  tag=$(basename "$P")
  p_link() { linkdir "$P" "$EXT/victim-dir"; }; u_link() { unlinkdir "$P"; }
  hostile "H16-dir-$tag-symlink" "unsafe path $P: is a symbolic link" p_link u_link "$P"
done
# parent-path substitution: a trusted ancestor replaced by a link to a look-alike external tree
p_runtime() { linkdir /var/lib/aihf/runtime "$EXT/fake-runtime"; }; u_runtime() { unlinkdir /var/lib/aihf/runtime; }
hostile H17-parent-path-runtime-symlink "unsafe path /var/lib/aihf/runtime: is a symbolic link" p_runtime u_runtime /var/lib/aihf/runtime "$AIHF_SCRATCH" "$AIHF_STATE"
p_opsroot() { linkdir /var/lib/aihf/ops "$EXT/fake-ops"; }; u_opsroot() { unlinkdir /var/lib/aihf/ops; }
hostile H18-parent-path-ops-symlink "unsafe path /var/lib/aihf/ops: is a symbolic link" p_opsroot u_opsroot /var/lib/aihf/ops "$AIHF_OPS_HOME" "$AIHF_CODEX_HOME"
p_aihf() { linkdir /var/lib/aihf "$EXT"; }; u_aihf() { unlinkdir /var/lib/aihf; }
hostile H19-parent-path-aihf-root-symlink "unsafe path /var/lib/aihf: is a symbolic link" p_aihf u_aihf /var/lib/aihf /var/lib/aihf/runtime /var/lib/aihf/ops /var/lib/aihf/riskd /var/lib/aihf/traderd /var/lib/aihf/signerd /var/lib/aihf/runtime/scratch /var/lib/aihf/runtime/state "$AIHF_OPS_HOME" "$AIHF_CODEX_HOME" "$SEC" "$SENT"

# control: the service identity itself cannot replace the root-owned parent names (these hostile cases need root, by design)
if selected H20; then
  if as_svc aihf-signerd bash -c "mv -T -- $SD $SD.x" 2>/dev/null; then fail "H20: signer identity renamed its own state directory (parent not root-protected)"; mv -T -- "$SD.x" "$SD"; else control "H20: aihf-signerd cannot rename or replace its own state directory (parent /var/lib/aihf is root-owned)"; fi
  as_svc aihf-signerd bash -c "ln -s $EXT /var/lib/aihf/planted" 2>/dev/null && fail "H20: signer identity created a name in /var/lib/aihf" || control "H20: aihf-signerd cannot create names in /var/lib/aihf"
fi

# ================================================================ process / precondition refusals
spawn_as() { # user -> sets BGPID of a long-lived process running with that uid; extra args = argv0 name
  local u="$1" name="${2:-sleep}"
  setpriv --reuid="$(id -u "$u")" --regid="$(id -g "$u")" --clear-groups bash -c "exec -a $name sleep 600" &
  BGPID=$!; sleep 0.5
}
for u in aihf-ops aihf-riskd aihf-traderd aihf-signerd; do
  selected "N05-$u" || continue
  LOG="$OUT/cases/N05-$u.log"; spawn_as "$u" harmless-name
  [ "$(awk '/^Uid:/ {print $2}' /proc/$BGPID/status 2>/dev/null)" = "$(id -u "$u")" ] && control "N05-$u: a process with uid $(id -u "$u") and a misleading name is running" || fail "N05-$u: harness could not start the probe process"
  run_apply "$LOG"; rc=$RC; kill "$BGPID" 2>/dev/null; wait "$BGPID" 2>/dev/null
  if [ "$rc" -ne 0 ] && grep -qE 'REFUSED:.*(process|running)' "$LOG"; then pass "N05-$u: re-apply refused while a process owned by $u runs (matched by uid, not by name)"; else fail "N05-$u: re-apply proceeded or failed for another reason (exit $rc): $(tail -1 "$LOG")"; fi
done
if selected N05-effective; then # a process whose REAL uid is root but whose EFFECTIVE uid is a service identity is still that identity's process
  LOG="$OUT/cases/N05-effective.log"
  setpriv --ruid=0 --euid="$(id -u aihf-signerd)" --clear-groups sleep 600 & BGPID=$!; sleep 0.5
  [ "$(awk '/^Uid:/ {print $2 "/" $3}' /proc/$BGPID/status 2>/dev/null)" = "0/$(id -u aihf-signerd)" ] && control "N05-effective: probe process has real uid 0 and effective uid $(id -u aihf-signerd)" || fail "N05-effective: harness could not start the probe process"
  run_apply "$LOG"; rc=$RC; kill "$BGPID" 2>/dev/null; wait "$BGPID" 2>/dev/null
  if [ "$rc" -ne 0 ] && grep -qE 'REFUSED:.*(process|running)' "$LOG"; then pass "N05-effective: re-apply refused while a process holds the service effective uid"; else fail "N05-effective: not refused (exit $rc): $(tail -1 "$LOG")"; fi
fi
for code in 1 3; do
  selected "N06-getent-$code" || continue
  LOG="$OUT/cases/N06-getent-$code.log"; mkdir -p "$OUT/shim$code"; printf '#!/bin/sh\nexit %s\n' "$code" > "$OUT/shim$code/getent"; chmod 0755 "$OUT/shim$code/getent"
  run_apply "$LOG" "PATH=$OUT/shim$code:$PATH"
  if [ "$RC" -ne 0 ] && grep -qE 'REFUSED:.*getent' "$LOG"; then pass "N06-getent-$code: re-apply refused when getent itself fails (exit $code), not skipped"; else fail "N06-getent-$code: getent failure was not refused (exit $RC): $(tail -1 "$LOG")"; fi
done
if selected N07; then # protected names in the ops-writable homes: planted links are REPLACED (rename), never followed; the external target is untouched
  fresh_ext; LOG="$OUT/cases/N07.log"
  rm -f -- "$AIHF_OPS_HOME/.bashrc"; as_svc aihf-ops ln -s "$EXT/victim-dir/victim-file" "$AIHF_OPS_HOME/.bashrc"
  rmdir -- "$AIHF_OPS_HOME/.agents"; as_svc aihf-ops bash -c "mkdir $AIHF_OPS_HOME/.agents && ln -s $EXT/victim-dir $AIHF_OPS_HOME/.agents/skills && echo x > $AIHF_OPS_HOME/.agents/f"
  rm -f -- "$AIHF_CODEX_HOME/config.toml"; as_svc aihf-ops ln -s "$EXT/victim-dir/decoy" "$AIHF_CODEX_HOME/config.toml"
  snap_ext > "$OUT/cases/N07.ext.pre"; run_apply "$LOG"; rc=$RC; snap_ext > "$OUT/cases/N07.ext.post"
  [ "$rc" -eq 0 ] && pass "N07: re-apply succeeds and replaces ops-planted objects at protected names" || fail "N07: re-apply failed (exit $rc): $(tail -1 "$LOG")"
  cmp -s "$OUT/cases/N07.ext.pre" "$OUT/cases/N07.ext.post" && pass "N07: external target unchanged (links were replaced, not followed)" || fail "N07: external target changed"
  [ "$(stat -c '%F|%U:%G|%a' -- "$AIHF_OPS_HOME/.bashrc" "$AIHF_OPS_HOME/.agents" "$AIHF_CODEX_HOME/config.toml" | tr '
' ' ')" = "regular empty file|root:root|644 directory|root:root|755 regular file|root:root|644 " ] && [ -z "$(ls -A -- "$AIHF_OPS_HOME/.agents")" ] && pass "N07: protected names are restored as root-owned fresh objects" || fail "N07: protected names not restored"
  secret_scan_clean "$LOG" && pass "N07: no secret-like material exposed" || fail "N07: secret-like material exposed"
fi
if selected H21; then # plan mode never mutates, even on a hostile tree
  fresh_ext; plant_sec_link_ext; snap_ext > "$OUT/cases/H21.ext.pre"; snap_prot | drop_paths "$SEC" "$SENT" > "$OUT/cases/H21.prot.pre"
  LOG="$OUT/cases/H21.log"; run_plan; snap_ext > "$OUT/cases/H21.ext.post"; snap_prot | drop_paths "$SEC" "$SENT" > "$OUT/cases/H21.prot.post"
  cmp -s "$OUT/cases/H21.ext.pre" "$OUT/cases/H21.ext.post" && cmp -s "$OUT/cases/H21.prot.pre" "$OUT/cases/H21.prot.post" && pass "H21: plan on a hostile tree changed nothing" || fail "H21: plan mutated the system"
  unplant_sec_svc
fi
run_apply "$OUT/final-reapply.log"
[ "$RC" -eq 0 ] && pass "FINAL: clean re-apply succeeds after the whole battery" || fail "FINAL: clean re-apply failed (exit $RC): $(tail -2 "$OUT/final-reapply.log" | tr '\n' ' ')"
snap_prot > "$OUT/final.snap" 2>&1; cmp -s "$OUT/golden.snap" "$OUT/final.snap" && pass "FINAL: protected state equals the golden state" || fail "FINAL: state differs from golden: $(diff "$OUT/golden.snap" "$OUT/final.snap" | head -3 | tr '\n' ' ')"
rm -rf --one-file-system -- "$EXT"
echo "SUMMARY hostile: pass=$npass fail=$nfail"
[ "$nfail" -eq 0 ]
