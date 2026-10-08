# Sourced constants for the isolated fund-ops runtime. This file is DATA (no commands). It mirrors contracts/ops-runtime-layout.json;
# tests/conformance/ops-provision.test.mjs enforces parity, so a drift between the two fails the test suite.
# Operator-run administrative artifact only (see ops/provision/README.md). Never sourced or invoked by runtime or model-facing code.

AIHF_CODEX_PIN="0.160.1"
# SHA-256 of the official linux-x64 musl codex binary of the pinned version (from the registry-verified npm package); checked at provision and verify time.
AIHF_CODEX_SHA256="f34a4d2301892ae96c90097786bfe5dc269f187b6f69faf42a7b357b8c081e35"
AIHF_OPS_USER="aihf-ops"
AIHF_OPS_GROUP="aihf-ops"
AIHF_OPS_HOME="/var/lib/aihf/ops/home"
AIHF_OPS_SHELL="/bin/bash"

AIHF_REQUIREMENTS="/etc/codex/requirements.toml"
AIHF_RELEASE_ROOT="/opt/aihf/releases"
AIHF_RELEASE_CURRENT="/opt/aihf/current"
AIHF_TOOLCHAIN="/opt/aihf/toolchain"
AIHF_CODEX_DIR="/opt/aihf/toolchain/codex"
AIHF_CODEX_BIN="/opt/aihf/toolchain/codex/bin/codex"
AIHF_NODE_DIR="/opt/aihf/toolchain/node"
AIHF_LAUNCHER="/opt/aihf/bin/fund-ops"
AIHF_LAUNCHER_PATH_ENV="/usr/bin:/bin"
AIHF_RUNTIME_ROOT="/var/lib/aihf/runtime"
AIHF_SCRATCH="/var/lib/aihf/runtime/scratch"
AIHF_STATE="/var/lib/aihf/runtime/state"
AIHF_CODEX_HOME="/var/lib/aihf/ops/codex-home"
AIHF_SERVICE_SHELL="/usr/sbin/nologin"
AIHF_SIGNER_SECRET_DIR="/var/lib/aihf/signerd/secrets"
AIHF_SIGNER_SENTINEL="/var/lib/aihf/signerd/secrets/sentinel"
# Fixed NON-SECRET marker written to the sentinel file. It is not, and must never be replaced by, key, seed or credential material.
AIHF_SIGNER_SENTINEL_CONTENT="AIHF-SIGNER-SENTINEL non-secret marker"
AIHF_FUNDCTL="/usr/local/sbin/fundctl"
AIHF_FUNDCTL_SOURCE="ops/fundctl/fundctl"
AIHF_AUDIT_LOG="/var/log/aihf-provision.log"
AIHF_WSL_CONF="/etc/wsl.conf"

# Service identities (P1-S3B, D-0009): "user home". Each has a private same-named group, no supplementary groups, no sudo, a locked password and a
# non-login shell; the home is its private state directory (see AIHF_DIRS).
AIHF_SERVICES=(
  "aihf-riskd /var/lib/aihf/riskd"
  "aihf-traderd /var/lib/aihf/traderd"
  "aihf-signerd /var/lib/aihf/signerd"
)

# Directory table: "path owner group mode" (applied in order; parents first). Mirrors the dir entries of the layout contract.
AIHF_DIRS=(
  "/etc/codex root root 0755"
  "/opt/aihf root root 0755"
  "/opt/aihf/toolchain root root 0755"
  "/opt/aihf/bin root root 0755"
  "/opt/aihf/releases root root 0755"
  "/var/lib/aihf root root 0755"
  "/var/lib/aihf/ops root root 0755"
  "/var/lib/aihf/ops/home root aihf-ops 1770"
  "/var/lib/aihf/ops/codex-home root aihf-ops 1770"
  "/var/lib/aihf/runtime root root 0755"
  "/var/lib/aihf/runtime/scratch aihf-ops aihf-ops 0700"
  "/var/lib/aihf/runtime/state aihf-ops aihf-ops 0700"
  "/var/lib/aihf/riskd aihf-riskd aihf-riskd 0700"
  "/var/lib/aihf/traderd aihf-traderd aihf-traderd 0700"
  "/var/lib/aihf/signerd aihf-signerd aihf-signerd 0700"
  "/var/lib/aihf/signerd/secrets aihf-signerd aihf-signerd 0700"
  "/usr/local/sbin root root 0755"
)

# Security-critical Codex-home names that are pre-created root-owned so the ops identity cannot create, replace or remove them
# (the Codex home is sticky and group-writable so Codex can keep its own mutable state). "name type mode".
AIHF_CODEX_HOME_PROTECTED=(
  "config.toml file 0644"
  ".env file 0644"
  "fund-ops.config.toml file 0644"
  "hooks.json file 0644"
  "AGENTS.md file 0644"
  "AGENTS.override.md file 0644"
  "rules dir 0755"
  "skills dir 0755"
  "agents dir 0755"
  "prompts dir 0755"
  "plugins dir 0755"
)

# The ops HOME is sticky and root-owned for the same reason: documented user skill roots ($HOME/.agents/skills) and shell startup files live under HOME.
AIHF_OPS_HOME_PROTECTED=(
  ".agents dir 0755"
  ".codex dir 0755"
  ".bashrc file 0644"
  ".profile file 0644"
  ".bash_profile file 0644"
  ".bash_login file 0644"
)
