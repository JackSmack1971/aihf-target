# ops/provision: human-run host provisioning for the isolated fund-ops runtime

`ops/provision/` is the **sole repository location authorized for human-run privileged host provisioning artifacts** (decision D-0007). The one other pinned path beneath `ops/` is the inert root-only operator control `ops/fundctl/fundctl` (FU-0007, P1-S3B); it receives no capability exemption.
It is outside the model and runtime authority surface and does not create a general privileged-code exception.

- Operator/administrator use only. Codex `fund-ops`, `riskd`, `traderd`, `signerd`, MCP servers and any model-facing code must never invoke, import or reference these files; the repository tripwire rejects a reference from anywhere else.
- The file set is pinned in `src/contracts/trust-zone-checker.mjs` (`OPS_PROVISION_FILES`). Adding a file here is a review-visible change to checker code and its tests.
- The canonical runtime is a **dedicated WSL2 Ubuntu distro** (decision OD-1). WSL is the runtime choice, not the security boundary: the properties come from managed Codex requirements, Unix identities and ownership, a root-owned release, and the removal of Windows interoperability.

## Three separate steps

| Step | File | Mutates the system? |
|---|---|---|
| 1. generate/validate artifacts | `fund-ops-validate.sh` | no (offline; checks `canonical-artifacts.sha256`) |
| 2. provision | `fund-ops-provision.sh plan` (default) / `apply` | only with an explicit `apply` as root |
| 3. verify installed state | `fund-ops-verify.sh` | no (only removable probes inside ops-writable directories) |

Constants live in `fund-ops-layout.sh` and mirror `contracts/ops-runtime-layout.json` (parity is tested). `wsl.conf.fund-ops` is the hardened per-distro WSL configuration. `canonical-artifacts.sha256` pins the reviewed requirements, profile, WSL template and layout contract (SHA-256 over LF-normalized content). Changing any pinned artifact requires updating the pin in the same reviewed diff.

## Operator procedure (dedicated distro, run as root, source tree on the Linux filesystem)

    bash ops/provision/fund-ops-validate.sh
    bash ops/provision/fund-ops-provision.sh plan --release-id <id> --codex-dir <official codex dir>
    bash ops/provision/fund-ops-provision.sh apply --release-id <id> --codex-dir <official codex dir> --configure-wsl
    # from Windows: wsl --terminate <distro>      (applies wsl.conf)
    bash /opt/aihf/current/ops/provision/fund-ops-verify.sh --expect-hardened-wsl

`apply` installs `/etc/codex/requirements.toml` byte-for-byte from the pinned canonical artifact and refuses to replace a *different* installed file unless `--replace-requirements` is passed after reviewing the printed diff. Releases are immutable directories under `/opt/aihf/releases/<id>` activated by an atomic symlink switch of `/opt/aihf/current`; reusing an id with different content is refused.

## Re-apply safety (FU-0011 / R15)

`apply` is safe to re-run on an installation whose service directories are controlled by lower-trust identities. Root never follows or trusts a path they can replace: layout directories and the signer sentinel are reached through a verified-descriptor walk (non-following metadata, open, compare, then resolve the next component relative to the descriptor), and symbolic links, non-directories, foreign owners, hard-linked or non-regular sentinels and untrusted ancestors make `apply` exit non-zero with `REFUSED: unsafe path ...` before anything is changed through them. It also refuses while any process holds the uid of the ops identity or a service identity, and when `getent` exits with anything other than found (0) or not-found (2). Nothing is repaired through unsafe state; remove the offending object as the operator and re-run. The live proof is `tests/live/provision-reapply-hostile.sh` (root, disposable `aihf-*` distro only, harmless sentinels only).

## What this slice does not do

Since P1-S3B the provisioner also creates the `aihf-riskd`, `aihf-traderd` and `aihf-signerd` identities (private groups, no sudo, non-login), their `0700` state directories, the signerd-only `0700` secret directory holding a `0600` fixed non-secret sentinel, and installs the inert `fundctl` (`root:root` `0700`, source `ops/fundctl/fundctl`, hash-pinned; every command prints `NOT_IMPLEMENTED` and exits non-zero). None of this has been applied to a live system; the verifier's identity/ACL denial tests are run in P1-S3C. It still does not install or start any service, store any real secret, contact Hyperliquid, or set an outbound network policy; those are later slices. A scratch or cloud environment run is not proof of the production identity until the same provisioning runs on the real dedicated distro.
