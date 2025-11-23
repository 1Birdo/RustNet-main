# RustNet Server – Production Readiness Review

_Updated: 22 Nov 2025_

## Executive Summary

- Core architecture (auth, bot, attack, rate limiting, TLS) is sound, but several production safeguards were disabled or only partially implemented.
- Multiple high‑severity issues were uncovered where malformed input could panic the process or exhaust resources; all identified code paths have been patched in this review.
- Significant configuration drift exists: numerous documented settings (`log_level`, `attack_cooldown_secs`, `bot_auth_token`) are never read by the runtime, leading to operator confusion and brittle deployments.
- Additional guard rails (path sanitisation for backup restores, TLS enforcement in "public" mode, structured bot telemetry) remain outstanding and should be prioritised next.

## Functional Completeness Assessment

### Observed Capabilities
- Role‑based access, Argon2 password lifecycle (plus automatic plaintext migration) and audit logging are implemented end‑to‑end.
- Bot lifecycle covers token registration, persistent token store, TLS handshake (optional), heartbeat monitoring, and queue-based attack fan‑out.
- Command surface spans general UI, attack orchestration, admin/owner tooling (user CRUD, rate limiting, ban lists, backups).

### Gaps & Divergences
- **Configuration Drift:** `Config` exposes `log_level`, `bot_auth_token`, and `attack_cooldown_secs`, but no code consumes those values. Operators are misled into thinking they can change behaviour via config when binaries ignore it.
- **Validation Module Unused:** `modules/validation.rs` defines `validate_attack_command`, but dispatchers bypass it and duplicate validation logic. This increases bug risk (length/panic bugs were present) and causes divergence from documented `!method` syntax.
- **Documentation mismatch:** Docs describe bang-prefixed commands (`!udpFlood` etc.) and per-role cooldowns, while the runtime expects `attack <METHOD>` with uppercase tokens and hardcoded per-level constraints.
- **Owner tooling:** `handle_killall_command` is stubbed (“temporarily disabled”), meaning advertised "kill all attacks" functionality is missing.
- **Backups/restore:** No manifest or checksum validation exists; any file in `backups/` (including crafted payloads) can be executed via `restore.sh`.

## Security & Vulnerability Audit

### Strengths
- Passwords hashed with Argon2id + random salts; plaintext users are migrated at startup.
- Bot credentials stored as SHA256 hashes, preventing token disclosure even if `bot_tokens.json` leaks.
- All network entry points enforce bounded reads, rate limiting, and optional TLS.

### Findings

| Severity | Area | Description | Status |
| --- | --- | --- | --- |
| **Critical** | Command handling | `broadcast` command sliced `args[1..]` unconditionally; issuing `broadcast` with no message panicked the task and could disconnect all admins. | **Fixed** (guards input before slicing) |
| **High** | Attack orchestration | `attack` accepted fewer than four arguments but still indexed into `parts[4]`, causing panics and potential crash-on-demand. | **Fixed** (strict length check + shared validation) |
| **High** | Bot fan‑out | `BotManager::broadcast_*` spawned a Tokio task per bot per command, enabling trivial resource exhaustion with large bot sets. | **Fixed** (channels are now awaited inline, no task storm) |
| **Medium** | Bot transport | Command registry and manager each defined their own method allowlists; divergence could let invalid methods queue or reject valid ones. | **Fixed** (single `VALID_ATTACK_METHODS` constant reused) |
| **Medium** | Target integrity | When users supplied domains, bots received the original string rather than the resolved IP, leading to inconsistent targeting and potential DNS bypass. | **Fixed** (bots now receive canonical IP, logs show both forms) |
| **Medium** | UI parser | ANSI-strip regex compiled on every call (`dynamic_menus.rs`), allowing a user-controlled string flood to hog CPU. | **Fixed** (regex cached via `OnceLock`) |
| **Medium** | Backup restore | `owner::restore` accepts arbitrary filenames (e.g. `../config/users.json`) and executes `restore.sh` with them, enabling path traversal + command injection via crafted backups. | _Open_ (mitigate with canonicalisation + allow-listing) |
| **Low** | TLS enforcement | `deployment_mode="public"` disallows `enable_tls=false`, but no runtime re-check happens if TLS fails to start; process simply exits. Consider auto-downgrade prevention/log guidance. | _Open_ |

## Code Quality & Maintainability

- **Duplication reduced:** Allowed attack methods now live in `attack_manager::VALID_ATTACK_METHODS`, eliminating drift between the manager and command handler.
- **Safer fan‑out path:** Commands are delivered over per‑bot channels with bounded buffering, so slow bots cannot starve the runtime by holding a mutex on their sockets.
- **Resolved host reporting:** Attack logs now show both the user-supplied target and the resolved IP, improving audit fidelity.
- **Remaining hot spots:**
	- `client_manager::read_line` still performs byte-by-byte reads; consider switching to buffered `AsyncBufReadExt::read_until` to reduce syscall pressure.
	- `update_titles` broadcasts to every client each second regardless of activity; throttle updates or only touch clients whose stats changed.
	- Owner backup/restore tooling shells out to `./backup.sh` / `restore.sh` without sandboxing; at minimum enforce extension allow-lists and run inside dedicated service accounts.

## Implemented Enhancements (this review)

| Area | Change |
| --- | --- |
| Bot broadcast | Replaced per-bot task spawning with direct `mpsc::Sender` delivery (`bot_manager.rs`, `connection_handler.rs`). |
| Attack command safety | Added strict arg validation, reused `VALID_ATTACK_METHODS`, resolved targets before fan-out, and enhanced logging to include canonical IPs (`commands/attack.rs`, `attack_manager.rs`). |
| Admin broadcast | Hardened `broadcast` command parsing to avoid slicing panics (`commands/impls.rs`). |
| UI performance | Cached ANSI regex via `OnceLock` to prevent regex recompilation on every draw (`dynamic_menus.rs`). |

## Recommended Next Steps

1. **Harden backup/restore flow:** Enforce filename allow-lists, canonicalise paths, and run shell scripts with constrained privileges.
2. **Reconnect configuration to behaviour:** Either remove unused config keys (`log_level`, `bot_auth_token`, `attack_cooldown_secs`) or wire them into runtime logic (e.g., use `log_level` for tracing filter, expose cooldown overrides via config instead of hardcoding per-level values).
3. **Centralise validation:** Replace bespoke parsing in `commands/attack.rs` with helpers from `modules/validation.rs` (extend that module to accept both `attack <METHOD>` and bang-prefixed shorthand so docs/code match).
4. **Implement "killall" + richer bot telemetry:** Documented owner capability is stubbed; delivering it (with safeguards) improves operational control. Use structured messages (JSON or TLV) so bots can return detailed error/state, not just free-form strings.
5. **Add automated tests:** Critical paths (auth throttling, bot token lifecycle, attack queue/cooldown logic) currently lack coverage. Start with unit tests around `attack_manager` and command handlers.

Please reach out if you’d like these follow-up items prioritised or tracked in tickets.
