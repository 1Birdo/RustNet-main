# RustNet Server – In-Depth Codebase Analysis & Enhancement Plan

**Date:** November 23, 2025
**Scope:** Server Codebase (`server/src`)

## 1. Functional Completeness Assessment

The server implements a functional Command & Control (C2) architecture with the following capabilities:
- **Authentication:** Role-based access control (Basic, Pro, Admin, Owner) with Argon2 hashing.
- **Bot Management:** TCP-based bot connection handling, authentication via tokens, and heartbeat monitoring.
- **Attack Orchestration:** Support for multiple attack methods (UDP, TCP, HTTP, etc.), concurrency limits, and per-user cooldowns.
- **Admin Interface:** ANSI-based terminal UI for managing users, bots, and viewing logs.

**Identified Gaps:**
- **Database Scalability:** The system relies on JSON files (`users.json`, `attack_history.json`) for storage. This is not ACID-compliant and will degrade in performance with many users or large history.
- **Granular Permissions:** Permissions are tied strictly to 4 levels. A more granular permission system (e.g., "can_kick", "can_attack_l7") would be more flexible.
- **Bot Command Execution:** The current protocol only supports "attack" commands. There is no facility for executing arbitrary shell commands or updating bots remotely (though `!update` is listed in help, it's not fully implemented in the analyzed files).
- **Real-time Monitoring:** Attack monitoring is limited to active counts. No bandwidth usage or detailed bot status telemetry is available.

## 2. Security and Vulnerability Audit

**Critical Findings:**
- **TLS Configuration:** TLS is optional. If `deployment_mode` is "local" (default), the server can start without TLS. Even in "public" mode, if TLS setup fails, the server might not exit gracefully in all paths (though `main.rs` does try to handle this).
- **Cleartext Fallback:** In `connection_handler.rs`, if TLS is not enabled, the server prints a warning but proceeds to accept cleartext credentials. This is a high risk for credential interception.
- **Input Handling:**
    - `read_line_bounded` protects against long lines, but `handle_bot_connection` uses a fixed 1024-byte buffer for auth, which could be a minor DoS vector if connections hang.
    - `admin.rs` log viewing reads the entire file (or large chunks) into memory, which could lead to OOM on small VPS instances if logs are massive.
- **Sensitive Data in Logs:** While passwords aren't logged, the `audit.log` contains usernames and IP addresses. Ensure this file is protected.

**Code Safety:**
- **Unsafe Code:** No explicit `unsafe` blocks were found in the analyzed modules, which is excellent.
- **Error Handling:** Generally good use of `Result` and `anyhow`/`thiserror`.

## 3. Code Quality Refactoring

**Issues:**
- **UI Duplication:** `admin.rs` contains significant code duplication for rendering tables and menus (borders, gradients, padding calculations). This violates DRY (Don't Repeat Yourself).
- **Stringly-Typed Data:** The `User` struct stores `level` as a `String` and parses it to an `Enum` on every access. This is inefficient and prone to data inconsistency if the JSON is manually edited with invalid values.
- **Hardcoded Values:** `VALID_ATTACK_METHODS` is hardcoded in `attack_manager.rs`. It should ideally be configurable or extensible.

**Refactoring Plan:**
- **Extract UI Logic:** Create a `TableBuilder` in `ui.rs` to standardize terminal output.
- **Optimize Data Structures:** Convert `User.level` to use `serde` with the Enum directly.
- **Streamline Config:** Ensure all config values are actually used (as noted in previous reports, some might be unused).

## 4. Implementation of Robust Enhancements

**Proposed Enhancements:**
1.  **Unified UI Framework:** Implement a reusable TUI (Text User Interface) builder to make adding new commands and menus easier and consistent.
2.  **Strict TLS Enforcement:** Modify the server to refuse non-TLS connections entirely when in "public" mode, and default to "public" for safety unless explicitly overridden.
3.  **Structured Logging:** Ensure all logs are structured (JSON) for easier parsing by external tools, or keep the current format but ensure rotation is robust.

---

**Immediate Action Items:**
1.  Refactor `admin.rs` to use a new `TableBuilder` in `ui.rs`.
2.  Fix the `User` struct serialization.
3.  Implement strict TLS checks.
