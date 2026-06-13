# Secure vs. Vulnerable: Side-by-Side Comparison

This project implements the same features twice — once under `/vuln/...` with
intentional vulnerabilities, and once under `/secure/...` with the
corresponding fix. This document explains each pair.

## 1. Login (`views_vulnerable.login_view` vs `views_secure.login_view`)

| | Vulnerable | Secure |
|---|---|---|
| Authentication | Looks up the user manually and calls `user.check_password()` | Uses Django's `authenticate()` |
| Session handling | Sets `request.session["user_id"]` directly without rotating the session key | Calls Django's `login()`, which rotates the session key |
| Error messages | "No account with that username" vs "Wrong password for that account" | Single generic message: "Invalid username or password." |
| Logging | Logs the raw password: `log.info(f"login attempt user={username} password={password}")` | Logs a redacted dict via `redact()`: password is replaced with `***REDACTED***` |
| Rate limiting | `vulnerable_is_rate_limited` (see below) | `secure_is_rate_limited` (see below) |

**Vulnerabilities introduced:**
- **Session fixation** — because the session ID is never rotated on login, an
  attacker who can set a victim's session cookie before they log in can hijack
  the authenticated session afterward.
- **Account enumeration** — distinct error messages let an attacker determine
  whether a username exists.
- **Credential leakage via logs** — plaintext passwords end up in application
  logs.

## 2. Password Reset (`password_reset_request`)

| | Vulnerable | Secure |
|---|---|---|
| Existence check | Returns 404 "No account uses that email" if the email isn't found | Always returns the same message regardless of whether the account exists |
| Token generation | `base64.urlsafe_b64decode(str(user.id))` — i.e. the token *is* the user's ID, just base64-encoded | `django.contrib.auth.tokens.default_token_generator` — a signed, time-limited, single-use token |
| Token storage | Stored indefinitely in `PasswordResetToken` with no expiry | Not stored; verified on demand via the token generator |

**Vulnerabilities introduced:**
- **Account enumeration** via the 404 response.
- **Predictable / forgeable reset tokens** — the "token" trivially decodes
  back to the target user's primary key, so any user's account can be reset
  by guessing/incrementing IDs.
- **No token expiry** — old reset tokens remain valid forever.

## 3. Document Access (`document_detail`, `document_list`)

| | Vulnerable | Secure |
|---|---|---|
| Auth required | No (`document_detail`/`document_list` are open to anonymous users) | `@login_required` |
| Ownership check | None — any document can be fetched by ID | `if doc.owner_id != request.user.id and not doc.is_published: raise PermissionDenied` |
| Listing scope | `Document.objects.all()` — every user's documents | `Document.objects.filter(owner=request.user)` |

**Vulnerability introduced: Insecure Direct Object Reference (IDOR) /
Broken Access Control** — any user (including anonymous visitors) can read
any document, including private/unpublished ones belonging to other users,
just by iterating `pk` values.

## 4. Document Creation (`document_create`)

| | Vulnerable | Secure |
|---|---|---|
| Form fields | `VulnerableDocumentForm` — `fields = "__all__"` (includes `owner`, `is_published`) | `SecureDocumentForm` — `fields = ["title", "body"]` only |
| Owner assignment | Whatever the client submits in the `owner` field | Forced server-side: `doc.owner = request.user` |
| Auth required | No | `@login_required` |

**Vulnerability introduced: Mass Assignment** — because the form exposes
every model field, a client can POST an arbitrary `owner` ID and set
`is_published=true`, creating documents that appear to belong to (and be
published by) another user.

## 5. Rate Limiting (`core/ratelimit.py`)

| | Vulnerable (`vulnerable_is_rate_limited`) | Secure (`secure_is_rate_limited`) |
|---|---|---|
| Client identity source | `X-Forwarded-For` request header | `request.META["REMOTE_ADDR"]` (and/or the submitted username) |
| Storage | In-process Python dict (`_attempts`) | Django cache backend (`cache.add` / `cache.incr`) |
| Scope | Global — one bucket per "client" across all endpoints | Scoped per action via `scope=` (e.g. `"login"`) and per identity |

**Vulnerabilities introduced:**
- **Spoofable rate-limit key** — `X-Forwarded-For` is client-controlled, so
  an attacker can send a different value on every request and never be
  throttled.
- **Non-durable, per-process state** — an in-memory dict doesn't survive a
  restart and isn't shared across multiple worker processes, so the limit is
  far weaker than it appears (and resets are trivial).

## 6. Logging (`core/logging_utils.py`)

The secure flows route all log messages through:
- `sanitize()` — strips control characters (including `\r`/`\n`) and
  truncates long values, preventing **log injection / log forging** where an
  attacker-controlled value (e.g. a username containing `\n`) could fabricate
  fake log lines.
- `redact()` — replaces values for sensitive keys (`password`, `token`,
  `session`, etc.) with `***REDACTED***` before logging, preventing
  **sensitive data exposure** in logs.

The vulnerable flows log raw, unsanitized values directly.

---

## Summary Table

| Category | Vulnerability (vuln/) | Mitigation (secure/) |
|---|---|---|
| Login | Session fixation, account enumeration, plaintext password logging | Session rotation via `login()`, generic errors, redacted logging |
| Password reset | Account enumeration, predictable tokens, no expiry | Generic response, signed time-limited tokens |
| Document read | IDOR / broken access control | Ownership + published checks, login required |
| Document create | Mass assignment (`owner`, `is_published`) | Restricted form fields, server-assigned owner |
| Rate limiting | Spoofable `X-Forwarded-For`, in-memory state | Trusted `REMOTE_ADDR`, shared cache backend |
| Logging | Raw secrets and unsanitized input in logs | Redaction + control-character sanitization |
