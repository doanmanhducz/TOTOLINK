# X6000R F07 — Unauthenticated VPN account disclosure and management

| Field | Value |
|---|---|
| Vendor | TOTOLINK (Zioncom) |
| Product | X6000R |
| Firmware | V9.4.0cu.1360_B20241207 |
| SHA-256 | 32f11a6f07b1d8e8598ae1a028d9dca58096a7d3b8e0677f5285db3672e051b6 |
| Component | shttpd |
| CWE | CWE-306, CWE-200 |
| Authentication | None |
| CVSS 3.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N — 8.2 High |
| Status | Reported to the vendor. The vendor confirmed a fix. |

## Summary

getVpnAccountCfg, setVpnAccountCfg, and delVpnAccountCfg are registered with the authentication flag unset. A caller who can reach the management service can read VPN usernames and passwords, create or change an account, and delete an account. An update is written through to the VPN chap-secrets file.

## Evidence

In isolated QEMU, requests without a cookie or token read synthetic VPN credentials, added an account, updated it, and deleted it. The update was present in chap-secrets. The accounts used in the test were created for the lab.

No physical device was tested.

## Coordination

Included in the X6000R report sent to fae@zioncom.net on 2026-10-02. The vendor later confirmed that the reported issues are fixed.

Credit: Duc Doan
