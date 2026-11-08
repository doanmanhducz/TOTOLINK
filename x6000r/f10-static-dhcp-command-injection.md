# X6000R F10 — Authenticated command injection in setStaticDhcpRules

| Field | Value |
|---|---|
| Vendor | TOTOLINK (Zioncom) |
| Product | X6000R |
| Firmware | V9.4.0cu.1360_B20241207 |
| SHA-256 | 32f11a6f07b1d8e8598ae1a028d9dca58096a7d3b8e0677f5285db3672e051b6 |
| Component | shttpd, liboperations.so, setStaticDhcpRules |
| CWE | CWE-78 |
| Authentication | A valid management session is required for this issue alone |
| CVSS 3.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H — 8.8 High |
| Status | Reported to the vendor. The vendor confirmed a fix. |

## Summary

setStaticDhcpRules validates the MAC address and stores the IP value unchanged. When DHCP settings are applied, that IP is copied into an arp shell command with no quoting. A logged-in management user can therefore supply shell syntax in the IP field.

This is the injection used by F14 once a stale session has been taken over. Filed separately because the injection also exists for a normal logged-in session.

## Evidence

In isolated QEMU, a logged-in session stored a crafted IP. The DHCP apply path reached the shell and wrote a harmless marker. A normal IP value stored the lease and did not write the marker. A request without a session was rejected.

No physical device was tested.

## Coordination

Included in the X6000R report sent to fae@zioncom.net on 2026-10-02. The vendor later confirmed that the reported issues are fixed.

Credit: Duc Doan
