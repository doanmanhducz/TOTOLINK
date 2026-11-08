# X6000R F14 — Unauthenticated command execution after a stale session

| Field | Value |
|---|---|
| Vendor | TOTOLINK (Zioncom) |
| Product | X6000R |
| Firmware | V9.4.0cu.1360_B20241207 |
| SHA-256 | 32f11a6f07b1d8e8598ae1a028d9dca58096a7d3b8e0677f5285db3672e051b6 |
| Component | shttpd, liboperations.so, setStaticDhcpRules |
| CWE | CWE-288, CWE-78 |
| Authentication | None after an existing management session is older than 300 seconds |
| CVSS 3.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 9.8 Critical, with the stale-session condition |
| Status | Reported to the vendor. The vendor confirmed a fix. |

## Summary

Two defects combine. The management service accepts a request from a different address when a session has been idle for more than 300 seconds, without checking a password or a token. That recovered session can call setStaticDhcpRules. The handler checks the MAC address and does not check the IP value. The stored IP is later placed into a shell command.

## Evidence

In an isolated QEMU run, a session was aged past 300 seconds. A second address with no credentials then called the static-DHCP handler. The appliance shell wrote a harmless marker file. A request from a fresh address, and a request with no prior session, were both rejected.

The lab network was loopback only. No physical device was tested.

## Coordination

The issue was included in the X6000R report sent to fae@zioncom.net on 2026-10-02. The vendor later confirmed that the reported issues are fixed.

Credit: doanmanhducz (Duc Doan)
