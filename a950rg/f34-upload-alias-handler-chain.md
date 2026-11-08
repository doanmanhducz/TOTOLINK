# A950RG F34 — Upload-alias authorization bypass to five command handlers

| Field | Value |
|---|---|
| Vendor | TOTOLINK (Zioncom) |
| Product | A950RG |
| Firmware | V4.1.2cu.5268_B20221104 |
| SHA-256 | fcf25f006f30575abb7356f0dd4325c4c952bd77f76b98166fbeb0de6c3d2c4f |
| Component | cstecgi.cgi and the handlers named below |
| CWE | CWE-862, CWE-78 |
| Authentication | None on the upload-alias route |
| CVSS 3.1 | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 8.8 High |
| Status | Reported to the vendor. The vendor confirmed a fix. |

## Summary

This is the same upload-query exception as F21, used to reach five other registered handlers instead of setUpgradeFW. It is one missing authorization check with five sinks, not five separate bypasses. The handlers are setDeviceName, setDiagnosisCfg, setNoticeCfg, setUploadSetting, and NTPSyncWithHost. Their ordinary routes require a session.

## Evidence

Isolated QEMU runs with no cookie reached each handler through the alias:

- setDeviceName ran the handler and the guest shell wrote a harmless marker. This is the clearest of the five.
- setDiagnosisCfg created a marker directory.
- setNoticeCfg applied shell redirection and created an empty file.
- setUploadSetting wrote a marker, then returned its invalid-configuration result.
- NTPSyncWithHost printed a marker before a later emulator fault.

A no-cookie upload query that did not contain the exception text was rejected as an invalid token. Two other handler names tried on the same alias did not produce a marker.

No physical device was tested. This score stays 8.8. It is not 9.8.

## Coordination

Included in the A950RG report sent to fae@zioncom.net as the group of additional handlers reached by the upload alias. The vendor later confirmed that the reported issues are fixed.

Credit: Duc Doan
