# A950RG F21 — Unauthenticated command execution through the upload query alias

| Field | Value |
|---|---|
| Vendor | TOTOLINK (Zioncom) |
| Product | A950RG |
| Firmware | V4.1.2cu.5268_B20221104 |
| SHA-256 | fcf25f006f30575abb7356f0dd4325c4c952bd77f76b98166fbeb0de6c3d2c4f |
| Component | cstecgi.cgi, upgrade.so, setUpgradeFW |
| CWE | CWE-862, CWE-78 |
| Authentication | None |
| CVSS 3.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 9.8 Critical |
| Status | Reported to the vendor. The vendor confirmed a fix. |

## Summary

The upload action in cstecgi.cgi is handled before the normal session check. A topic is accepted when it contains the text UploadCustomModule. Query text is copied into the generated JSON without escaping, so the topic can end at setUpgradeFW and a FileName value can be added beside it. setUpgradeFW places that file name into a shell command.

## Evidence

One isolated QEMU run sent a request with no cookie. The local broker recorded the forged topic. The upgrade handler ran, returned its invalid-firmware result, and the guest shell wrote a harmless marker file. The same upload action without the exception text was rejected as an invalid token.

No physical device was tested.

## Coordination

Included in the A950RG report sent to fae@zioncom.net. The vendor later confirmed that the reported issues are fixed.

Credit: Duc Doan
