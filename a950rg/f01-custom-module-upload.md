# A950RG F01 — Unauthenticated custom module installation

| Field | Value |
|---|---|
| Vendor | TOTOLINK (Zioncom) |
| Product | A950RG |
| Firmware | V4.1.2cu.5268_B20221104 |
| SHA-256 | fcf25f006f30575abb7356f0dd4325c4c952bd77f76b98166fbeb0de6c3d2c4f |
| Component | cstecgi.cgi, product.so, UploadCustomModule |
| CWE | CWE-306, CWE-434 |
| Authentication | None |
| CVSS 3.1 | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 8.8 High |
| Status | Reported to the vendor. The vendor confirmed a fix. |

## Summary

UploadCustomModule is exempt from the session check. A request with no cookie can store a native module where the control service loads custom modules. After the loader is restarted, the service calls the module's initialization function.

## Evidence

In isolated QEMU, a no-cookie upload returned success and wrote a benign test module to the custom-module directory. A separate run restarted the loader by hand. The loader opened that module and the initialization function wrote a harmless marker. The restart invoked by the upload handler itself did not show a new loader or callback in this emulator.

No physical device was tested.

## Coordination

Included in the A950RG report sent to fae@zioncom.net. The vendor later confirmed that the reported issues are fixed.

Credit: Duc Doan
