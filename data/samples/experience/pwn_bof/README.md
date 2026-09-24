# pwn_bof (teaching lab)

Intentionally vulnerable local binary for buffer-overflow teaching.

**Expected techniques:** stack-buffer-overflow, ret2win-style control

**Build:** already compiled as `vuln` when gcc is available.

**Safety:** local only; do not expose on a network.

**Note:** uses deprecated `gets` on purpose for teaching.
