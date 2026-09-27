# pwn_nx_ret2win (multi-mitigation teaching lab)

Modern defaults imply **NX** (no stack shellcode). Overflow still reaches `win()`.

**Mitigations:** NX (typical), no PIE if built `-no-pie` for simpler teaching.

```bash
checksec --file=vuln   # if available
./vuln
```

**Expected techniques:** stack-buffer-overflow, ret2win  
**Provenance:** synthetic-lab
