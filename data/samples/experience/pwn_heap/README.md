# pwn_heap (teaching lab)

Simplified heap note manager with intentional **use-after-free** (free without nulling).

**Expected techniques:** heap-overflow, tcache-poisoning (conceptual), use-after-free

```bash
./vuln
# 1 alloc → 2 free → 3 show (UAF read) — lab only
```

**Provenance:** synthetic-lab  
**Note:** teaching binary, not a hardened glibc exploit challenge.
