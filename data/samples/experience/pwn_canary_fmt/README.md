# pwn_canary_fmt (multi-mitigation teaching lab)

**Canary enabled** (`-fstack-protector`). First input is a **format-string** leak surface; second is classic overflow.

Teaching sequence: leak → defeat canary → control return → `win()`.

**Expected techniques:** format-string, stack-buffer-overflow  
**Provenance:** synthetic-lab
