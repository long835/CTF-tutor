# pwn_decoy_crypto (ambiguous lab)

The binary **mentions AES** in a string. The actual bug is an unbounded stack read.

**Teaching goal:** do not trust decoy strings; confirm with crash/control evidence.

**Expected techniques:** stack-buffer-overflow (not crypto)

**Provenance:** synthetic-lab
