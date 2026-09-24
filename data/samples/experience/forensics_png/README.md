# forensics_png (teaching lab)

Minimal PNG with a `tEXt` comment carrying a flag-like string.

**Expected techniques:** image-metadata, steganography-basics

```bash
strings hidden.png | grep flag
# or: exiftool / pngcheck if installed
```

**Provenance:** synthetic-lab
