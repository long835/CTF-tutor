# forensics_pcap (teaching lab)

Minimal PCAP with one HTTP response that embeds a flag-like string in an HTML comment.

**Expected techniques:** pcap-http, network-forensics

**How to investigate:**
```bash
tcpdump -A -r capture.pcap
# or: strings capture.pcap | grep flag
```

**Provenance:** synthetic-lab (not a contest capture)
