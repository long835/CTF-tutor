# forensics_pcap_multi (teaching lab)

Multi-packet PCAP: TCP handshake-ish traffic + HTTP GET + response.

The flag is in the **HTTP response body**, not the first packet.

```bash
tcpdump -A -r capture.pcap
strings capture.pcap | grep flag
```

**Expected techniques:** pcap-http, network-forensics  
**Provenance:** synthetic-lab
