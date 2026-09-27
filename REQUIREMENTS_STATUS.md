# v0.9.2 coherent architecture

## Single classification path
`classify_pipeline`: deterministic signals → heuristic → optional LLM → **evidence arbitration** → calibrated belief + UNKNOWN/ABSTAIN

## Agent loop
Uses pipeline + `capability_plan` + Pwn/Rev stage actions (not two competing classifiers).

## Capability-aware
Explicit CAN / CANNOT lists; missing tools surfaced; no claim past evidence.

## Still out of bounds
Live CTF, human RCT, full OS plugin isolation, autonomous general exploitation.
