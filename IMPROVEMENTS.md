# CTF-Tutor v0.4.6

## Honest classifier numbers
| Set | Score | Independence |
|-----|-------|----------------|
| ground_truth / independent / public | ~100% | medium–high |
| generated (own vocabulary) | ~96% | **low** — may share rules |
| **external_hard** | **~70%** | **high** — deliberate non-taxonomy wording |

Do not market 96% as real-world accuracy.

## This pass
- `data/eval/external_hard.json` (23 cases)
- Gate check: external_hard ≥ 50%
- status reports eval_honesty
