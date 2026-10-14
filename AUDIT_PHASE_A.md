## Tests added (NOT RUN)
- `tests/test_plugin_integration.py`
  - `test_inprocess_plugin_register_and_invoke`
  - `test_sandbox_listing_and_worker_call`
  - `test_worker_print_noise_and_malformed_output`
  - `test_worker_returns_nonobject_json`
  - `test_worker_crash_during_call`
  - `test_huge_output_handling`
  - `test_listing_failure_register_raises`
  - `test_listing_timeout`
  - `test_declared_permission_clamped`
  - `test_registration_rollback_on_register_failure`
  - `test_collision_rejected`

## Verified
Nothing verified yet; run the commands below.

| Command | Result |
| --- | --- |
| `python -m pytest -q tests/test_plugin_integration.py` |  |
| `python -m pytest -q tests/test_plugin_sandbox.py` |  |
| `python -m compileall -q agent scripts tests` |  |
| `git diff --check` |  |
| `scripts/verify_env.py` |  |
| `CTF_TUTOR_ENABLE_PLUGINS=1 python main.py plugins` |  |
| `CTF_TUTOR_ENABLE_PLUGINS=1 CTF_TUTOR_PLUGIN_USE_SANDBOX=1 python main.py plugins` |  |

## Not verified
- The tests in `tests/test_plugin_integration.py` were not run in this environment.
- The full test suite was not run here.
- Runtime behavior of the sandboxed plugin worker under real CI conditions is not yet verified.

## Residual risks
- A subprocess boundary alone does not prevent filesystem or network access; the worker still runs with the host's effective privileges unless it is run inside a container or VM.
- Output truncation and read limits are best-effort mitigations, not a complete memory or process isolation policy.
- The current design is intentionally fail-closed for discovery and tool-call failures, but it still should be run under container/VM isolation for untrusted plugins.
