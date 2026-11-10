# Feedback task starting environment

Upstream: https://github.com/twisted/twisted
Upstream commit: `a5ab096ce0956026954f83d7e46dd75a568cf4b7`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m twisted.trial twisted.cred.test.test_cred twisted.web.test.test_httpauth twisted.protocols.haproxy.test twisted.mail.test.test_smtp
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `PASSED (successes=174)`
Whole-command wall time: 0.316 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
