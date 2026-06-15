# Contributing

The most welcome contribution is an audit of the auditor.

bedrock's one promise is that it never asserts more than it checked. If you find
a place where it does — a verdict that claims more confidence than its evidence
supports, a reified output, a tier assigned without the check behind it — open an
issue or a PR. That's the bug class this project cares about most.

Practical stuff:
- Keep it one file. `bedrock.py` (and the mirror at `src/bedrock/__init__.py`)
  is the whole tool. Resist the urge to add a framework.
- Every new check carries a tier. If you can't say what kind of knowing a check
  produces (FORCED / EMPIRICAL / CONDITIONAL / STIPULATED), it isn't ready.
- No hosted dependencies, no telemetry, no per-user cost. See docs/WHY-FREE.md.
- Tests live in tests/. Add one for any new check.

By contributing you agree your work is released under the MIT license.
