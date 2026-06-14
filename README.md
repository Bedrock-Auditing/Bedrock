[README.md](https://github.com/user-attachments/files/28935661/README.md)
<div align="center">

# bedrock

**What does your trust actually rest on?**

A supply-chain auditor that prices popularity at zero.
One file. One command. Zero config. Free, forever.

</div>

---

Every dependency tool answers *"is this package safe?"* with popularity —
downloads, stars, how many others depend on it. That is not evidence. It is
*other people's trust*, and trust grounded in trust is a ring that never
reaches the ground. The 2024 xz backdoor was that ring weaponized: sock-puppet
accounts vouching for each other until a maintainer handed over the keys.

**bedrock prices the evidence instead — on your machine.**

```bash
pip install bedrock-audit
bedrock requests --verify-source
```

```
  bedrock — requests  [+source]
  ----------------------------------------------------------------------
   requests           2.33.1    FAIL    tree:CONDITIONAL
   charset-normalizer 3.4.6     PASS    tree:CONDITIONAL
   idna               3.11      FAIL    tree:CONDITIONAL  !! 1 known vulnerabilities: GHSA-65pc
   urllib3            2.6.3     FAIL    tree:CONDITIONAL  !! 4 known vulnerabilities: GHSA-qccp
   certifi            2026.2.25 PASS    tree:CONDITIONAL
  ----------------------------------------------------------------------
   VERDICT: FAIL/CONDITIONAL  (weakest link, 5 pkgs)
   ledger: 117 files hashed, 20 fetches, 1036KB source  ·  popularity priced at zero
```

That output is real. `requests` fails because two of its dependencies carry
live CVEs, and the failure propagates to the root by weakest link — your app is
never more trustworthy than its least-verifiable dependency.

## What it checks

bedrock resolves your real transitive dependency tree (marker-aware) and grades
every package by what can actually be **verified**, weakest link first:

| tier | evidence |
|------|----------|
| **FORCED** | every installed file re-hashed against the wheel RECORD on *your* disk; with `--verify-source`, every installed `.py` compared byte-for-byte against the **published sdist** — the check that catches the xz class: an artifact diverging from its public source |
| **EMPIRICAL** | live OSV vulnerability scan; PEP 740 publisher attestations |
| **CONDITIONAL** | linked public repository; release within a sliding freshness window |
| **STIPULATED** | console-script divergence consistent with installer rewrite — flagged, never silently skipped |
| **UNPAID** | downloads, stars, age. **Popularity is priced at zero.** |

Every audit **seals into a tamper-evident hash chain** (`bedrock_chain.json`):
re-running on an identical environment reproduces the seal; changing one byte
breaks it.

## Usage

```bash
bedrock fastapi                       # audit a package and its tree
bedrock fastapi --verify-source       # + source-vs-installed verification
bedrock requests flask --json         # machine-readable, for CI
bedrock django --sbom sbom.json       # emit a CycloneDX 1.5 SBOM
bedrock pytest --offline              # local-only; remote tiers ABSENT not failed
```

Exit code is a contract: `0` = PASS at CONDITIONAL or better, `1` = read the
bill, `2` = nothing to audit (package not installed here).

No account. No telemetry. No hosted service. Nothing phones home. bedrock runs
entirely on your machine and costs you — and us — nothing per audit. That is
deliberate (see [`docs/WHY-FREE.md`](docs/WHY-FREE.md)).

## In CI

```yaml
- run: pip install bedrock-audit
- run: bedrock $(your-root-package) --verify-source --json
```

The repository audits itself on every push — see
[`.github/workflows/self-audit.yml`](.github/workflows/self-audit.yml). A tool
that prices trust should be willing to be checked, including by itself.

## What bedrock does *not* claim

It does not prevent attacks. A clean hash of a backdoored wheel is *integrity,
not innocence* — the wheel matched what was uploaded, and the upload was the
attack. bedrock tells you what your trust rests on. What you do about it is
yours. Every claim it makes is tiered; nothing is asserted that wasn't checked.

## The deeper part (optional)

bedrock's tier system isn't ad-hoc. It's one application of a general method for
building auditing systems that never reify their own outputs — *terrain first,
map second, every claim priced*. If you want the foundations the tool is built
on, they're in [`docs/METHOD.md`](docs/METHOD.md), open for inspection. You do
not need any of it to use the tool. But if you ever wondered why most security
tooling drowns you in noise, the answer is in there: they rank by what's cheap
to measure, not by what's actually been established. **Read it and check it —
the method invites the audit it performs.**

## License

MIT. Released free because trust infrastructure should not be paywalled, metered,
or rented. Use it, fork it, ship it inside your own tools. No attribution
required, though it's appreciated.
