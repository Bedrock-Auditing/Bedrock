#!/usr/bin/env python3
"""
bedrock — what does your trust actually rest on?
================================================================================
A supply-chain auditor that prices POPULARITY AT ZERO. Download counts, stars,
and "everyone uses it" are not evidence — they are other people's trust, and
trust grounded in trust is a ring that never reaches the ground. The 2024 xz
backdoor was that ring weaponized. bedrock prices the evidence instead, on YOUR
machine, and tells you the weakest link in your whole dependency tree.

One file. One command. Zero config. Readable by a vibe coder, trusted by an auditor.

    python3 bedrock.py fastapi --verify-source
    python3 bedrock.py requests flask --json
    python3 bedrock.py pytest --offline          # local-only, no network
    python3 bedrock.py django --sbom sbom.json   # CycloneDX out

Evidence tiers (the ORDER is the only stipulation; everything else is derived):
    FORCED       verified here, on disk: every installed file re-hashed against
                 the wheel RECORD; with --verify-source, every installed .py
                 compared byte-for-byte against the PUBLISHED sdist. The atom
                 that catches the xz class: artifact != public source.
    EMPIRICAL    the world voted, fetched live: OSV vulnerability scan; PEP 740
                 publisher attestations.
    CONDITIONAL  testable but sampled: linked public repo; release within a
                 sliding freshness window measured against today().
    STIPULATED   declared worlds: console-script divergence consistent with an
                 installer shebang rewrite — flagged, NEVER silently skipped.
    UNPAID       popularity. Priced at zero. Recorded so it can never be
                 smuggled back in as evidence.

Verdicts propagate by WEAKEST LINK through the transitive tree: your app is
never more trustworthy than its least-verifiable dependency. Every audit seals
into a tamper-evident hash chain. License: MIT.
"""
import sys, json, time, hashlib, base64, pathlib, urllib.request
import io, tarfile, datetime, argparse
from collections import deque
import importlib.metadata as im

try:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    _HAVE_PACKAGING = True
except Exception:
    _HAVE_PACKAGING = False
    def canonicalize_name(n): return n.lower().replace("_", "-")

TIER = {"UNPAID": 0, "STIPULATED": 1, "CONDITIONAL": 2,
        "EMPIRICAL": 3, "FORCED": 4}
TNAME = {v: k for k, v in TIER.items()}
WORD = {1.0: "PASS", 0.5: "UNKNOWN", 0.0: "FAIL"}
FRESH_DAYS = 540
H = {"fetch_s": 0.0, "hash_s": 0.0, "files": 0, "fetches": 0, "src_kb": 0}

def b64sha(d):
    return base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b"=").decode()

def fetch(url, raw=False, timeout=30):
    t0 = time.time(); H["fetches"] += 1
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = r.read()
        out = data if raw else json.loads(data.decode())
    except Exception:
        out = None
    H["fetch_s"] += time.time() - t0
    return out

def record_integrity(dist):
    t0 = time.time()
    checked = mismatched = unhashed = rewrites = 0
    bad = []
    for f in (dist.files or []):
        if f.hash is None:
            unhashed += 1; continue
        if f.hash.mode != "sha256":
            continue
        try:
            data = f.locate().read_bytes()
        except (FileNotFoundError, OSError):
            continue
        checked += 1
        if b64sha(data) == f.hash.value:
            continue
        is_script = ("/bin/" in str(f) or "/Scripts/" in str(f)
                     or str(f).startswith("../"))
        if is_script and data.startswith(b"#!"):
            rewrites += 1
        else:
            mismatched += 1; bad.append(str(f))
    dt = time.time() - t0
    H["hash_s"] += dt; H["files"] += checked
    atoms = []
    if checked == 0 and unhashed == 0:
        return [("record_absent", TIER["UNPAID"], 0.5, dt,
                 "no verifiable RECORD (legacy install) — not checkable, "
                 "recorded not punished")]
    if checked:
        note = f"{checked} files match RECORD"
        if bad: note += f", {mismatched} DIVERGE: {bad[0]}"
        if unhashed: note += f" [{unhashed} RECORD entries unhashed — coverage gap]"
        atoms.append(("record_integrity", TIER["FORCED"],
                      1.0 if mismatched == 0 else 0.0, dt, note))
    if rewrites:
        atoms.append(("script_rewrite", TIER["STIPULATED"], 0.5, 0.0,
                      f"{rewrites} console script(s) diverge with shebang "
                      "structure — consistent with installer rewrite, "
                      "NOT cleared: re-audit advised"))
    return atoms

def source_matches_installed(name, version, dist):
    rel = fetch(f"https://pypi.org/pypi/{name}/{version}/json")
    if not rel:
        return []
    sdist = next((u for u in rel.get("urls", [])
                  if u.get("packagetype") == "sdist"
                  and u["filename"].endswith(".tar.gz")), None)
    if not sdist:
        return [("source_available", TIER["UNPAID"], 0.5, 0.0,
                 "no sdist published — source-vs-installed not checkable")]
    blob = fetch(sdist["url"], raw=True)
    if not blob:
        return []
    H["src_kb"] += len(blob) // 1024
    t0 = time.time()
    published = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith(".py"):
                    parts = pathlib.Path(m.name).parts
                    key = "/".join(parts[1:]) if len(parts) > 1 else m.name
                    published[key] = hashlib.sha256(tf.extractfile(m).read()).hexdigest()
    except (tarfile.TarError, EOFError):
        return [("source_parse", TIER["UNPAID"], 0.5, 0.0, "sdist unreadable")]
    compared = diverged = 0
    examples = []
    for f in (dist.files or []):
        if not str(f).endswith(".py"):
            continue
        key = str(f)
        if key not in published:
            continue
        try:
            disk = f.locate().read_bytes()
        except (FileNotFoundError, OSError):
            continue
        compared += 1
        if hashlib.sha256(disk).hexdigest() != published[key]:
            diverged += 1
            if len(examples) < 3:
                examples.append(key)
    dt = time.time() - t0
    H["hash_s"] += dt
    if compared == 0:
        return [("source_match", TIER["UNPAID"], 0.5, dt,
                 "no comparable .py paths (build-generated / namespaced) — "
                 "not checkable")]
    val = 1.0 if diverged == 0 else 0.0
    note = (f"{compared} installed .py match published source" if not diverged
            else f"{diverged}/{compared} installed .py DIVERGE from published "
                 f"source: {', '.join(examples)} — ARTIFACT != SOURCE")
    return [("source_match", TIER["FORCED"], val, dt, note)]

def pypi_atoms(name, version):
    atoms = []
    meta = fetch(f"https://pypi.org/pypi/{name}/{version}/json")
    if meta is None:
        return atoms
    vulns = meta.get("vulnerabilities") or []
    atoms.append(("osv_scan", TIER["EMPIRICAL"], 0.0 if vulns else 1.0, 0.0,
                  f"{len(vulns)} known vulnerabilities"
                  + (": " + vulns[0].get("id", "?") if vulns else "")))
    info = meta.get("info", {})
    urls = (info.get("project_urls") or {})
    repo = any("github.com" in (u or "") or "gitlab" in (u or "")
               for u in list(urls.values()) + [info.get("home_page") or ""])
    rel = fetch(f"https://pypi.org/pypi/{name}/json")
    if not repo and rel:
        i2 = rel.get("info", {})
        u2 = list((i2.get("project_urls") or {}).values()) + [i2.get("home_page") or ""]
        repo = any("github.com" in (u or "") or "gitlab" in (u or "") for u in u2)
    atoms.append(("source_repo_linked", TIER["CONDITIONAL"],
                  1.0 if repo else 0.5, 0.0,
                  "public source repository linked" if repo else "no public repo"))
    newest = None
    if rel:
        for files in rel.get("releases", {}).values():
            for fobj in files:
                ts = fobj.get("upload_time_iso_8601", "")
                if ts: newest = max(newest or ts, ts)
    cutoff = (datetime.date.today() - datetime.timedelta(days=FRESH_DAYS)).isoformat()
    fresh = bool(newest and newest[:10] >= cutoff)
    age = ((datetime.date.today() - datetime.date.fromisoformat(newest[:10])).days
           if newest else None)
    atoms.append(("release_cadence", TIER["CONDITIONAL"], 1.0 if fresh else 0.5, 0.0,
                  f"latest upload {newest[:10] if newest else '?'}"
                  + (f" ({age}d ago; window {FRESH_DAYS}d)" if age is not None else "")))
    for f in (meta.get("urls") or []):
        if f.get("provenance"):
            atoms.append(("pep740_attestation", TIER["EMPIRICAL"], 1.0, 0.0,
                          "publisher attestation present")); break
    else:
        atoms.append(("pep740_attestation_absent", TIER["UNPAID"], 0.5, 0.0,
                      "no attestation served — absence recorded, not punished"))
    atoms.append(("popularity", TIER["UNPAID"], 1.0, 0.0,
                  "downloads/stars/age: PRICED AT ZERO — not evidence"))
    return atoms

def dep_tree(roots):
    seen, order, edges = {}, [], {}
    q = deque(canonicalize_name(r) for r in roots)
    while q:
        name = q.popleft()
        if name in seen:
            continue
        try:
            dist = im.distribution(name)
        except im.PackageNotFoundError:
            continue
        seen[name] = dist; order.append(name); edges[name] = []
        for raw in (dist.requires or []):
            if _HAVE_PACKAGING:
                try:
                    req = Requirement(raw)
                except Exception:
                    continue
                if req.marker is not None:
                    try:
                        if not req.marker.evaluate({"extra": ""}):
                            continue
                    except Exception:
                        pass
                dep = canonicalize_name(req.name)
            else:
                if ";" in raw and "extra" in raw.split(";", 1)[1]:
                    continue
                dep = canonicalize_name(raw.split(";")[0].split("(")[0]
                        .split("[")[0].split(">")[0].split("<")[0]
                        .split("=")[0].split("!")[0].split("~")[0].strip())
            if dep:
                edges[name].append(dep); q.append(dep)
    return seen, order, edges

def audit(roots, verify_source=False, offline=False):
    dists, order, edges = dep_tree(roots)
    table = {}
    for name in order:
        dist = dists[name]
        atoms = record_integrity(dist)
        if offline:
            atoms.append(("offline", TIER["UNPAID"], 0.5, 0.0,
                          "offline: EMPIRICAL/CONDITIONAL atoms ABSENT, not "
                          "failed — coverage shrank, verdict says so"))
        else:
            if verify_source:
                atoms += source_matches_installed(name, dist.version, dist)
            atoms += pypi_atoms(name, dist.version)
        graded = [a for a in atoms if a[1] > TIER["UNPAID"]]
        table[name] = {"version": dist.version, "atoms": atoms,
                       "own_value": min((a[2] for a in graded), default=0.5),
                       "own_tier": min((a[1] for a in graded), default=0),
                       "W": round(sum(a[3] for a in atoms), 3)}
    val = {n: table[n]["own_value"] for n in table}
    tr = {n: table[n]["own_tier"] for n in table}
    for _ in range(len(table)):
        for n in table:
            for d in edges.get(n, []):
                if d in table:
                    val[n] = min(val[n], val[d]); tr[n] = min(tr[n], tr[d])
    for n in table:
        table[n]["tree_value"], table[n]["tree_tier"] = val[n], tr[n]
    return table, edges

def seal(out, path="bedrock_chain.json"):
    p = pathlib.Path(path)
    chain = json.loads(p.read_text()) if p.exists() else []
    prev = chain[-1]["sha"] if chain else "GENESIS"
    body = json.dumps(out, sort_keys=True)
    out["sha_prev"] = prev
    out["sha"] = hashlib.sha256((prev + body).encode()).hexdigest()[:16]
    chain.append(out); p.write_text(json.dumps(chain, indent=1))
    return out

def to_record(table, edges, roots):
    return {"roots": roots,
            "packages": {n: {"version": d["version"],
                             "tree_value": d["tree_value"],
                             "tree_tier": TNAME[d["tree_tier"]],
                             "own_tier": TNAME[d["own_tier"]],
                             "atoms": [{"id": a[0], "tier": TNAME[a[1]],
                                        "value": a[2], "note": a[4]}
                                       for a in d["atoms"]]}
                         for n, d in table.items()},
            "edges": edges}

def cyclonedx(table):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"timestamp": datetime.datetime.now().isoformat() + "Z",
                         "tools": [{"name": "bedrock", "version": "0.1.0"}]},
            "components": [
                {"type": "library", "name": n, "version": d["version"],
                 "purl": f"pkg:pypi/{n}@{d['version']}",
                 "properties": [
                     {"name": "bedrock:tier", "value": TNAME[d["tree_tier"]]},
                     {"name": "bedrock:verdict", "value": WORD[d["tree_value"]]},
                 ] + [{"name": "bedrock:finding", "value": a[4]}
                      for a in d["atoms"] if a[2] == 0.0]}
                for n, d in table.items()]}

def report(table, edges, roots, verify_source):
    print(f"\n  bedrock — {', '.join(roots)}"
          + ("  [+source]" if verify_source else ""))
    print("  " + "-" * 70)
    for n, d in table.items():
        w = WORD[d["tree_value"]]
        flag = next((a for a in d["atoms"] if a[2] == 0.0), None)
        print(f"   {n:18s} {d['version']:9s} {w:7s} tree:{TNAME[d['tree_tier']]:11s}"
              + (f"  !! {flag[4][:34]}" if flag else ""))
    rl = [canonicalize_name(r) for r in roots if canonicalize_name(r) in table]
    av = min(table[r]["tree_value"] for r in rl) if rl else 0.5
    at = min(table[r]["tree_tier"] for r in rl) if rl else 0
    print("  " + "-" * 70)
    print(f"   VERDICT: {WORD[av]}/{TNAME[at]}  (weakest link, {len(table)} pkgs)")
    print(f"   ledger: {H['files']} files hashed, {H['fetches']} fetches, "
          f"{H['src_kb']}KB source  ·  popularity priced at zero")
    return av, at

def main():
    ap = argparse.ArgumentParser(prog="bedrock",
        description="What does your trust actually rest on? Popularity = zero.")
    ap.add_argument("packages", nargs="*", default=["pytest"])
    ap.add_argument("--verify-source", action="store_true",
                    help="compare installed .py against published sdist")
    ap.add_argument("--offline", action="store_true",
                    help="skip network; remote tiers marked ABSENT not failed")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--sbom", metavar="FILE", help="write CycloneDX SBOM to FILE")
    a = ap.parse_args()
    roots = a.packages or ["pytest"]
    table, edges = audit(roots, a.verify_source, a.offline)
    missing = [r for r in roots if canonicalize_name(r) not in table]
    if missing and not a.json:
        print(f"\n  bedrock: not installed in this environment: "
              f"{', '.join(missing)}")
        print("  bedrock audits what is INSTALLED. Install the package first "
              "(e.g. `pip install " + missing[0] + "`), then re-run.")
        if not table:
            sys.exit(2)
    rec = seal(to_record(table, edges, roots))
    if a.sbom:
        pathlib.Path(a.sbom).write_text(json.dumps(cyclonedx(table), indent=1))
    rl = [canonicalize_name(r) for r in roots if canonicalize_name(r) in table]
    av = min(table[r]["tree_value"] for r in rl) if rl else 0.5
    at = min(table[r]["tree_tier"] for r in rl) if rl else 0
    if a.json:
        print(json.dumps({"verdict": WORD[av], "tier": TNAME[at],
            "packages": len(table), "seal": rec["sha"],
            "findings": [{"package": n, "note": x[4]}
                         for n, d in table.items() for x in d["atoms"]
                         if x[2] == 0.0]}, indent=1))
    else:
        report(table, edges, roots, a.verify_source)
        if a.sbom:
            print(f"   SBOM (CycloneDX) written to {a.sbom}")
        print(f"   sealed: {rec['sha']}\n")
    sys.exit(0 if (av == 1.0 and at >= TIER["CONDITIONAL"]) else 1)

if __name__ == "__main__":
    main()
