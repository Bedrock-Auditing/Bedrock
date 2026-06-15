import sys, pathlib, hashlib, json
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))
import bedrock

def test_offline_audit_runs():
    table, edges = bedrock.audit(["pytest"], offline=True)
    assert "pytest" in table and table["pytest"]["own_value"] in (0.5, 1.0)

def test_record_integrity_forced_tier():
    import importlib.metadata as im
    atoms = bedrock.record_integrity(im.distribution("packaging"))
    forced = [a for a in atoms if a[0] == "record_integrity"]
    assert forced and forced[0][1] == bedrock.TIER["FORCED"]

def test_popularity_is_zero():
    assert bedrock.TIER["UNPAID"] == 0 < bedrock.TIER["FORCED"]

def test_weakest_link_never_exceeds_own():
    table, edges = bedrock.audit(["pytest"], offline=True)
    for n, d in table.items():
        assert d["tree_tier"] <= d["own_tier"]

def test_cyclonedx_shape():
    table, _ = bedrock.audit(["iniconfig"], offline=True)
    s = bedrock.cyclonedx(table)
    assert s["bomFormat"] == "CycloneDX" and s["components"]

def test_seal_chain_tamper_evident(tmp_path):
    p = tmp_path / "chain.json"
    bedrock.seal({"roots": ["a"], "x": 1}, str(p))
    bedrock.seal({"roots": ["b"], "x": 2}, str(p))
    chain = json.loads(p.read_text())
    prev, ok = "GENESIS", True
    for g in chain:
        body = {k: v for k, v in g.items() if k not in ("sha", "sha_prev")}
        want = hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()[:16]
        ok &= g["sha"] == want
        prev = g["sha"]
    assert ok
    chain[0]["roots"] = ["TAMPERED"]
    body = {k: v for k, v in chain[0].items() if k not in ("sha", "sha_prev")}
    want = hashlib.sha256(("GENESIS" + json.dumps(body, sort_keys=True)).encode()).hexdigest()[:16]
    assert chain[0]["sha"] != want
