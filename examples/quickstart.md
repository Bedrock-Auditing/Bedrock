# Quickstart

```bash
pip install bedrock-audit          # or: python3 bedrock.py  (no install)
```

Audit something you already have installed:

```bash
bedrock requests --verify-source
```

Gate a CI build on it:

```bash
bedrock myapp --json || echo "supply chain needs review"
```

Generate an SBOM for compliance:

```bash
bedrock myapp --sbom sbom.cdx.json
# -> standard CycloneDX 1.5, with a verdict + tier on every component
```

That's the whole tool. There is no step two.
