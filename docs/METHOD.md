# The method behind bedrock

bedrock's tier system is one application of a general discipline for building
auditing systems that don't lie to themselves. This document is the foundation,
open for inspection. **You do not need it to use the tool.** It's here because a
method that audits trust should be willing to be audited.

## The core move: price every claim

Most tools collapse everything into a binary — pass/fail, safe/unsafe, a green
checkmark. That collapse throws away the most important information: *how do we
know?* A package that passed a proof and a package that passed one mocked test
both render as a green checkmark, and the checkmark cannot tell them apart.

bedrock refuses the collapse. Every piece of evidence carries a **tier** that
records what kind of knowing it is:

- **FORCED** — verified here, now, by computation you could repeat. A file hash
  that matches. A source comparison that holds byte-for-byte. No trust required;
  the check either passes or it doesn't.
- **EMPIRICAL** — the world reported it and we fetched the report. A CVE scan, an
  attestation. Trustworthy as the source, no more.
- **CONDITIONAL** — testable but sampled. A linked repo, a recent release. True
  as far as it was checked, which is not all the way.
- **STIPULATED** — a declared assumption, flagged as such. Not hidden, not
  cleared.
- **UNPAID** — asserted but not established. **Popularity lives here.** It is
  recorded precisely so it can never be smuggled in as if it were evidence.

A verdict is only as strong as its weakest tier. This is the **weakest-link**
rule, and it's not a heuristic — it's forced. If your application depends on a
package whose trust is UNPAID, your application's trust is UNPAID, no matter how
many FORCED checks the rest of the tree passes. One unverifiable dependency is
an unverifiable application. bedrock propagates this through the whole
dependency graph and shows you the weakest link.

## Terrain first, map second

The discipline underneath the tiers is a habit: never let the map outrun the
terrain. A claim ("this package is safe") is a map marker. It is only worth what
the terrain underneath it can support. The job of an auditor is to check the
marker against the ground, and to mark clearly where there is no ground — not to
draw confident markers over unsurveyed territory.

This is why bedrock will say UNKNOWN. An honest "I don't have evidence here" is
worth more than a confident verdict with nothing under it. Most tools won't say
UNKNOWN because it feels like failure. It isn't. It's the most important thing an
auditor can say, because it's the one place a real attack hides.

## Why this generalizes (stated honestly)

The method here — price every claim, never reify an output into a fact it hasn't
earned, propagate by weakest link, say UNKNOWN when the terrain is unsurveyed —
is not specific to Python packages. It's a general shape for auditing *any*
system where claims accumulate and the cost of a wrong confident answer is high.

We're being deliberate about scope. bedrock demonstrates the method on
dependency trees because that's a domain where the checks are concrete, the
results are immediately useful, and you can verify every claim yourself today.
Whether the same discipline applies more broadly is a question we think is worth
asking — but a question you should ask *after* you've watched it work on
something checkable, not before. A method earns the right to be applied to harder
terrain by first proving itself on terrain you can inspect.

That is the whole sequence: prove it where it's checkable, then ask where else it
holds. If you find the tool useful and the method sound, you're equipped to ask
that second question yourself. We'd rather hand you a working instrument and an
open method than a grand claim you'd have to take on faith — taking things on
faith is the exact failure this method exists to prevent.

## Check it

Everything above is in the source. The tiers are in `bedrock.py`, plainly named.
The weakest-link propagation is the `audit()` function — twenty lines, no magic.
The seal chain is `seal()`. If any of it is wrong, it's wrong in a way you can
point to in code, which is the only kind of wrong worth having. Pull requests
that find a reified claim — a place where bedrock asserts more than it checked —
are the most welcome kind.
