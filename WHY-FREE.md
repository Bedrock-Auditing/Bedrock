# Why bedrock is free

Not free-trial. Not free-tier. Not open-core-with-a-paywall-later. Free.

## The short version

A new user normally adopts a tool *in debt*: a learning cost, a trust cost, a
lock-in risk, and the latent bill of "what happens when the free tier ends." We
paid the establishment cost up front so you don't carry any of that. You start
on a stable footing someone else already paid to build.

Releasing bedrock costs us nothing per user. It runs entirely on your machine —
no hosted service, no per-audit inference, no telemetry, nothing that bills
anyone when you run it. A thing that is cheap to release and confers stability
without initial debt isn't a product. It's closer to a spore.

The goal is not revenue. The goal is that better auditing rigor spreads. Free is
simply the configuration that spreads furthest.

## The longer version

Most "free" software in security is a funnel. The free tier exists to create the
debt the paid tier collects — and every user is quietly recalculating the bill
the whole time they use it. That recalculation is a cost too. It shapes what you
build on top of the tool, because you're hedging against the day the terms
change.

bedrock removes that. There is no day the terms change, because there are no
terms beyond the MIT license. You can fork it, vendor it, ship it inside your own
closed product, and never speak to us. That is not generosity for its own sake;
it is the only configuration in which you can build on bedrock *without* a hidden
liability in your dependency on it. A trust tool that you have to trust not to
rug-pull you has failed at its one job.

## What we get

Standing, not fees. A person who ships genuinely useful infrastructure, with the
rigor visible in the source, accrues a different kind of credit than a vendor —
the slower, larger kind that opens doors a paywall closes. If you find this
useful, the return we're hoping for is that you check the method, find it sound,
and carry the discipline into your own work. That propagation is the whole point.

## The one constraint this puts on us

Free-forever only works if release cost stays near zero. So every tool in this
project must be self-contained once shipped: no hosted dependency, no per-user
cost, nothing that bills us when you run it. The moment a feature needs us to
keep paying for each user, it stops being a spore and becomes a liability with
our name on it. If you ever see bedrock grow a mandatory hosted component, that
is the day to fork the last self-contained version. We'd rather you never need
to.
