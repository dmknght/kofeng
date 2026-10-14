# Plan: the similarity database at scale

Goal: know, with numbers, what the block lookup structure does from 1e4 to 1e7 blocks (32 hashes each,
1.28 GB of hashes at 1e7), and make sure it never truncates silently.

## What is tested, without files

A deterministic generator (tests/lib/genome/fnprint_scale_synth.c) makes N blocks: real-like (the 32 smallest
of a span, so values sit at the bottom of the 32-bit range), uniform random, family variants (1000 blocks
sharing 28 of 32 hashes), a few HOT hashes held by every block, a tenth on the LIB side. An object is the list
of window values the pass would hand over; the oracle is a sorted set and a loop over each block's slots.
Cases: build time and bytes per pair vs N; filter bits per hash and load; false hits of a 32-bit key on
random values (expected n_key / 2^32, checked within 6 sigma); credit equals the oracle on every block;
families; skew (alternating two hot keys: bounded); a database over the allowance is refused with a status and
the ledger returns to zero; 4 threads share one database; retirement is opt-in and changes nothing for a tag
that is not retired; a database built twice is the same index; sizes the index word cannot hold are refused.
The shipped matcher is measured on the same bytes (tests/unit/fnprint_scale_cur.c): same credit on every block,
its limits with file:line, and a KM_CHECK for each silent degradation.

## Scales and cost

Default: 1e4 and 1e5 blocks, under 5 s and 200 MB (`make unit`). Opt in: `--scale=1e6`, `--scale=1e7` on the
test binary (1e7 needs several GB for the shipped matcher alone: 8 bytes per pair plus a 4-byte stamp per pair
per thread). The measured curves (time, Ir, D1/LL misses, peak memory; stream vs batch) are scratch
measurements, not tests: fnprint_scale.md and fnprint_pred_eval.md.

## What would change the plan

A real corpus DB (the repo ships none), a pack with more than 2^24 blocks, or a change of the window or the
block layout (not in scope: no pack or ABI change here).
