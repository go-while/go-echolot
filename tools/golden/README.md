# Golden stats from Echolot

`harness.pl` runs Echolot's unmodified `Echolot/Stats.pm` (`build_stats`, `calculate`) on ping data read from JSON:
- it stubs Echolot's logging, tools, config and storage;
- it pins `time()` and `gmtime()`, so the output is reproducible;
- it writes `pub/` and `priv/` (`mlist2.txt`, `mlist.txt`, `rlist*.txt`) and `calc.json`, the per-remailer results of `calculate()`.

`gen.py <case>` writes the input of a golden case, deterministically:

1. random data: 6 remailers with 2 keys each, outstanding pings, very slow latencies, a 0 % remailer, and middleman vs exit caps;
2. hand-made edge cases (docs/design.md §11): no pings, only outstanding pings, even and odd medians, latencies on the bucket edges of both history alphabets, min_hr at 99 h and 100 h, nicks of 12, 13 and 15 characters, ties in reliability, day reliability 0.99985 vs 0.99995, exact `%5.1f`/`%6.2f` ties (1/16, 3/16, 1/32, 5/32) and near ties, pings less than a day in the future, the strict 12-day cutoff, every option letter, a hidden remailer, a `testing` one and one without conf; with sameop and both broken sections;
3. the remailers of case 2 with `stats_sort_by_latency` on and empty (but defined) broken sections;
4. random data with `stats_days` 7 and other weights;
5. no remailers.

`gen.py chain<n>` writes the chain ping cases (design §8.2), in `testdata/golden/chain<n>/`:

1. hand-made: every rule of the evaluation (`E:Stats.pm:557-622`) on 10 remailers with simple stats: 1, 2 and exactly 3 pings out; the 1.5 × (lat A + lat B) grace, one second either side; done/out exactly at 0.3 × rel A × rel B (3/10 with rel 1 × 1, 3/20 with 1 × 0.5) and just above; the 10-day window, one second either side; a young ping that is back; remailers that aren't rows; chains with a hidden or `testing` remailer (private only); a dead remailer whose chains compress to `(echo *)` at the threshold; a right nick at 5 privately and 4 publicly; with `broken1` and `broken2` files holding `*` entries, a duplicate, an empty line and lines that aren't chains;
2. random chain pings between the remailers of case 1, a few pairs losing almost everything; no files;
3. chain pings on but none sent and no files (both sections empty), and `compress_broken_chain` alone on hand-made lists (`compress.json`).

An input may set `config` (`stats_days`, `pings_weight`, `stats_sort_by_latency`) and `files` (the texts of `sameop`, `broken1`, `broken2`; a missing one is a missing file). An input with `chainpings` (`[sent, addr1, addr2, latency or null]`, even an empty list) turns chain pings on with Echolot's settings (`E:Config.pm:123-131`); the harness then also writes `ic.json`, the intensive care of the evaluation (`"addr1 addr2": reason`; the broken chains are the `bad: done/out` ones). `compress` (`[[num, [chain, ...]], ...]`) runs `compress_broken_chain` alone and writes `compress.json`.

```sh
python3 gen.py 2 > in.json
perl harness.pl /path/to/echolot/Echolot/Stats.pm in.json out/
```

It needs perl with core modules and JSON::PP only; GnuPG::Interface isn't needed. `../../testdata/golden/case*/` hold `in.json` and the output from crooks/echolot @ 40676ca (Stats.pm is unchanged by the yamn patch) on perl 5.40; `make golden ECHOLOT=/path/to/echolot` regenerates them all.

`go test ./internal/output/` compares against them without perl: `calc.json` within 1e-9 (JSON::PP prints 15 digits) and `pub/` and `priv/` `mlist2.txt` and `mlist.txt` byte for byte. `go test ./internal/chain/` compares the chain cases: `ic.json`, `compress.json`, and `mlist2.txt` and `mlist.txt` with the broken sections from `chain.Broken1Text` and `chain.Broken2Text`. The harness only runs Echolot's code; it doesn't change it.
