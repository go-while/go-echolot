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

An input may set `config` (`stats_days`, `pings_weight`, `stats_sort_by_latency`) and `files` (the texts of `sameop`, `broken1`, `broken2`; a missing one is a missing file).

```sh
python3 gen.py 2 > in.json
perl harness.pl /path/to/echolot/Echolot/Stats.pm in.json out/
```

It needs perl with core modules and JSON::PP only; GnuPG::Interface isn't needed. `../../testdata/golden/case*/` hold `in.json` and the output from crooks/echolot @ 40676ca (Stats.pm is unchanged by the yamn patch) on perl 5.40; `make golden ECHOLOT=/path/to/echolot` regenerates them all.

`go test ./internal/output/` compares against them without perl: `calc.json` within 1e-9 (JSON::PP prints 15 digits) and `pub/` and `priv/` `mlist2.txt` and `mlist.txt` byte for byte. The harness only runs Echolot's code; it doesn't change it.
