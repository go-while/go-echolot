# Golden stats from Echolot

`harness.pl` runs Echolot's unmodified `Echolot/Stats.pm` (`build_stats`, `calculate`) on ping data read from JSON:
- it stubs Echolot's logging, tools, config and storage;
- it pins `time()` and `gmtime()`, so the output is reproducible;
- it writes `pub/` and `priv/` (`mlist2.txt`, `mlist.txt`, `rlist*.txt`) and `calc.json`, the per-remailer results of `calculate()`.

`gen.py` writes a deterministic synthetic data set: 6 remailers with 2 keys each, outstanding pings, very slow latencies, a 0 % remailer, and middleman vs exit caps.

```sh
python3 gen.py 1 > in.json
perl harness.pl /path/to/echolot/Echolot/Stats.pm in.json out/
```

It needs perl with core modules and JSON::PP only; GnuPG::Interface isn't needed. `../../testdata/golden/case1/` holds `in.json` and the output from crooks/echolot @ 40676ca on perl 5.40.

The plan (docs/design.md §11) is to commit more cases under `testdata/golden/`. `go test` then compares against them without perl, and a `make golden` target regenerates them where perl is present. The harness only runs Echolot's code; it doesn't change it.
