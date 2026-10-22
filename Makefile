# make golden ECHOLOT=/path/to/echolot regenerates testdata/golden/ with
# Echolot's own Stats.pm (tools/golden/README.md).  go test never needs it.

ECHOLOT ?=
GOLDEN_CASES := 1 2 3 4 5
CHAIN_CASES := 1 2 3

.PHONY: golden test

test:
	go test ./...

golden:
	@test -n "$(ECHOLOT)" -a -f "$(ECHOLOT)/Echolot/Stats.pm" || \
		{ echo "set ECHOLOT to an Echolot checkout (with Echolot/Stats.pm)"; exit 1; }
	@for n in $(GOLDEN_CASES); do \
		d=testdata/golden/case$$n; \
		rm -rf $$d && mkdir -p $$d && \
		python3 tools/golden/gen.py $$n > $$d/in.json && \
		perl tools/golden/harness.pl "$(ECHOLOT)/Echolot/Stats.pm" $$d/in.json $$d || exit 1; \
		echo "$$d"; \
	done
	@for n in $(CHAIN_CASES); do \
		d=testdata/golden/chain$$n; \
		rm -rf $$d && mkdir -p $$d && \
		python3 tools/golden/gen.py chain$$n > $$d/in.json && \
		perl tools/golden/harness.pl "$(ECHOLOT)/Echolot/Stats.pm" $$d/in.json $$d || exit 1; \
		echo "$$d"; \
	done
