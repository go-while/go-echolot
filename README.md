# go-echolot

A pinger for the [yamn](https://github.com/crooks/yamn) remailer network, in Go. It is meant to replace the patched Perl [Echolot](https://github.com/crooks/echolot) that today's yamn pingers run.

**Status: phase 2 (pings → mlist2) is in place** (steps 1–8 of the plan in [docs/design.md §12.3](docs/design.md#123-first-pr-sized-steps)). go-echolot requests keys and confs from the remailers you add, pings every key through the `yamn` binary, publishes a key only after a ping to it came back (proof of possession), and writes `pubring.mix`, `type2.list`, `mlist2.txt` and `mlist.txt`. Still to come in phase 2: importing an Echolot data directory, and the 14-day side-by-side run against mixmin's pinger (§12.2) before its files are announced.

A pinger:
- collects each remailer's key and capabilities by mail (`remailer-key`, `remailer-conf`);
- sends test messages (pings) through each remailer and measures latency and reliability;
- publishes the results that yamn clients download: `pubring.mix` and `mlist2.txt`.

## Documents

- [docs/design.md](docs/design.md): the design. Architecture, data model, wire and output formats, the stats algorithm ported exactly from Echolot, security and trust, operations, testing, the phased plan, and open questions with recommended answers.
- [docs/spec.md](docs/spec.md): the earlier spec of what Echolot does. Where it differs from the design, the design wins.

## Main points

- **yamn only:** no Type I (cypherpunk/PGP) remailers and no Mixmaster.
- **Output files** are byte-compatible with Echolot's, so existing yamn clients work unchanged.
- **Dependencies:** the Go standard library and `golang.org/x/...`, plus one reviewed exception: `github.com/dchest/blake2s` v1.0.0, the package yamn uses for keyids (unkeyed BLAKE2s-128, which `x/crypto` can't compute; the review is yamn's ISSUES.md Y-52 ([go-while/yamn#68](https://github.com/go-while/yamn/pull/68))). Ping packets are built by running the `yamn` binary, which is not imported.
- **Storage:** plain files (`state.json`, a `pings.jsonl` journal) under one locked state directory.
- **Keys reach clients faster:** keys are requested every 2 h, and the keyring is rebuilt within minutes of a key change instead of up to ~32 h later.
- **Trust (yamn issue Y-03):**
  - **Proof of possession:** a key is published only after a ping encrypted to it has come back.
  - **Quarantine:** an unexpected key, name or address change waits 24 h or for operator approval.
  - **Signatures:** output files carry minisign-compatible Ed25519 signatures.
  - **yamn's own checks:** yamn clients already cross-check several pingers (`urls.pingers`, `key_quorum`), and yamn remailers warn when a pinger publishes a key that isn't theirs.

## Repository contents

- `cmd/go-echolot/`: the command: `run`, `deliver`, `add`/`delete`/`enable`/`disable`/`set`, `approve`/`reject`, `getkeyconf`, `buildkeys`, `status`, `keys`, `dumpconf`, `version` (`go-echolot help`). Commands that change the state go to the running daemon through a spool and SIGHUP.
- `internal/app/`: the daemon (jobs, reply handling), the operator commands, the spool and the thesaurus of raw replies.
- `internal/mailin/`, `internal/mailout/`: Maildir intake and `deliver`; sendmail, SMTP (verified TLS, per-command timeouts) and Tor for .onion remailers.
- `internal/sched/`, `internal/sdnotify/`: the slot scheduler and job loop; systemd notification and watchdog.
- `internal/config/`: the INI-style config parser, defaults and validation.
- `internal/store/`: the state dir: `state.json`, the `pings.jsonl` journal, the secret and the lock.
- `internal/token/`: reply addresses with HMAC tokens, Echolot's MD5 tokens after an import, and the keys derived from the secret.
- `internal/replies/`: parsers for `remailer-key` and `remailer-conf` replies and `pubring.mix`, accepting exactly what yamn clients accept.
- `internal/keys/`: the key policy: validity, which key is published and pinged, nick pinning, quarantine of unexpected changes, proof of possession, expiry.
- `internal/output/`: the published files, `pubring.mix`, `type2.list`, `mlist2.txt`, `mlist.txt` and their `.meta` files, byte-identical to Echolot's.
- `internal/stats/`: Echolot's `calculate()`, ported exactly and tested against Echolot's own output (`testdata/golden/`, `make golden`).
- `internal/pinger/`: the ping body (NaCl secretbox, MAC), the encoder that runs `yamn -m --stdout` with its own config and a one-key keyring per ping, and the receive side.
- `internal/blake2s/`: yamn's keyid (unkeyed BLAKE2s-128).
- `internal/fileutil/`: atomic file writes. `internal/civil/`: calendar dates for key validity.
- `examples/config.ini`: an example config that documents every key.
- `examples/go-echolot.service`: a systemd unit (`Type=notify`, watchdog).
- `tools/golden/`: a harness that runs Echolot's unmodified `Stats.pm` on synthetic ping data, so go-echolot's stats can be tested against Echolot's numbers. See its [README](tools/golden/README.md).
- `testdata/golden/case1..5/`: inputs and Echolot's output for the stats tests: the edge cases of design §11, `sort_by_latency`, 7 stats days, no remailers.
- `testdata/replies/`: a real yamn `remailer-key` and `remailer-conf` reply from victor's remailer (`yamn@virebent.art`), as stored by mixmin's pinger, for the reply parsers.
- `testdata/pubrings/`: the live `pubring.mix` of the mixmin, victor and frell pingers, fetched 2026-10-22 (6, 6 and 7 keys; every keyid checked against BLAKE2s-128). Frell's still lists middleman's key, which expired on 2026-10-19.
- `testdata/echolot-import/`: a synthetic Echolot metadata file, for the import of an Echolot data directory.

## Building

Go 1.27.3 or later:

```sh
go build ./cmd/go-echolot
go test -race ./...
# with the real yamn binary (client and remailer round trips):
(cd ../yamn && go build -o /tmp/yamn .) && YAMN_BIN=/tmp/yamn go test -run Yamn ./internal/pinger ./internal/app
```

## License

GPL-2.0-or-later (see [LICENSE](LICENSE)), the same as Echolot, whose algorithms and formats are ported.
