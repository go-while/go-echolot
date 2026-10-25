# go-echolot: design (yamn-only pinger)

Status: design draft, 2026-10-21; updated 2026-10-22 (proof of possession, yamn-side status, no more Perl work; see the addendum at the end). Builds on [`spec.md`](spec.md); where they differ, this document wins.

Sources:
- **Echolot:** [crooks/echolot](https://github.com/crooks/echolot) @ 40676ca. It differs from upstream (`https://git.noreply.org/projects/echolot.git`, 54d9504) only in Conf.pm:140/142 (brace escaping) and the GnuPG uid parsing in Conf.pm:399–415.
- **yamn:** go-while/yamn @ f9299d7 (module `github.com/crooks/yamn`).

File:line references below are to those trees. `E:` means Echolot and `Y:` means yamn.

Contents:
1. Decisions at a glance
2. Corrections to the spec, and surprises
3. Architecture and repository decision
4. Components and package layout
5. Data model and storage
6. Wire formats
7. Output files (byte-exact)
8. Algorithms
9. Security and trust (Y-03)
10. Operations
11. Testing
12. Phased plan, sizes, first PRs
13. Open questions (with recommended answers)

---

## 1. Decisions at a glance

| Decision | Recommendation |
|---|---|
| Repository | Separate repo `go-while/go-echolot`, with **no Go import of yamn**. Packets are built by running the `yamn` binary (`-m --stdout -c 1`) behind an `Encoder` interface. |
| Storage | Plain files: `state.json` (replaced atomically) plus an append-only `pings.jsonl` journal, under one `flock`ed state dir. Not LevelDB or bbolt. |
| Token MAC | HMAC-SHA256 with an HKDF-derived key, truncated to 16 hex digits. The Echolot address shape `local+type.id=time=hash@domain` is kept. |
| Ping body | Echolot's field layout, sealed with NaCl `secretbox`, base64-armored. |
| Key requests | `remailer-key` every 2 h. The pubring is rebuilt within 5 min of a key change and at least hourly. |
| Expired keys | Never published, never pinged. |
| Ping history | Kept 12 days per *address*, independent of key expiry. This is a deliberate change from Echolot. |
| Discovery | Operator-maintained list. Other remailers' conf replies only produce *suggestions*. |
| Key changes | Normal rotation is accepted automatically. An unexpected key change, nick change or address change goes into quarantine until the operator approves or 24 h pass. |
| Proof of possession | A key is published only after a ping encrypted to it has come back (§9.2). A forger who can send mail to the pinger but can't read the remailer's mail never gets a key published. |
| Signatures | minisign-compatible Ed25519 detached signatures (`*.minisig`) with a signed trusted comment carrying the file name, time and expiry. |
| Client cross-check | New yamn `urls.pingers` list, `key_quorum` N-of-M, and per-remailer median stats. Specified in §9.6 so it can be done as an independent yamn PR. |
| Liveness | `status.json`/`status.txt` in the results dir, a `go-echolot check` exit code, a systemd watchdog, and peer staleness checks between pingers. |
| Dependencies | Standard library and `golang.org/x/...` only (decision 2026-10-22): `x/crypto` (`nacl/secretbox`, `blake2b` for minisign), `x/sys/unix` (`flock`). HKDF, Ed25519, HMAC, JSON, SMTP and Maildir handling come from the standard library or are our own code. No YAML library, so the config is a small INI format (§10.3). One reviewed exception (2026-10-22), not a precedent for other imports: `github.com/dchest/blake2s` v1.0.0 for yamn's keyid, unkeyed BLAKE2s-128, which `x/crypto/blake2s` can't compute (its 128-bit variant needs a key). yamn uses the same package and version (same `go.sum` hash); the review is yamn's ISSUES.md Y-52 ([go-while/yamn#68](https://github.com/go-while/yamn/pull/68)). |
| Perl Echolot | No further changes (decision 2026-10-22). The go-while/echolot `yamn` branch stays as it is; all new pinger work goes into go-echolot. |

---

## 2. Corrections to the spec, and surprises

### 2.1 What the spec got wrong or missed

1. **"The yamn pingers run modified, unpublished Echolot code." The change was small and is known in outline.**
   - The September 2020 SEC3 tutorial (archived in [go-while/echolot](https://github.com/go-while/echolot/tree/research/usenet-pinger-history/research/usenet/wayback), branch `research/usenet-pinger-history`, `research/usenet/wayback/sec3-install_yamn_pinger-2020-09-20.html`, lines 126–174) sets up a pinger like this:
     - download stock `github.com/crooks/echolot/archive/master.zip`;
     - replace `Echolot/Conf.pm` with a "tweaked Conf.pm … Thank you, Zax for this patch" (Zax = Steve Crook, the yamn author);
     - replace `templates/echolot.html`;
     - use SEC3's `pingd.conf`.
   - "echolot4yamn" only appears in the 2021+ versions of the tutorial, and is presumably the same bundle.
   - yamn's key block (keyid line, then one 64-hex public key line; `Y:keymgr/secret.go:205-210`) has been unchanged since 2014 (commit 4e0e9fa). So the patch must essentially be `parse_mix_key`'s block regex (`E:Conf.pm:285-289`, repeated at 320-324), accepting a hex line in place of `\d+` plus base64.
   - `pingd.conf` presumably set `mixmaster` to the yamn binary and `mixhome` to the yamn directory.
   - `Pinger/Mix.pm` runs `$mixmaster -m -S -l <chain>` with `MIXPATH` set and writes `mix.cfg` (`E:Pinger/Mix.pm:69-110`). pre-2022 yamn ignores both and reads `yamn.cfg` (gcfg) from its own lookup path (YAMNCFG or `--dir` at the time). So those pingers probably relied on the working directory or on that config path, and yamn sent the ping itself via `Pipe = sendmail -f … -t`. We don't need to reproduce this exactly.
   - None of the patched files was archived, so the details stay unknown. That doesn't matter, because we reimplement from the stock Echolot source.
2. **Victor's version string.** Victor's "Mixmaster 0.2c" (summary version `4:0.2c`) is plain upstream crooks/yamn from 2021 (version const `0.2c` at e353d8d), not a fork.
   - There is a sec3pinger/yamn module (`github.com/sec3pinger/yamn@v0.0.0-20211104194555-1e9eba20d98e`, still served by the Go module proxy) with `versionprog = "yamn-0.2c"`.
   - Its `packet.go` differs from crooks 772af56 **only in error-message strings**. The wire format has been stable since 2016, which settles the version-skew question in §3.
3. **"If a reply lists two keys during rotation, both get the same timestamp."** This cannot happen with yamn.
   - `remailer-key` replies with the file `files.pubkey` (`Y:server.go:712-717`). That file always holds exactly one key, because `WritePublic` and `WriteMyKey` rewrite it (`Y:keymgr/secret.go:166-215, 250-302`).
   - The tie can still occur in the store: the old key, last seen in an earlier reply, sits next to the new one. Echolot breaks it by the strict `<` on `last_update` (`E:Stats.pm:816`), i.e. by hash order only when the timestamps are exactly equal.
   - We handle N keys per reply anyway (Mixmaster style), with a deterministic order (§8.4).
4. **`last_update` is not the reply time.** `Mailin::handle` passes the *token timestamp*, i.e. when the request was sent, as the time (`E:Mailin.pm:94-101`). So `last_update` for keys and confs means "time we asked". `set_key`/`set_caps` ignore any reply whose timestamp is not newer than what is stored (`E:Storage/File.pm:1289-1292, 1355-1358`).
5. **Old pings vanish with their key, which truncates the history.**
   - `expire()` deletes a key 5 days after `last_update`, **together with its ping files** (`E:Storage/File.pm:1575-1578`).
   - With short key lifetimes, the 12-day history is therefore cut short. That explains the `?????` columns on mixmin and Victor, 2026-10-21 04:40: e.g. `yamn ?????1100110`. mixmin's own keys run only 5 days (`2026-10-18 … 2026-10-23`).
   - Frell shows a full 12 days for the same remailers, and still lists middleman's key two days after it expired. That's consistent with a larger `expire_keys`.
6. **Expired keys are published.**
   - `build_mixring` picks the key with the newest `last_update` and never looks at the expiry date (`E:Stats.pm:808-827`).
   - Key *replies* with a past expiry date are rejected (`E:Conf.pm:344-346`). So a key that stops being refreshed stays in `pubring.mix` for up to 5 days after its date.
   - Live examples:
     - Frell and Victor still served middleman's key `ffbd…` (expires 2026-10-19) on 10-20; Frell still serves it on 10-21.
     - Victor served yamn4's old `a2559b…` (expires 10-19) on 10-20.
   - yamn clients drop such keys themselves (`Y:keymgr/public.go:367-379`), so the damage is a missing remailer, not a broken one.
7. **Pinging and listing don't depend on the remailer state.**
   - `send_pings` checks only `pingit` (`E:Pinger.pm:126`).
   - `build_rems`/`build_mixring` don't look at `status`.
   - A remailer in `ttl timeout`/`dead` is therefore still pinged and listed until its keys expire. Only *requests* stop (`E:Conf.pm:71`).
8. **Local send failures count as remailer losses.** `do_ping` registers the ping as `out` even when the `mix` call failed: the return value of `do_mix_ping` is ignored (`E:Pinger.pm:96-108`).
9. **Request types.** yamn never answers `remailer-stats` ("ignoring request", `Y:server.go:767-773`), and answers `remailer-adminkey` only if `files.adminkey` exists. Echolot sends all five daily (`E:Conf.pm:80`).
10. **The methodology document contradicts the code.**
    - `doc/methodology` describes `mod_age = (now − sent − 15 min) × 0.8` and "fraction returned *within* mod_age".
    - The code divides by 0.8 and counts latencies strictly *greater* than mod_age (`E:Stats.pm:220-229, 277`), i.e. "probability it is still coming". The spec follows the code, correctly. We do the same.
11. **The chain-ping window is 10 days, not 12.** `chainping_period => 10*24*60*60` carries the comment "12 days" (`E:Config.pm:126`). Chain pings *expire* after 12 days (`expire_chainpings`, `E:Config.pm:142`).
12. **"Frell's caps lines lack addresses."** I could not reproduce this. Frell's `mlist2.txt` fetched 2026-10-21 04:41 has normal `$remailer{"…"} = "<addr> …";` lines. Either way it doesn't matter:
    - yamn stops reading after the first empty line following the table (`Y:keymgr/public.go:210-216, 272-274`);
    - Echolot never reads `mlist2.txt`;
    - only Mixmaster-era tools parse that section.
13. **Size estimate.** The spec's ≈1,750 lines covers the bare core. With CLI, health, import and tests, the MVP is ≈3,900 lines of code plus about as much test code (§12).

### 2.2 Other surprises in the code

- **Discovery is circular.** A yamn conf reply's "SUPPORTED MIXMASTER (TYPE II) REMAILERS" list is just the summary lines of the remailer's *own downloaded* `pubring.mix` (`Y:server.go:744-751`), which comes from a pinger.
  - So "6 remailers recommend X" really means "the pingers they fetch from list X".
  - The list is still useful diagnostically: it shows which key each remailer currently believes in for every other remailer.
- **Address takeover via key replies.**
  - `parse_mix_key` takes *every* summary line in a key reply (`E:Conf.pm:278-284`).
  - Any line whose address differs becomes a prospective address with reason `self-capsstring-key` (`E:Conf.pm:348-352`).
  - Prospective addresses with that reason are added immediately at the next commit (`E:Storage/File.pm:937-941`).
  - So any remailer can make every Echolot pinger start mailing requests to arbitrary third-party addresses.
- **Nick collisions are dangerous for clients.**
  - yamn's `Pubring.Put` overwrites the nick→address map (`Y:keymgr/public.go:133-136`), and stats are matched by nick (`Y:keymgr/public.go:224-229`).
  - A second remailer claiming nick `yamn` can therefore capture `-l yamn` chains and the real remailer's stats.
  - Echolot doesn't prevent duplicate nicks.
- **Nick length.** `mlist2.txt` truncates nicks to 12 characters (`E:Stats.pm:402`), but yamn matches the full nick, so longer nicks silently get no stats. The Echolot summary regex also only accepts `[a-z0-9]+` (`E:Conf.pm:279`).
- **CRLF hazard.** The summary regex ends in `.*?$` with `/m` (`E:Conf.pm:278-284`). A CRLF reply leaves `\r` in the stored summary, and yamn then fails to parse the date ("Malformed valid-to date", `Y:keymgr/public.go:361-366`).
- **Token timestamps never expire.** `verify_address_tokens` checks only the MAC (`E:Tools.pm:118-145`), so a leaked reply address works forever.
- **Mail is parsed raw.** Mailin takes the first `To:` line literally: no unfolding, no MIME, case-sensitive `To:` (`E:Mailin.pm:72-80`). yamn's replies are plain text without MIME (`Y:quickmail/quickmail.go:44-87`), so this works in practice.
- **Middleman pings measure two hops.** A middleman remailer randhops a final-hop packet through a random exit from its own pubring and stats (`Y:server.go:540-544, 665-692`). It also needs stats to do so (`Y:chain.go:48-51`). So a middleman's ping figures include that random exit and depend on the middleman's own pinger feed.
- **Client staleness only warns.** yamn warns about stale stats but still uses them (`Y:chain.go:40-46`). A dead pinger is never noticed by the software.

---

## 3. Architecture and repository decision

### 3.1 Options

| | A: separate repo, yamn subprocess | B: separate repo, import yamn packages | C: `yamn --pinger` |
|---|---|---|---|
| Packet creation | `yamn -m --stdout -c 1 -l <addr>` with a one-key pubring | in-process `Encode()` | in-process `encodeMsg` |
| yamn changes needed | none (needs `--stdout`, PR #26 / c6d9a95) | large refactor (below) | ~3k lines added to `package main` |
| Coupling | CLI flags plus mbox output only | Go API and module path | full |
| Install | `go install github.com/go-while/go-echolot@latest` works | needs `replace github.com/crooks/yamn => github.com/go-while/yamn`. `go install …@latest` refuses modules with replace directives, so users must clone and build. | single binary |
| Risk to remailers | none | refactor touches packet code | pinger bugs ship in the remailer/client binary; more globals |
| Cost per ping | one process (~10/h for 20 remailers) | none | none |

### 3.2 What B would need from yamn

Today `encodeMsg` (`Y:client.go:263-365`) reads the globals `Pubring` and `cfg`. Armor lives in `utils.go` (`armor`, `wrap64`, `Y:utils.go:272-300`) and is tied to `version`. A library split would need:
- a `mix` (or `packet`) package that exports `Encode(plain []byte, hops []keymgr.Hop, opts) ([]byte, error)` and `Armor(io.Writer, []byte)`. That means moving `packet.go` (1,004 lines), `crypto.go`, parts of `utils.go` and `chain.go`, and removing the globals;
- `keymgr.Remailer` fields that are now unexported (`name`, `caps`, `version`, `from`, `until`), plus a constructor;
- the module-path problem solved: either upstream merges, or the fork renames its module.

That is a worthwhile *yamn* refactor (testability), but it shouldn't block the pinger.

### 3.3 Version skew

- Packet format: `packet.go` is wire-identical across:
  - crooks 2016–2025;
  - the 2021 sec3pinger module (error strings only);
  - the go-while fork. Its packet changes only touch multi-chunk IDs (Y-05) and bounds (Y-01, Y-16); a single-chunk exit packet is the same.

  So a pinger on the fork's yamn measures old remailers faithfully.
- Behaviour that does differ by remailer version:
  - Y-07 exit header allow-list (affects only the From-line test);
  - Y-08 `dest_block`/`max_size` (an operator could block the pinger);
  - Y-19 reply limiter (doesn't bite, §9.4).
- Multi-chunk mail is broken on pre-fork exits (Y-05), so **a ping must always fit in one chunk** (`maxFragLength = 17910`, `Y:yamn.go:21`). §6.3 caps it at 16 KiB.
- The pinger needs a yamn with `--stdout`. At startup go-echolot runs a self-test: it encodes to a throwaway key and checks for exactly one mbox entry with `-----BEGIN REMAILER MESSAGE-----`. A failure is fatal and the log names the minimum version.

### 3.4 Recommendation

**Option A**, as proposed. The code doesn't argue against it: version skew is a non-issue on the wire, and B has the `replace`/`go install` trap.
- Put packet creation behind an interface (§4, `pinger.Encoder`), so B can replace it later without touching anything else.
- Use the yamn binary also in integration tests, to check that our `pubring.mix`/`mlist2.txt` parse the way clients parse them.
- go-echolot does **not** import `github.com/crooks/yamn/keymgr`. The few things it needs are reimplemented (§6.4): keyid = BLAKE2s-128(pk), and the pubring parser rules (~150 lines). This keeps go.mod free of `replace`.

---

## 4. Components and package layout

```
cmd/go-echolot/          main.go: CLI dispatch (§10.4)
internal/config          INI-style config parser (stdlib only, §10.3), defaults, validation
internal/store           State (state.json), ping journal, flock, atomic writes
internal/store/echolotimport   import of an Echolot data dir (§5.5)
internal/token           reply-address tokens, HKDF key derivation, legacy MD5
internal/mailin          Maildir scan/claim/delete, header parsing, dispatch
internal/mailout         Mailer interface: sendmail pipe, SMTP; request composer
internal/replies         conf/key parsers, thesaurus (raw replies)
internal/keys            key validation, selection, pinning/quarantine policy
internal/pinger          ping body, sealing, Encoder (yamn subprocess), receive
internal/stats           Echolot calculate(), history/caps strings
internal/output          pubring.mix, type2.list, mlist2.txt, mlist.txt, .meta, HTML (phase 3)
internal/sched           slot hashing, job loop, debounced triggers
internal/minisign        minisign sign/verify (phase 4)
internal/health          health checks, status.json/txt, peer checks, notifications
internal/chain           chain pings and broken-chain detection (phase 3)
internal/civil           Date: a calendar date in UTC (yamn's "2006-01-02" key dates), our own small type
```

### 4.1 Key interfaces (sketch)

This was the plan before the code. Where they differ, the code is right: `mailin` is a `Scanner` struct with `Scan(ctx)`; `mailout.New(cfg.Mail, password, Options)` builds the routing, rate-limited mailer, and `ComposeRequest` takes the subject and body; `keys.Apply*Reply` take an extra `now`; `sched.Loop` has `Debounced` and `OnTick` besides `Every` and `Trigger`.

```go
// config
type Config struct { Pinger PingerCfg; Paths PathsCfg; Yamn YamnCfg; Mail MailCfg;
    Schedule ScheduleCfg; Stats StatsCfg; Keys KeysCfg; Discovery DiscoveryCfg;
    Signing SigningCfg; Health HealthCfg; Compat CompatCfg }
func Load(path string) (*Config, error)

// store
type Store struct{ /* in-memory State + journal handle */ }
func Open(dir string) (*Store, error)          // takes the flock, loads, replays journal
func (s *Store) Update(fn func(*State) error) error  // mutate + atomically persist state.json
func (s *Store) AppendPing(ev PingEvent) error // journal append + fsync
func (s *Store) Pings(addr string, since time.Time) (out []Ping, done []Ping)
func (s *Store) Compact(before time.Time) error
func (s *Store) Close() error

// token
type Kind string // "conf","key","help","adminkey","ping","chainping","bounce"
type Token struct { Kind Kind; ID int; Time time.Time }
type Minter struct{ /* keys, local part, delimiter, domain, hashLen */ }
func (m *Minter) Address(t Token) string
func (m *Minter) Verify(addr string, now time.Time) (Token, error)

// mailin
type Message struct { Path string; Delivered time.Time; Header mail.Header; Body []byte; Rcpt string }
type Handler interface { Handle(ctx context.Context, tok token.Token, m *Message) error }
func Scan(dir string, h Handler) (n int, err error)   // new/ only; deletes on success

// mailout
type Mail struct { EnvelopeFrom string; Rcpt []string; Data []byte }
type Mailer interface { Send(ctx context.Context, m Mail) error }
func NewSendmail(path string) Mailer
func NewSMTP(cfg SMTPCfg) Mailer
func ComposeRequest(from, to string, kind token.Kind, body string, now time.Time) []byte

// replies
type ConfReply struct { Type, Nick, Address, Caps string; Supported []SummaryLine }
func ParseConf(body []byte) (*ConfReply, error)
type SummaryLine struct { Nick, Address, KeyID, Version, Caps string; Created, Expires civil.Date }
type KeyBlock struct { KeyID string; PK [32]byte }
type KeyReply struct { Keys []ParsedKey; Errors []error }   // ParsedKey = SummaryLine + KeyBlock
func ParseKey(body []byte) *KeyReply
func IsNotARemailer(body []byte) bool

// keys
type Decision int // Accept, AcceptRotation, Quarantine, Reject
func Validate(pk ParsedKey, rem *store.Remailer, today civil.Date) error
func Classify(rem *store.Remailer, pk ParsedKey, now time.Time, cfg KeysCfg) Decision
func Publishable(rem *store.Remailer, now time.Time) *store.Key   // §8.4

// pinger
type Hop struct { Address, Nick, KeyID string; Summary string; PK [32]byte }
type Encoder interface {
    // Encode returns the single outgoing mail for the first hop of chain.
    Encode(ctx context.Context, chain []Hop, plaintext []byte) (to string, mail []byte, err error)
}
type YamnEncoder struct { Binary, TmpDir string; Timeout time.Duration; Sender string }
func Seal(k *[32]byte, plain []byte) []byte   // §6.3
func Open(k *[32]byte, body []byte) ([]byte, error)

// stats
type Result struct { Latency *float64; Reliability float64; LatencyDay [12]*float64; ReliabilityDay [12]*float64 }
func Calculate(out []time.Time, done []Done, now time.Time, p Params) Result   // §8.1

// output
func WritePubring(dir string, entries []PubEntry) (changed bool, err error)
func WriteMlist2(dir string, rows []Row, sections Sections, now time.Time) error

// sched
func Slot(key []byte, id string, session int64, n int) int
type Loop struct{ /* jobs */ }
func (l *Loop) Every(name string, d time.Duration, fn func(ctx context.Context, at time.Time))
func (l *Loop) Trigger(name string)   // debounced immediate run
```

### 4.2 Responsibilities

- **mailin:**
  - Scans `Maildir/new` once a minute (Echolot `processmail`, `E:Config.pm:105`).
  - Extracts the recipient in this order: `X-Original-To`, `Delivered-To`, `To`. The token verifies against any of them.
  - Takes the delivery time from the file mtime.
  - Dispatches by `Kind`.
  - Files that fail verification move to `mail-errors/` (kept 7 days, like `save_errormails`, `E:Mailin.pm:225-247`) and are counted as bounces when they carry a `bounce.` token.
- **request sender:** For each active remailer with `fetch`, at its hashed slot, composes and sends `remailer-key`/`conf`/`help`/`adminkey`. It decrements `ttl` per *conf* request (`E:Conf.pm:104`).
- **reply handling:** conf → `ParseConf` → pinning (§9.2) → `Conf` update and `ttl` restore (`E:Conf.pm:149-156`). key → `ParseKey` → `Validate` → `Classify` → store, `ttl` restore, trigger `buildkeys` on any new or changed publishable key. Every reply is saved raw to `thesaurus/<id>.<kind>` (`E:Thesaurus.pm:40-58`).
- **pinger:** For each remailer with `pingit`, for each *pingable* key (valid by date, seen within retention), at its slot: build the body (§6.3), append an `out` event, encode with yamn, send, and append `abort` on failure.
- **receiver:** Opens the body, verifies the MAC, matches an outstanding ping, and appends `done` with latency = delivered − sent.
- **stats engine:** Every 5 min, `Calculate` per address, then the `mlist2.txt`/`mlist.txt` writers. Write-if-changed is *not* applied here, because `Generated:` must advance.
- **key writer:** `pubring.mix`/`type2.list`, public and private, plus `.meta`. Written only when the content changes. Triggered by key events (debounced 5 min) and hourly.
- **scheduler:** One 5-minute tick for pings and requests (slot model, §8.3), plus independent periodic jobs. Missed slots after downtime are skipped, not caught up.
- **health:** §10.2.

---

## 5. Data model and storage

### 5.1 Records

```go
type State struct {
    Version     int                      // 1
    MaxID       int                      // like addresses_maxid (E:Storage/File.pm:1046-1069)
    Remailers   map[string]*Remailer     // by address
    Prospective map[string][]Suggestion  // by address
    Pending     []PendingChange          // quarantined changes awaiting approval
    Fromlines   map[string]map[int]Fromline // addr -> with_from -> info (phase 3)
}
type Remailer struct {
    ID              int       // stable; appears in tokens and thesaurus names
    Address         string
    Nick            string    // pinned nick ("" until first accepted conf)
    Status          string    // "active" | "ttl timeout" | "dead" | "disabled: not a remailer" | "disabled"
    TTL             int       // default 5; -1 per conf request; reset on valid conf/key reply
    ResurrectionTTL int       // default 8; weekly checks while in "ttl timeout"
    Fetch, PingIt, ShowIt bool
    Added           time.Time
    Conf            *Conf
    Keys            map[string]*Key  // by keyid
}
type Conf struct {
    Nick, Type, Caps string    // Caps = whole $remailer{...} line
    LastUpdate  time.Time      // token time of the request (Echolot semantics)
    Received    time.Time
    DontExpire  bool           // set manually (E:Conf.pm:231-257)
}
type Key struct {
    KeyID, Nick, Address, Version, Caps string
    Created, Expires  civil.Date
    PK                [32]byte
    FirstSeen, LastSeen time.Time   // token time of first/last reply listing it
    LastReceived      time.Time
    Sightings         int
    ProvenAt          time.Time     // when the first ping encrypted to this key came back; zero = not yet (§9.2)
    State             string        // "active" | "quarantined" | "rejected"
}
type Ping struct {        // journal events: out / done / abort
    ID       uint64
    Addr     string
    KeyID    string
    WithFrom bool
    Sent     time.Time    // unix seconds
    Latency  int64        // seconds; done only
}
type ChainPing struct { ID uint64; A, KeyA, B, KeyB string; Sent time.Time; Latency int64 } // phase 3
type Suggestion struct { Time time.Time; Reason, Source string }
```

The secret lives in its own file, `secret`: 32 random bytes as hex, mode 0600.

Retention:

| What | When it goes | Echolot comparison |
|---|---|---|
| Keys | removed when `LastSeen` is older than `keys.retention` (5 d, as `expire_keys`) **and** they are expired, or 30 d after `LastSeen` whatever the date | Echolot: 5 d after last seen, regardless of date |
| Confs | expire after 5 d unless `DontExpire` | same as `E:Storage/File.pm:1589-1594` |
| Pings | expire after 12 d by `Sent` | **not** deleted with their key (see §2.1-5, §8.5) |
| Thesaurus | 21 d | |
| Mail errors | 7 d | |

### 5.2 Storage choice

Data volume: ~20 remailers × 12 pings/day × 12 days ≈ 3,000 ping records, plus a few kB of state.

| | Plain files (JSON + JSONL) | LevelDB (goleveldb) | bbolt |
|---|---|---|---|
| Inspect/repair | `cat`, `jq`, editor | needs a tool | needs a tool |
| Atomicity | rename for the state; append + fsync for the journal | batch writes; no multi-key transactions | full ACID transactions |
| Dependency | stdlib | goleveldb (v1.0.0, 2019; reused by yamn, but a separate repo gains nothing) | go.etcd.io/bbolt |
| Fit for <1 MB of data | ideal: load everything into memory | overkill, many files | fine, but opaque |
| Echolot import | direct mapping | mapping plus encoding | mapping plus encoding |

**Recommendation: plain files.** Everything stays in memory, so the files only have to be durable and readable. Layout:

```
state_dir/
  lock             flock(LOCK_EX|LOCK_NB) for the daemon's lifetime; holds "pid\n"
  secret           32 bytes hex, 0600
  state.json       State, written via tmp + fsync + rename + fsync(dir)
  pings.jsonl      {"ev":"out","id":7,"addr":"…","key":"…","wf":0,"sent":1792560000}
                   {"ev":"done","id":7,"lat":1234,"rcv":1792561234}
                   {"ev":"abort","id":7,"err":"smtp: …"}
                   {"ev":"next","id":8}   first line after compaction: IDs aren't reused
  chainpings.jsonl (phase 3)
  commands/        CLI spool (§10.4)
  thesaurus/       <id>.conf|key|help|adminkey (+ .meta.json with received time)
  mail-errors/
  pinger.key       minisign secret key (phase 4), 0600
```

### 5.3 Crash safety

- `state.json` is always replaced atomically. The order is temp file, `fsync`, `rename`, then `fsync` of the directory, the same helper as yamn's `writeFileAtomic` (`Y:utils.go:169-190`) plus the fsyncs.
- Journal lines are appended with `O_APPEND` and one `fsync` per event. At ~100 pings an hour that costs nothing, and a mail can be deleted as soon as its `done` returns.
  - On load, an incomplete last line (no `\n`) is truncated away. Other bad lines are logged and skipped.
  - A write that fails part way is truncated back. If that fails too, the journal takes no more writes until restart.
  - Unknown IDs in `done` are ignored.
- If the directory `fsync` fails *after* a rename, the new file is already in place: the store keeps it (in memory too) and logs an error, instead of rolling back to data that's no longer on disk.
- Compaction (daily, with expiry) writes a new journal of live records via tmp + rename.
- Mail: process → persist → *then* unlink the Maildir file. A crash reprocesses mail, and every handler is idempotent:
  - a duplicate `done` is ignored, as in `E:Storage/File.pm:582-587`;
  - key/conf replies with a non-newer token time are ignored (`E:Storage/File.pm:1289-1292, 1355-1358`).
- Pings: `out` is appended **before** encoding/sending, and `abort` after a local failure. A crash in between counts as one lost ping, which is rare. Echolot counts *every* local failure as a loss (§2.1-8).

### 5.4 Locking

- The daemon holds an exclusive non-blocking `flock` on `state_dir/lock`. A second instance fails with "already running (pid N)".
- CLI commands:
  - **read-only** commands (`status`, `keys`, `summary`, `check`) read `state.json` without the lock. Atomic renames guarantee a consistent snapshot.
  - **mutating** commands try the lock. If the daemon isn't running they apply the change directly. Otherwise they drop a command file into `commands/` (written to a tmp name, then renamed) and send SIGHUP to the PID in `lock`. The daemon also polls `commands/` every 10 s. This keeps Echolot's `commands.txt` + HUP model (`E:Commands.pm:43-127`) without its single shared file.

### 5.5 Importing an Echolot data directory

Feasible.

**Format** (`E:Storage/File.pm`):
- `data/metadata` is `# vim:set syntax=perl:\n` followed by `Data::Dumper->Dump([$METADATA],['METADATA'])`, i.e. Perl source `$METADATA = {...};` (264-281). It is read back with `eval` (214-248).
- Its layout:
  - `version` (=1), `secret` (32 hex = 16 bytes, 250-251), `addresses_maxid`;
  - `addresses{addr}{id,status,ttl,fetch,showit,pingit,resurrection_ttl}`;
  - `remailers{addr}{conf{nick,type,capabilities,last_update,dont_expire}, keys{mix}{keyid}{key,summary,nick,last_update,stats}}`;
  - `prospective_addresses{addr}["time; reason; additional", …]`;
  - `fromlines{addr}{type}{0|1}{last_update,from,disclaim_top,disclaim_bot}`.
- Ping files: `data/<stats>.out` (one unix time per line) and `data/<stats>.done` (`sent latency` per line), where `<stats>` is the per-key basename (357-362, 548-618).
- Chain pings: `data/chainpings.mix.out` (`sent a1 t1 k1 a2 t2 k2`) and `.done` (… `lat`) (632-878).
- Thesaurus: `results/thesaurus/<id>.<type>`.

**Conversion.** Don't parse Perl in Go. Echolot hosts have perl, and JSON::PP has been core since 5.14:

```sh
perl -MJSON::PP -e 'my $f=shift; my $c=do{local(@ARGV,$/)=($f);<>}; my $METADATA; eval $c; die $@ if $@;
  print JSON::PP->new->canonical->encode($METADATA)' ~/echolot/data/metadata > metadata.json
go-echolot import-echolot --metadata metadata.json --datadir ~/echolot/data \
  --thesaurus ~/echolot/results/thesaurus --state-dir /var/lib/go-echolot
```

(This export was tested with a Dumper file made the same way, [`testdata/echolot-import/fake-metadata`](../testdata/echolot-import/fake-metadata). The `eval` runs the operator's own file, which Echolot itself evaluates on every start.)

**Import rules:**
- Keep IDs and `addresses_maxid`, so in-flight `conf.<id>` tokens still resolve.
- Import `secret` into `state_dir/legacy_secret`, with its end: import time + 48 h. Until then, accept Echolot MD5 tokens: `md5_hex("<type>.<id>=<time>"+secret)[:8]` (`E:Tools.pm:94-145`). This applies to request replies only. `compat.legacy_md5_tokens_until`, if set, overrides the end.
- Keys: parse `summary` and `key` with the yamn rules. Drop and report keys that fail keyid = BLAKE2s(pk). This check comes before a key gets any ping history or proof: stock Echolot doesn't check it, so a forged reply with the same keyid but another key replaces the stored key while the pings (encrypted to the old key, `E:Pinger/Mix.pm:46`) stay with the keyid. The nick from the conf becomes the pinned nick if it matches the key nick, and is quarantined otherwise.
- Pings (all counted in the stats: Echolot published their keys):
  - import all `done` records; the first one of each key also proves that key (§9.2), since Echolot's ping was encrypted to it, so the imported keyring isn't empty until new pings return;
  - import `out` records older than 24 h, as genuine losses;
  - drop `out` records younger than 24 h. Their replies are GPG-encrypted and can't be verified, and dropping them avoids counting them as losses. The effect is ≤ 1 day of slightly fewer samples. A `gpg --decrypt` subprocess window for legacy pings is possible but not worth the code.
- Chain pings: `chainpings.mix.out`/`.done`, with the rules for pings; only chains whose two keys were imported.
- Status, flags and ttl: copy. Prospective addresses become `Suggestions`.
- **Not imported:** `fromlines` (they expire after 5 d anyway), GnuPG state.

SEC3's patched Conf.pm may store slightly different `key` text. The importer only relies on `summary` + `key` containing the yamn block, and reports anything else.

---

## 6. Wire formats

### 6.1 Reply-address tokens

Shape (unchanged from Echolot, `E:Tools.pm:94-116`):

```
<localpart><delim><kind>[.<id>]=<unixtime>=<mac>@<domain>
e.g. pinger+key.12=1792560000=3f9a0c51d2e47b08@pinger.example.org
     pinger+ping=1792560000=…@…      pinger+bounce.12=…=…@…
```

- `mac = hex(HMAC-SHA256(K_tok, "<kind>[.<id>]=<unixtime>"))[:hash_len]`. `hash_len` defaults to 16; Echolot used 8 MD5 digits (`E:Config.pm:88`).
- Length is fine: `pinger+adminkey.123=1792560000=` plus 16 digits is 47 characters, under the 64-character local-part limit.
- Keys: `K_x = HKDF-SHA256(secret, salt="go-echolot", info="v1 "+x)` for x ∈ {`token`, `ping-mac`, `ping-box`, `sched`}.
- Verification (case-insensitive local part; constant-time compare):
  - reject timestamps more than 1 h in the future;
  - reject request and bounce tokens older than 7 d, and ping and chain-ping tokens older than 12 d.

  Echolot doesn't check age at all (§2.2).
- The parser also accepts the `local@domain(token)` form used when the delimiter is empty (`E:Tools.pm:108-113, 124-131`).

### 6.2 Request mail

```
From: pinger+key.12=1792560000=3f9a0c51d2e47b08@pinger.example.org
To: yamn@mixmin.net
Subject: remailer-key
Date: Wed, 21 Oct 2026 04:40:00 +0000
Message-ID: <20261021044000.4f1c2a9e@pinger.example.org>

Hello,

This message requests remailer configuration data. ...      (remailerxxxtext, E:Config.pm:224-236)
```

- **Envelope sender:** `pinger+bounce.<id>=<t>=<mac>@domain` (VERP), so bounces can be attributed to the remailer.
  - Echolot used the bare address (`E:Tools.pm:155-158, 168`).
  - yamn replies to the *header* `From:` (`Y:server.go:695-703`), so the VERP sender doesn't change the reply.
- **Kinds and cadence:** `key` every 2 h, `conf` every 24 h, `help` every 7 d, `adminkey` every 7 d, `stats` never (§2.1-9).
- **Resurrection checks** (`ttl timeout` state): conf + key weekly, as in `E:Conf.pm:110-126`.

### 6.3 Ping

Plaintext body:

```
remailer: yamn@mixmin.net
type: mix
key: 47c15db37d0d840b1f5ad4274384be22
with_from: 0
sent: 1792560000
id: 4711
mac: <64 hex = HMAC-SHA256(K_ping-mac, "v1:"+remailer+":"+type+":"+key+":"+with_from+":"+sent+":"+id)>
-----BEGIN GARBAGE-----
<random 0..4095 bytes as hex, 64 chars per line>        (E:Tools.pm:415-442)
-----END GARBAGE-----
```

Sealed form, which becomes the body of the mail fed to yamn:

```
-----BEGIN ECHOLOT PING-----
Version: go-echolot-1
                                    (blank line)
<base64(nonce[24] || secretbox.Seal(K_ping-box, nonce, plaintext)), 64 columns>
-----END ECHOLOT PING-----
```

- The receiver strips whitespace and blank lines inside the armor (the "broken middleman" workaround, `E:Pinger.pm:162-166`), opens the box, then checks the MAC.
- The MAC is redundant with the authenticated box, but cheap. It keeps a `--plain-pings` debug mode possible.
- The `id` lets `done` match without relying on the `sent` value being unique.

Mail given to `yamn` on stdin (with `with_from` alternating per 2-hour session, `E:Pinger.pm:142`):

```
[From: pinger@pinger.example.org]          only when with_from = 1
To: pinger+ping=1792560000=<mac16>@pinger.example.org

<sealed body>
```

- yamn's client reduces `From` to the bare address and drops everything outside its allow-list (`Y:client.go:73-101`). Nothing above is affected.
- **Size:** the plaintext is ≤ 8.5 KiB and the sealed body ≤ 12 KiB. Anything over 16 KiB is refused, so the ping is always a single chunk (§3.3).

Encoder call, per ping, in a fresh temp dir `D` (mode 0700):

```
D/pubring.mix   one entry (canonical, §7.1) per hop
D/yamn.yml:
  general: {loglevel: warn}
  files:   {pubring: D/pubring.mix, mlist2: D/mlist2.txt, pooldir: D/pool, secring: D/secring.mix,
            idlog: D/idlog, chunkdb: D/chunkdb}
  urls:    {fetch: false, key_pinning: off}
  remailer: {address: pinger@pinger.example.org}
  stats:   {num_copies: 1, use_expired: false}
yamn --config D/yamn.yml --dir D -m --stdout -c 1 --nodummy -l <addr1>[,<addr2>]
```

Notes from yamn master (as of yamn #70/#71, 2026-10-22):
- **`key_pinning: off`.** yamn pins keys by default since #70 (`urls.key_pinning: hold`): it holds a remailer's early or changed key and refuses to encrypt to it. Then pings to a quarantined key would never go out and proof of possession (§9.2) could never succeed. go-echolot's own key policy replaces pinning here.
- **One key per ping run.** yamn keeps one key per address, the last one in `pubring.mix`. To ping a specific key (both keys during a rotation, or a quarantined one), `D/pubring.mix` holds just that key (plus the exit's for a chain), never the published keyring.
- **Keys yamn won't use:** expired keys unless `stats.use_expired`; keys whose created date is in the future, always.
- **No downloads:** `urls.fetch: false` (Y-49); with `urls.pingers` unset yamn reads only `files.pubring`.
- **Random hops need stats:** `-l middle,*` fails ("cannot use random remailers without stats") unless `files.mlist2` holds stats; see question 14 for middleman pings.
- **Headers:** the client keeps only what an exit passes on; `From`, `Reply-To`, `Date` and `Message-ID` are removed (Y-20, Y-47). The token goes in the `To` address and the data in the body.
- **Exit status:** `yamn -m` exits 1 on errors such as an unknown or held remailer or a bad chain (Y-46). That is a local failure (`abort`, §5.3), not a lost ping.
- **Own directory and config** (`--dir`, `--config`), so a remailer on the same host is unaffected (question 15).

- Pass addresses in `-l`, not nicks. `Pubring.Get` resolves anything containing `@` by address (`Y:keymgr/public.go:139-165`), which avoids any nick ambiguity.
- The output is an mboxrd stream (`Y:mbox.go:38-57`). Expect exactly one entry whose `To:` is hop 1.
- yamn writes `To:`, `From: <remailer.address>` and `Subject: yamn-<ver>` (`Y:utils.go:265-270`). go-echolot adds `Date:` and `Message-ID:` when it sends over SMTP; sendmail adds them itself.
- 30 s timeout. Stderr is logged.

### 6.4 Parsing yamn's replies

What yamn sends:
- the key reply: `"Here is the Mixmaster key:\n\n=-=-=…"` followed by `key.txt` (`Y:server.go:712-717`, sample [`testdata/replies/t_65.key`](../testdata/replies/t_65.key), mixmin's stored reply);
- the conf reply: `Y:server.go:718-751`, sample `t_65.conf`.

Both are plain text with no MIME (`Y:quickmail/quickmail.go:44-87`). Before parsing:
- normalize CRLF to LF;
- decode a `Content-Transfer-Encoding: quoted-printable/base64` body if present (defensive);
- undo PGP dash-escaping: a leading `- ` is removed from every line (RFC 4880; Echolot only handled `^- -`, `E:Conf.pm:457`).

**Summary line** (exactly what yamn clients accept, `Y:keymgr/public.go:343-394`):

```
^([a-z0-9]{1,12}) (\S+@\S+) ([0-9a-f]{32}) (\S+) (\S+) (\d{4}-\d{2}-\d{2}) (\d{4}-\d{2}-\d{2})$
```

- Exactly 7 fields from splitting on single spaces, as yamn's `readPubring`: a line with a double space is not a summary line. (Changed 2026-10-22 from "runs of whitespace accepted": accept exactly what yamn clients accept, never more.) No field may be empty; version and caps are printable ASCII.
- The name is `[a-z0-9]+` of any length on read, as yamn's `ValidName`; upper case is rejected, not lower-cased. The address must pass yamn's `ValidAddress` (≤ 52 bytes, printable, none of `"(),:;<>[\]`).
- The caps field holds `E`/`M` (`Y:keymgr/secret.go:177-183`).
- The 12-character nick limit is ours: longer nicks are *quarantined* by the key policy, never published automatically. It guarantees `mlist2.txt` rows match (§2.2).
- Length limits (added 2026-10-22): nick ≤ 32 bytes, version and caps ≤ 32 bytes each; in a conf reply, options ≤ 128 and Remailer-Type ≤ 64. yamn reads `pubring.mix` and `mlist2.txt` with `bufio.Scanner`, whose line limit is 64 KiB: a single longer line makes `readPubring` fail and the client drops the *whole* keyring. Live values are a few bytes ("4:0.2.6", "E", "middle v2").
- The line is *re-serialized* canonically for output. Echolot copied it verbatim.

**Key block:**

```
-----Begin Mix Key-----
<keyid: 32 hex>
<pk: 64 hex>
-----End Mix Key-----
```

A key is accepted only if all of these hold:
- the block keyid equals the summary keyid;
- BLAKE2s-128(pk) equals the keyid (`Y:keymgr/public.go:430-440, 461-469`);
- `created ≤ today(UTC)` and `expires ≥ today` (Echolot's rules, `E:Conf.pm:339-346`), plus `expires > created` and `expires − created ≤ 400 d`;
- the summary address equals the remailer's address. The domain is compared case-insensitively; Echolot compared exactly (`E:Conf.pm:348`).

The reply may contain 0..n summary lines and blocks; they are paired in order by yamn's state machine (summary line, Begin, keyid, key, End). Where yamn would pair a line with the wrong block, both keys are dropped and logged. Lines naming *other* addresses become Suggestions only (§9.3), never additions.

**Conf reply:**
- `Remailer-Type: (.*)` (`E:Conf.pm:138`);
- caps line `^\s*(\$remailer\{"([a-z0-9]{1,12})"\}\s*=\s*"<(\S+@\S+)>([^"]*)";)\s*$` (cf. `E:Conf.pm:140-142`);
- the `SUPPORTED MIXMASTER (TYPE II) REMAILERS` list: summary lines until the first non-matching line (`E:Conf.pm:177-206`).

Caps that matter: `middle`, and `v2`. Everything else goes into the options string as in §7.3.

**"not a remailer":** `^\s*not\s+a\s+remailer\b` at the very start of the body (`E:Conf.pm:47-54`). go-echolot sets `PingIt=Fetch=false` and status `disabled: not a remailer`, and alerts the operator. Echolot did this silently (`E:Storage/File.pm:1233-1250`).

---

## 7. Output files (byte-exact)

Every writer refuses to write a line longer than 1 KiB (`pubring.mix`, `type2.list`, `mlist2.txt`, `mlist.txt`): yamn clients read these files with `bufio.Scanner` (64 KiB per line), and one overlong line loses the whole file for every client. The input limits of §6.4 keep real lines far below that; the writer check is the second line of defence.

Echolot doesn't write atomically (`E:Stats.pm:302-310`). We write every file via tmp + rename. The public directory gets only `list-it` remailers; the private directory gets all of them (`E:Stats.pm:683-687, 829-839`). Here, `list-it` means `ShowIt && Conf != nil && Caps !~ /\btesting\b/i` (`E:Stats.pm:491, 822`).

### 7.1 pubring.mix and type2.list

- Per address: the publishable key (§8.4). The address needs a conf with a nick (`E:Stats.pm:823`) and conf nick == key nick (our pinning rule).
- Entries are sorted by canonical summary line, as a byte-wise string compare (`E:Stats.pm:829`).

```
<summary>\n
\n
-----Begin Mix Key-----\n
<keyid>\n
<pk hex>\n
-----End Mix Key-----\n
\n
```

- `type2.list` holds the summary lines alone, one per line, in the same order (`E:Stats.pm:834, 838`).
- This matches all three live pubrings byte for byte. The file ends in `-----\n\n` (checked on `pingers/mixmin.mix`).
- An empty keyring is written as an empty file. yamn's `CheckPubring` then rejects the download (`Y:keymgr/check.go:15-30`) and keeps its previous copy, which is the desired behaviour.

### 7.2 .meta files

`<file>.meta` contains `Expires: <Day>, <DD> <Mon> <YYYY> <HH:MM:SS> +0000\n` (`E:Tools.pm:195-225`). The expiry is now + `buildkeys` (8 h) for keyrings and now + `buildstats` (5 min) for lists (`E:Stats.pm:311-315, 846-851`).
- They exist only for Apache `mod_cern_meta`. No yamn code reads them (`Y:utils.go:142-167`).
- Default on (`compat.meta_files: true`), so existing web configs keep working. The keyring expiry becomes now + 1 h to match our cadence.

### 7.3 mlist2.txt

Exactly as `E:Stats.pm:390-423`:

```
Stats-Version: 2.0\n
Generated: %s\n                       strftime "%a %d %b %Y %H:%M:%S GMT" (UTC) (E:Stats.pm:48-58)
Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options\n
------------------------------------------------------------------------\n      (72 '-')
per remailer: "%-12s %-12s %6s   %-12s  %5.1f%%  %s\n"
    nick[:12], latency history, min_hr(latency), uptime history, reliability*100, options(15 chars)
[ "\nGroups of remailers sharing a machine or operator:\n" + sameop + "\n" ]   if sameop.txt exists
[ "\nBroken type-I remailer chains:\n"  + broken1 + "\n" ]                         if defined
[ "\nBroken type-II remailer chains:\n" + broken2 + "\n" ]                         if defined
"\n\n\nRemailer-Capabilities:\n\n"
caps lines sorted byte-wise, each + "\n"
```

- **Broken sections.** "Defined" follows Echolot (`E:Stats.pm:668-679`):
  - with chain pings on, both sections are always printed, even when empty (mixmin, Frell);
  - with chain pings off they are printed only if `broken1.txt`/`broken2.txt` exist (Victor prints none).

  Phases 1–2 behave like Victor. From phase 3, like mixmin.
- **`min_hr(sec)`, without seconds** (`E:Stats.pm:60-83`):
  - undefined, negative, or h > 99 → `99:59`;
  - h = int(sec/3600), m = int(sec/60) mod 60;
  - h > 0 → `"%2d:%02d"`, else `"  :%02d"`.

  Medians can be x.5 values; integer truncation reproduces Perl's `%`.
- **Latency history:** 12 characters, oldest on the left (`E:Stats.pm:104-133`), per-day median d:
  - `0` <20 m, `1` <1 h, `2` <2 h, … `9` <9 h;
  - `A` <12 h, `B` <18 h, `C` <24 h, `D` <30 h, `E` <36 h, `F` <42 h, `G` <48 h;
  - `H` otherwise; `?` no data.
- **Uptime history:** per day, `?` if nothing was sent that day; `+` if ≥ 0.9999; else `int(rel*10)` (`E:Stats.pm:135-149`).
- **Options:** 15 characters (`E:Stats.pm:151-203`), from the conf caps line (case-insensitive `\b` word matches):

  `D` middle · `P` post|anon-post-to · `2`/`R`/`M` remix2/remix/mix · `H` hybrid · `2`/`G` repgp2/repgp · `O` pgponly · `X` ext · `A` max · `T` test · `L` latent · `E`/`e` ekx/ek · `U` esub · `I` inflt\d+ · `N` rhop\d+ · klen digit.

  For yamn, the result is `"D" + 14 spaces` for middlemen and 15 spaces for exits (live files agree).
- **Rounding:** Go's `%5.1f` and Perl's (glibc) agree, including exact ties (tested 2026-10-21 on perl 5.40 and Go 1.27).
- **Row order:** reliability descending (exact float), then latency if `sort_by_latency`, then nick byte-wise (`E:Stats.pm:498-504`).
- **What yamn reads:** `Generated:`, the dashes, then per row the fields before `%`, split on whitespace (exactly 5 fields: nick, history, `h:mm`/`:mm`, history, uptime), stopping at the first empty line (`Y:keymgr/public.go:167-294`). The format above guarantees 5 fields, because neither history string can contain a space.

### 7.4 mlist.txt

Format as `E:Stats.pm:330-354`: sections first, then `Last update:`, a header, and rows `"%-14s %-12s %8s %6.2f%%\n"` with the type-I history alphabet (`#*+-._`, space = no data) and `min_hr(...,1)`. Nobody in yamn reads it. It's 40 lines and kept for parity with Frell and mixmin.

### 7.5 Not produced

- PGP keyrings, rlists, clist (type I);
- private `results.private` variants of HTML;
- `echolot.css` (phase 3 ships its own).

---

## 8. Algorithms

### 8.1 Stats: Echolot's `calculate()` (`E:Stats.pm:231-300`), exactly

Inputs per address: all `out` timestamps and `done` (sent, lat) pairs of **all keys** of the address, with `sent > now − 12·86400`.

```
W = [0.5 1.0 1.0 1.0 1.0 0.9 0.8 0.5 0.3 0.2 0.2 0.1]    (E:Config.pm:200)
day(t) = int((now − t) / 86400)                          (int truncates toward 0)
for each done (s, l):  d = day(s); latDay[d] += l; sentW += W[d]; recvW += W[d]; sentDay[d]++; recvDay[d]++
L = sort(all l);  latency = median(L)          median: even n → mean of the two middle elements
latencyDay[d] = median(sort(latDay[d]))
for each out s:    p = |L| == 0 ? 0 : |{ l ∈ L : l > x }| / |L|,  x = (now − s − 900) / 0.8
                   d = day(s); sentW += W[d]; recvW += W[d]·p; sentDay[d]++; recvDay[d] += p
reliability = sentW > 0 ? recvW / sentW : 0
relDay[d]   = sentDay[d] > 0 ? recvDay[d] / sentDay[d] : undefined
```

- `percentile` uses a strict `>`, via its "first index with lat < L[i]" loop (`E:Stats.pm:220-229`).
- A ping sent "in the future" (clock skew of more than a day) would index `W[-1]` in Perl. We clamp `d` to `[0, 11]` and log it.
- Summation order: Echolot sums done pings, then out pings, in hash order. Floating-point sums can differ in the last bit. That can only flip a `%5.1f` exactly at a rounding boundary. The golden tests compare numbers with tolerance 1e-9 and formatted text exactly, and avoid boundary cases.

### 8.2 Chain pings (phase 3; `E:Chain.pm:126-207`, `E:Stats.pm:509-645`)

**Scheduling:**
- Every pair (A, B), A ≠ B, of pingable remailers is pinged with each remailer's newest key, once a week (`2016 × 5 min`).
- "Intensive care" pairs are pinged daily (`288 × 5 min`). These are pairs with fewer than 3 pings and none returned, or pairs currently judged broken.

**Evaluation**, refreshed at most every 4 h (`chainping_update`):
- Window: sent within 10 d.
- Each `done` counts. Each `out` counts unless it is unreturned *and* younger than 1.5 × (lat A + lat B).
- `(A B)` is **broken** if `out ≥ 3` (or any returned) and `done/out ≤ 0.3 × rel(A) × rel(B)`.

**Compression** (`E:Stats.pm:509-555`):
- count per left/right nick, with `*` entries adding `n`;
- threshold = n × 0.5;
- emit `(A *)` / `(* B)` and drop the covered pairs; sort, dedupe;
- operator `broken2.txt` lines are merged with the computed chains and go through the same compression and sort (`E:Stats.pm:619-631`; corrected 2026-10-22, it said "prepended").

**Public vs private:** public includes only pairs where both remailers are `list-it` (`E:Stats.pm:624-625`).

### 8.3 Scheduling slots

Echolot (`E:Pinger.pm:117-140`, `E:Conf.pm:61-85`, `E:Tools.pm:79-86`):
- tick T = 300 s, N slots per period;
- `this = (t/T) mod N`, `session = t / (T·N)`;
- an item fires when `md5hex(id ‖ session ‖ secret)[:4] mod N == this`.

Ours keeps the structure:

```
slot(id, period) = uint64(HMAC-SHA256(K_sched, id + "|" + session)[:8]) mod N,
N = period / 5 min, session = floor(t / period)
```

| Item | id | Period |
|---|---|---|
| ping | addr+"|mix|"+keyid | 2 h (N=24) |
| key request | addr+"|key" | 2 h |
| conf request | addr+"|conf" | 24 h (N=288) |
| help / adminkey | addr+"|help" / "|adminkey" | 7 d |
| chain ping | A+"|"+B | 7 d; intensive care 24 h |

- `with_from = session(ping) mod 2`, as Echolot.
- Missed ticks are skipped (Echolot's `missok=0` semantics would fire one late run, `E:Scheduler.pm:111-123`).
- Manual `sendpings`/`getkeyconf` bypass slots (`E:Commands.pm:84-88`).
- **Rate guard:** at most `mail.max_per_hour` outgoing mails (default 200), as an abuse fuse.

### 8.4 Key selection and the deliberate improvements

**Valid(k, now)**, the same rule yamn clients use (`Y:keymgr/public.go:349-379`):
- `now ≥ lastMidnightUTC(k.Created)`, and
- `now < nextMidnightUTC(k.Expires)`, and
- `k.State == active`.

**Proven(k):** `k.ProvenAt` is set, i.e. a ping encrypted to k came back (§9.2). Required for publishing unless `keys.require_proof: false`. Pinging only needs Valid.

**Publishable(rem):** among *valid* and *proven* keys whose nick and address match the remailer's pins (so a key yamn's self-check would flag, §9.7, is never published; an unpinned remailer publishes nothing), order by:
1. `LastSeen` (token time) descending, i.e. the key the remailer advertised most recently;
2. then `Created` descending;
3. then `Expires` descending;
4. then keyid ascending.

Take the first.
- This equals Echolot's choice (newest `last_update`, `E:Stats.pm:813-819`) whenever there is no tie, and is deterministic when there is one.
- *LastSeen* goes first, not *Created*. If an operator restores an older secring, we follow what the remailer actually advertises.

**Pingable(rem):** all valid keys with `LastSeen ≥ now − keys.retention`. During yamn's ~48 h rotation overlap (§9.2) both keys are pinged, as Echolot does.

How each improvement changes the output compared with Echolot:

| Change | Echolot | go-echolot | Effect on output |
|---|---|---|---|
| Key request cadence | 24 h (`E:Config.pm:112-113`) | 2 h | A new key reaches `pubring.mix` ≤ 2 h + mail RTT + 5 min after the remailer advertises it, instead of up to ~32 h. |
| Pubring rebuild | every 8 h (`E:Config.pm:107`) | on change (debounced 5 min), checked hourly | Same as above; `Last-Modified` changes only when content changes. |
| Expired keys | published up to 5 d after the last reply | never published | A dead remailer disappears from `pubring.mix` at its expiry date instead of later. Clients behave the same, since they drop expired keys themselves; other tools and humans see accurate files. |
| Pings to expired keys | continue until the key leaves the store | stop at expiry | Slightly fewer samples during a remailer's death; no change for live remailers. |
| Ping history vs key expiry | deleted with the key (`E:Storage/File.pm:1575-1578`) | kept 12 d per address | Full 12-character histories (no `?????` after rotations); reliability and latency use up to 12 d of data instead of ~7. Numbers therefore differ from mixmin/Victor, but are what Echolot *intends*. `compat.drop_pings_with_key: true` restores Echolot behaviour for side-by-side comparison. |
| Local send failure | counted as a lost ping | not counted (`abort`) | Reliability no longer drops because of the pinger's own outages. |
| Latency source | processing time (mail is processed every 60 s; downtime inflates latency) | Maildir delivery time | Latency lower by ≤ 1 min normally; correct after pinger downtime. `compat.latency_from: processing` restores Echolot behaviour. |
| Multiple keys in one reply | hash order on ties | deterministic order (above) | Stable output; irrelevant for yamn (one key per reply). |
| Duplicate nicks / >12 characters | allowed | refused / quarantined | Prevents broken stats matching (§2.2). |

### 8.5 Expiry and states (daily job)

**States** (`E:Storage/File.pm:1152-1222`):
- `active` → `ttl timeout` when `TTL ≤ 0` (5 conf requests without any valid conf/key reply, about 5 d);
- `ttl timeout` → `dead` after 8 weekly resurrection checks fail;
- any valid reply → `active`.

Unlike Echolot, `pingit` pings are also suspended in `dead` (configurable). In `ttl timeout` pinging continues, because the stats should show the outage.

**Expiry:** as the table in §5.1.

**Prospective/Suggestions:** dropped after 5 d (`E:Storage/File.pm:915-928`).

---

## 9. Security and trust (Y-03)

### 9.1 Validating key replies

The checks in §6.4, plus:
- the reply must come back on a token minted for *that remailer's ID* and kind `key`;
- the token's age must be ≤ 7 d;
- the token time must be newer than the stored `LastSeen` for this keyid (no replays of old replies).

Rejections are logged with a reason and kept in the thesaurus.

### 9.2 Pinning and quarantine

**Bindings:**
- address ↔ nick is pinned at the first accepted conf (TOFU) or by the operator (`add <addr> --nick yamn`);
- nick uniqueness is enforced across all remailers.

**Normal rotation** (accepted at once). yamn generates a new key when no key is "active", i.e. once the current key is within `expiringDays = 48` h of its expiry, rounded to midnight (`Y:keymgr/secret.go:366-409`; `Y:server.go:64-79, 112-120`). In non-daemon `-M` runs, the generation happens at the next start. So a new keyid K' for address A is accepted automatically if:
- A's current publishable key K expires within 72 h, or K is already expired, or A has no valid key; and
- K'.nick == pinned nick, and K'.Created ≥ K.Created.

**Unexpected change.** A new valid keyid while K still has more than 72 h left, or a nick or address change, creates a `PendingChange` and sets the key `State = quarantined`:
- the old key stays published;
- the operator is notified (log, `status.json`, optional mail);
- the change is applied after `keys.quarantine` (24 h) **if** the new key was seen in ≥ 2 independent replies (distinct tokens ≥ 30 min apart) *and* the old key wasn't seen again in that period;
- `approve`/`reject` override this.

A remailer that really lost its secring therefore becomes usable again after ≤ 24 h, or immediately with approval. A one-off forged or injected reply never reaches clients.

**Proof of possession (added 2026-10-22).** Pinning and quarantine only slow a forger down: one who keeps sending forged `remailer-key` replies for 24 h still wins. So a key is published only once the remailer has shown it holds the secret key:
- Every Valid key is pinged as usual (§8.4 Pingable), including new and quarantined ones. Pings to a key that isn't published yet are sent but not counted in the stats.
- When a ping encrypted to key k comes back (token and secretbox check pass, §6.3), set `k.ProvenAt` once. Only proven keys are Publishable.
- Why it works: the ping goes to the address in the key, encrypted to that key. Only someone with the secret key can decrypt it, and the return path is the secretbox-sealed body with an HMAC token, which can't be faked without decrypting. A forger who can send mail but can't read the remailer's mail never gets a ping back.
- A middleman's ping goes middle → random exit → pinger. Its return proves the middle decrypted its layer, which is enough.
- Cost: a rotated key appears one ping round later, ≤ 2 h plus latency at the planned cadence. yamn's rotation overlap is ≥ 48 h, so clients keep the old key in the meantime. A new remailer is published after its first returned ping. A remailer that's down when it rotates isn't published with the new key until it answers, which is correct.
- Limit: someone who controls the remailer's mailbox (or the remailer) can answer pings. That's owning the remailer, which no pinger can detect.
- Quarantine still applies on top: an unexpected change needs both the 24 h quarantine (or approval) and a proven key.
- `status.json` lists each key's `FirstSeen`, `ProvenAt` and `State`, so remailer operators can check what we publish for them. yamn remailers already warn about foreign keys in pingers' keyrings (yamn PR #67, see §9.7).

**Conf address mismatch** (Echolot added it immediately, `E:Conf.pm:149-153`): pending "address change". Nothing is mailed to the new address until it is approved.

### 9.3 Discovery policy

Echolot:
- auto-adds an address listed by ≥ 6 distinct remailers within 5 d, checked every 8 h (`E:Storage/File.pm:944-957`);
- immediately adds any address named in a self-reply (`E:Storage/File.pm:937-941`).

**Recommendation: an operator-maintained list.**
- `add`/`delete`/`enable`/`disable` CLI commands, with an optional nick pin.
- Supported lists and foreign summary lines become `Suggestions`, shown in `status` and `summary` and never mailed.

Reasons:
1. the supported list is derived from pingers' own pubrings (§2.2), so it adds no independent evidence;
2. auto-add lets any remailer make the pinger mail third parties (§2.2);
3. the network has ~7 remailers, so 6 recommendations is nearly "everyone", and manual curation is cheap.

`discovery.mode: echolot` is available for parity but not recommended.

### 9.4 Mail loops and abuse limits

- **No auto-replies:** go-echolot never replies to incoming mail. Bounces and unverifiable mail go to `mail-errors/`.
- **Outgoing rate fuse:** `mail.max_per_hour`.
  - Requests are sent only to remailers in the list and in `active`/resurrection state.
  - Request load with the defaults: key 12 + conf 1 + help/adminkey ≈ 0.3 → ≈ 13.3 requests per remailer per day, plus 12 pings × keys. For 7 remailers that is ≈ 260 mails/day.
- **yamn's per-address daily reply limiter** (Y-19):
  - it hashes the full lowercased `From` address and allows one reply per address per UTC day (`Y:replylimit.go:40-71`; used at `Y:server.go:704-708, 786-787`);
  - every request uses a unique token address, so the limiter never blocks the pinger. The cost to the remailer is 8 bytes per request per day.
  - **Do not reuse token addresses** (e.g. no "static" From for retries). A retry must mint a new token, or the second reply is suppressed.
- **Loop safety:** our request mails carry `Subject: remailer-*`.
  - If a remailer forwarded a request to another remailer's address, that remailer would reply to our token address: harmless.
  - We never send to addresses taken from mail content.

### 9.5 Signed outputs

**Format:** minisign-compatible detached signatures, `<file>.minisig`, Ed25519 (`internal/minisign`).

Why minisign and not a new format:
- existing tooling (`minisign -Vm pubring.mix -P <key>`) lets humans verify;
- the format has a *signed* trusted comment, which we use for replay protection;
- verification is ~120 lines (`crypto/ed25519` + `x/crypto/blake2b`, already a yamn dependency via x/crypto), so yamn needs no new module.

```
untrusted comment: go-echolot signature
<base64: "ED" || keyid[8] || sig[64]>          sig over BLAKE2b-512(file)  (prehashed, minisign's default)
trusted comment: timestamp:1792670400 file:pubring.mix pinger:mixmin expires:1792843200
<base64: global sig[64] over (sig || trusted comment)>
```

**The trusted comment is the contract with yamn's verifier:**

```
trusted = pair *( SP pair )            ; exactly one space between pairs, none before or after
pair    = key ":" value                ; any order; each key at most once
key     = 1*( %x61-7A / DIGIT / "_" )  ; a-z, 0-9, _
value   = 1*( %x21-7E )                ; printable ASCII, no space (":" allowed)
```

- **Required:** `timestamp` and `expires`, decimal Unix seconds UTC (1 to 18 digits, no sign), with `expires` after `timestamp`; `file`, the published file's base name.
- **Optional:** `pinger`, the pinger's name for people (`pinger.sitename` with every byte outside `%x21-7E` replaced by `_`, at most 64 bytes).
- A reader **ignores keys it doesn't know**, so more can be added later. There is no `sha256` key: the signature already covers the file (BLAKE2b-512), and a hash in the comment would add nothing.
- The signature file is four lines, each ending in LF, as minisign writes it. Readers may accept CR LF and blank lines after the four, as minisign does.
- go-echolot writes `timestamp file [pinger] expires` in that order (`minisign.Trusted`); `minisign.ParseTrusted` is the reference parser and `minisign.VerifyFile` the reference check (signature, grammar, `file` equals the name fetched, not expired).

**Timestamps never go backwards** (yamn remembers the newest timestamp it accepted per pinger key and file, and refuses older ones):
- the next timestamp of a file is `max(now, last + 1)`, so strictly increasing per key and file, also within one second;
- `last` is saved in `state.json` (`signed`, per key ID and file) *before* the signature is published, so a crash can't reuse or lower it;
- at start, the timestamps of our own signatures already in `results_dir` raise `last` too, so a state dir restored from a backup doesn't go back. Only signatures whose trusted comment verifies with our key count: anyone able to write the results directory could otherwise push the timestamps far into the future;
- after a clock step back, the timestamps continue from `last + 1` and go-echolot logs a warning. But a timestamp never runs more than 15 min (`MaxAhead`) ahead of the clock: beyond that, go-echolot stops signing and logs an error until the clock catches up. Otherwise, after a clock that was once ahead by D, every signature would stay valid for D plus its validity, which defeats the expiry. Meanwhile the files keep being written, their old signatures no longer match, and clients keep their last copies.
- Recovering at once from a clock that was far ahead takes a new key (key rotation below): timestamps are kept per key, so a new key starts at the clock.
- **For yamn:** refuse a `timestamp` more than a few minutes in the future, and keep the rollback state per pinger *key* (key ID) and file, so a rotation can reset it.
- **What yamn does** (PR #72): it fetches `<url>.minisig` for each signed URL and compares `file:` with the last path element of the URL. The web server must therefore serve the files under their real names (§10.1).

**Validity and cadence:**
- `expires`: `pubring.mix` and `type2.list` timestamp + 48 h; `mlist2.txt` (and `mlist.txt`, if listed) + 6 h.
- Signed whenever written: the stats at every build (`schedule.stats_interval`), the keyrings at every check (`schedule.pubring_check_interval`) even when they didn't change, and after every key change. With signing on, both intervals must be ≤ 1 h.
- A pinger that's down over 6 h makes clients keep their last mlist2 copy, and yamn's `stats.stale_hours` warns. That's intended.
- Only `results_dir` is signed (what clients fetch), not `private_results_dir`.

**Publishing order:** the file first, then its `.minisig`, each an atomic rename. A client fetching between the two sees a mismatch and keeps its old copy until the next fetch. A file that's no longer signed (signing turned off, or dropped from `signing.files`) loses its old `.minisig` at its next write, since it would no longer match.

**Keys:**
- `go-echolot keygen` writes `signing.key_file` (default `<state_dir>/pinger.key`, mode 0600, never overwritten) in minisign's secret key format *without a password* (`minisign -G -W`): the daemon reads it unattended, and like ssh it refuses a key file others may read. minisign itself signs with it, and a key from `minisign -G -W` works in go-echolot.
- `pinger.pub` (minisign's two-line public key format, `"Ed" || keyid || pk`) is published in `results_dir`. yamn's config takes only its base64 line.
- The base64 line is shown on the index page.
- The key and fingerprint are listed in the yamn repo (`doc/pingers.md`) through a reviewed PR. This is the trust anchor; HTTPS of the pinger is not.
- Key rotation: the new `pinger.pub` is signed with the old key (`go-echolot sign --key old.key --valid 720h pinger.pub` → `pinger.pub.minisig`), and the doc PR is updated.
- `go-echolot sign [--key] [--valid] FILE…` signs other files. It refuses the names of the published files (`pubring.mix`, `type2.list`, `mlist2.txt`, `mlist.txt`) wherever they are: those are the daemon's to sign, and the daemon removes the signatures of the ones it doesn't sign. `go-echolot verify [--pub KEY|FILE] FILE…` checks files as yamn does.

**Test vectors** (`testdata/signing/`, shared with yamn's verifier tests): a test key, `pinger.pub`, `pubring.mix` and `mlist2.txt`, each signed by go-echolot and by the reference minisign 0.12 tool with the same key and trusted comment. CI installs Debian's `minisign`, verifies go-echolot's signatures with `minisign -Vm`, and runs round trips both ways with new keys (`MINISIGN_BIN`), so the format is proven against the reference tool, not only our own code.

**yamn client verification** (single pinger; as implemented in yamn PR #72, which always fetches `<url>.minisig`):

```yaml
urls:
  fetch: true
  pubring: https://www.mixmin.net/yamn/pubring.mix
  mlist2:  https://www.mixmin.net/yamn/mlist2.txt
  pinger_keys: ["RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"]   # minisign public keys; if set, both files must be signed by one of them
  require_signatures: true              # refuse a config in which a pinger has no keys
  max_signature_age_hours: 48           # 0: only the expiry counts
```

Download rule in `httpGet`/`timedURLFetch` (`Y:utils.go:142-167`, `Y:client.go:379-400`). A file is accepted (written atomically) only if:
- the validator passes (as today), and
- some `pinger_keys` entry verifies the signature, and
- the trusted comment's `file:` equals the basename, and
- `now < expires` and `now − timestamp ≤ max_signature_age_hours`, and
- `timestamp` is not older than the newest one accepted from this pinger for this file (rollback).

Otherwise the previous local copy is kept and a warning is logged. A file whose `.minisig` doesn't match yet (fetched between the two writes) is the same case: keep the old copy, try again at the next fetch.

### 9.6 Client-side multi-pinger cross-check (spec for a yamn PR)

**Config,** as yamn implements it (go-while/yamn `d5f9d63`; `yamn(1)`, "Pinger signatures"). The first draft of this spec had a per-pinger `key:` and `max_stats_age_hours`/`max_pubring_age_hours`; yamn does it with the keys below.

```yaml
urls:
  fetch: true
  pingers:                              # if non-empty, replaces urls.pubring/urls.mlist2
    - name: mixmin
      pubring: https://www.mixmin.net/yamn/pubring.mix
      mlist2:  https://www.mixmin.net/yamn/mlist2.txt
      keys: ["RWQ…"]                    # minisign public keys; if set, both files must be signed by one of them
    - name: victor
      pubring: https://echolot.virebent.art/pubring.mix
      mlist2:  https://echolot.virebent.art/mlist2.txt
    - name: frell
      pubring: http://echolot.theremailer.net/yamn/pubring.mix
      mlist2:  http://echolot.theremailer.net/yamn/mlist2.txt
  key_quorum: 2                 # pingers that must agree on a key
  pinger_keys: []               # single pinger (urls.pubring/urls.mlist2) only: its minisign keys; must stay empty with pingers
  require_signatures: false     # refuse a config in which a pinger has no keys
  max_signature_age_hours: 48   # refuse a signature older than this (0: only its expiry counts)
stats:
  stale_hours: 24               # an mlist2 older than this is stale (see step 1)
```

**Algorithm.** Run at the existing hourly fetch (`Y:server.go:140-162`) and client fetch (`Y:client.go:133-138`).

1. **Fetch** each pinger's files into `<files.pubring>.<name>` and `<files.mlist2>.<name>`, with today's validation (`CheckPubring`/`CheckStats`) and signature checks. A failed fetch keeps that pinger's previous copy.
   - **Keys:** a pinger's last accepted pubring counts. For a pinger with keys, a download must verify and be no older than `urls.max_signature_age_hours` (the signature's `timestamp`, §9.5) to replace it; a refused download keeps the previous copy (`pubring.mix.<name>`), and its accepted signature is stored next to it (`pubring.mix.<name>.minisig`).
   - With `urls.pingers`, a signing pinger's copy counts in the merge only while that stored signature verifies with one of its keys, names the file, hasn't expired and isn't older than `urls.max_signature_age_hours` (yamn PR #74). A pinger whose new files keep failing drops out when its last signature runs out: with go-echolot's expiries (§9.5), after 48 h for `pubring.mix` and 6 h for `mlist2.txt`. If too few pingers are left for `key_quorum`, the current keyring is kept. A single pinger keeps its file, since nothing could replace it.
   - **Stats:** a remailer's stats must come from at least as many pingers as the key quorum: fresh ones first (mlist2 `Generated` within `stats.stale_hours`), older ones added, newest first, only when the fresh ones are too few (`keymgr/merge.go`).
2. **Parse** each pubring with the existing `ImportPubring` rules (validity dates, keyid = hash) into a set of entries E_p = {(address, name, keyid, pk, version, caps, from, until)}.
3. **Vote:** for each address a, group the entries by (keyid, pk, name). A group is *accepted* if its number of distinct pingers is ≥ Q, where Q = `min(key_quorum, number of usable pingers)`.
   - If Q < `key_quorum`, log a warning. If there are 0 usable pingers, keep the existing merged files.
   - If several groups are accepted for a (rotation), choose the latest `from`, then the latest `until`, then the lowest keyid.
   - version/caps are taken as the value most of the agreeing pingers carry. On a tie, take the one from the pinger with the newest mlist2 `Generated`.
4. **Nick conflicts:** if two accepted addresses carry the same name, keep the one with more votes. On a tie, drop both and warn. This mirrors the uniqueness rule in §9.2.
5. **Write** the merged `files.pubring` in canonical format (§7.1). `KeyRefresh`/`ImportPubring` then run unchanged.
6. **Stats:** for each remailer name in the merged keyring, collect (latency minutes, uptime ×10) from every stats-usable pinger whose mlist2 row parses (same parsing as `ImportStats`).
   - The merged value is the **median**. With an even count, take the *lower* middle uptime and the *higher* middle latency, i.e. conservative.
   - A remailer with no rows gets no row.
   - Write the merged `files.mlist2` in mlist2 format (§7.3). Histories are `????????????` and options are taken from the newest source. `Generated` is the *oldest* `Generated` among the inputs used, so `StatsStale` stays conservative.
7. **Logging:**
   - log per pinger: keys contributed, keys outvoted, stats age;
   - log every address where the pingers disagree on the keyid. That is the operator-visible cross-check, and the same data a pinger operator wants.

**Properties:**
- With Q = 2 of 3, a single compromised or stale pinger can neither inject a key nor suppress a valid one.
- A newly rotated key is used once 2 pingers have it. With go-echolot cadence that takes ≤ ~2 h. With today's Echolot pingers it takes up to ~32 h; the old key remains valid ≥ 48 h, so service continues.

**Tests:**
- 3 synthetic pingers covering: agreement, one lying, one stale, a rotation in progress, and a nick collision;
- signature failure handling;
- `use_expired` interplay.

**Status (2026-10-22):** steps 1–7 are done in yamn (PR #30, `de59490`, plus #52 for the stats quorum); `urls.pingers` entries have `name`, `pubring`, `mlist2`. Not done: the per-pinger `key` and `require_signatures`, and `max_stats_age_hours`/`max_pubring_age_hours` (yamn uses `stats.stale_hours`). Those come with signed outputs (§9.5), as a yamn PR in phase 4.

**Status (2026-10-23):** yamn PR #72 checks go-echolot's signatures per §9.5. It is tested against `testdata/signing` (both signatures of each file) and end to end with go-echolot `c5214c7` (`keygen` + `sign`, then `yamn --refresh`).

**Status (2026-10-25):** the "not done" items above are done, differently named: per-pinger `keys` (a list), `urls.pinger_keys` for a single pinger, `urls.require_signatures` (#72); the keyring's age is `urls.max_signature_age_hours` (default 48, #72), and the stats' age is `stats.stale_hours`. The config example above shows them. yamn PR #74 (`ffe4f4c`) leaves a signing pinger out of the merge once its stored signature is stale (step 1).

### 9.7 What yamn already does (2026-10-22)

These are merged in go-while/yamn and change what go-echolot has to do:
- **Keyid check** (`fa8b18c`): clients ignore a key whose keyid isn't `blake2s-128(PK)`. go-echolot drops such keys too (§9.1).
- **Cross-check** (#30, #52): with `urls.pingers` and `key_quorum` (default 2), one wrong or compromised pinger can't add or replace a key, and stats are a conservative median.
- **Remailer self-check** (#67, `5020c1b`): at startup and hourly, a remailer reads each downloaded keyring and warns, once a day, when one lists a key for its name or address that isn't in its secret keyring, its name with another address, or its address under another name. It detects a forgery that reached every pinger, but only on remailers that run this fork, and only after clients may already use the key.
- **What remains for go-echolot:** preventing the forgery before it's published, through proof of possession (§9.2), quarantine (§9.2) and signatures (§9.5).

---

## 10. Operations

### 10.1 Deployment

- **Account:** a dedicated user `pinger` with home `/var/lib/go-echolot`. The binaries `go-echolot` and `yamn` (fork ≥ c6d9a95) go in `/usr/local/bin`. Never run go-echolot as root: yamn ≥ d5f9d63 (PR #73) refuses to run as root, so no ping could be built and `yamn_selftest` goes crit.
- **Mail in.** No procmail is needed. Pick one:
  - (a) Postfix: `recipient_delimiter = +` plus `home_mailbox = Maildir/` (or a per-user `mailbox_command`-free local delivery). Everything for `pinger+*@domain` lands in `~pinger/Maildir/new`.
  - (b) Any MTA: `~pinger/.forward` = `"|/usr/local/bin/go-echolot deliver"`. `deliver` writes into the Maildir atomically and records `ORIGINAL_RECIPIENT`/`EXTENSION` from Postfix's environment as `X-Original-To`.
  - (c) A dedicated virtual Maildir for a subdomain (`pinger.example.org`). This is cleanest for SPF, DKIM and DMARC.
- **Mail out:** `mail.method: sendmail` (default; the MTA queues and retries), or `smtp`. The `smtp` method reuses yamn's TLS policy: verify the relay, STARTTLS required for a non-loopback relay, AUTH only to the relay; cf. `Y:mail.go:446-604`. The envelope sender is a VERP bounce token (§6.2).
- **Publishing:** `results_dir` (e.g. `/var/www/pinger/yamn`) is owned by `pinger` and served read-only by the web server. Only the results directory is ever exposed.
  - **Serve the files under their real names, side by side.** yamn (PR #72) fetches a file's signature from `<url>.minisig` and checks that the trusted comment's `file:` equals the last path element of the URL it downloaded. So a URL that rewrites `/pubring` to `pubring.mix`, or that redirects to another name, fails verification. Give clients URLs like `https://pinger.example.org/yamn/pubring.mix`, with `pubring.mix.minisig` next to it.

systemd unit:

```ini
[Unit]
Description=go-echolot yamn pinger
After=network-online.target postfix.service
Wants=network-online.target

[Service]
Type=notify
User=pinger
ExecStart=/usr/local/bin/go-echolot run --config /etc/go-echolot/config.ini
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30
WatchdogSec=10min
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/go-echolot /var/www/pinger/yamn
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

`sd_notify` is a ~30-line `$NOTIFY_SOCKET` writer, with no dependency. `WATCHDOG=1` is sent only when a scheduler tick has completed.

### 10.2 Health and staleness self-monitoring

Checks run every tick (`internal/health` has the thresholds, `internal/app/health.go` gathers the inputs). Each has a state ok/warn/crit:

| Check (name) | warn | crit |
|---|---|---|
| Last good mailbox scan (`mailbox_scan`) | > 5 min | > 30 min |
| Ping replies received, any remailer (`ping_replies`) | a ping out for 3 h (or 1.5 × `ping_interval`) with no reply of any ping since | 6 h (or 3 × `ping_interval`), while ≥ 2 remailers are pingable (else warn) |
| Outgoing send failures (`send_failures`) | > 10 % over 1 h, or any mail held back by `mail.max_per_hour` | 100 % over 1 h |
| `mlist2.txt` Generated age (`mlist2_age`) | > 15 min (or 3 × `stats_interval`) | > 1 h (or 12 × `stats_interval`) |
| Publishable keys (`keys`) | a published key expires in < 24 h with no successor | 0 keys |
| yamn self-test (`yamn_selftest`) | — | fails |
| Pending quarantine (`pending`) | any | — |
| Bounces for a remailer (`bounces`) | any in 24 h | — |
| Disk free in state/results (`disk_state`, `disk_results`) | < 10 % | < 2 % |
| **Peer pingers** (`peer_<name>`: `[peer <name>] mlist2`, fetched hourly) | `Generated` > 6 h old, or never fetched | > 24 h old |
| Peers' key disagreement with us (`key_agreement`) | — (info) | — |

Details:
- **Replies.** The clock starts at the oldest ping still out that was sent after the newest reply, so a pinger with nothing to ping stays ok. Pings sent before a start of `run` count from that start: the replies that waited in the Maildir are read within a minute. The start time is kept in `state.json` (`health.reply_clock`) and moves only when a reply came since the last start, so a daemon that restarts again and again still warns.
- **Send failures** count every attempt to send a request or a ping, except those never attempted: a `.onion` recipient without `mail.tor_socks`, a mail that fails the checks, a send cut off at the end of the tick. Fewer than 3 sends in the hour are too few to judge. Mails the rate fuse held back aren't failures, but any in the hour make the check warn: the network has outgrown `mail.max_per_hour`.
- **mlist2.txt** is read back from `results_dir`: the check sees what clients get. A missing file is crit only once the stats should have been written.
- **Keys.** A successor is another key of the remailer, active or in quarantine, that expires later.
- **Self-test** runs at the start and hourly.
- **Bounces** are kept in `state.json` (`health.bounces`) with their delivery time, so a restart doesn't hide them and old bounces read after downtime don't count as new.
- **Peers.** The peers' `mlist2.txt` are fetched at the start and hourly, all at once, with a 30 s timeout and at most 2 MiB each. A peer that can't be fetched ages from its last good fetch, so a host that is down goes warn and then crit. A `Generated` time in the future counts as the time of the fetch, so a peer with a clock far ahead still goes stale. What the fetches found is kept in `state.json` (`health.peers`) across restarts. The peer's `pubring.mix` (`[peer <name>] pubring`, by default next to its `mlist2.txt`) is compared with our public keyring: each address both list with different keyids is logged and shown under `key_agreement` (not `peer_keys`, which would be the check of a `[peer keys]`). That check is for information only and is always ok: during a key rotation, pingers disagree for hours.

Outputs:
- `results/status.json` (machine-readable: `generated`, `pinger`, `version`, `state`, and each check's `name`, `state` and `detail`) and `status.txt`, both rewritten every tick. They are public, like the rest of `results_dir`: they hold counts, remailer addresses and the peers' fetch errors, but no local paths or yamn errors (those go to the log).
- `go-echolot check` reads `status.json` and exits 0/1/2 (ok/warn/crit) for Nagios or cron. The first line is Nagios's summary (`GO-ECHOLOT WARNING - pending: …`); the whole status follows. It adds a `status_age` check, because a stopped or hung daemon stops rewriting the file: warn after 15 min (or 3 ticks), crit after 30 min (or 6 ticks). A missing or unreadable `status.json`, or a config `check` can't read, is crit. A `|` in a detail becomes `/`, since Nagios reads performance data after it.
- `health.notify` mails the operator a digest when a check's state differs from the one last mailed about (ok if none was), at most 1 mail per 6 h per check. A check that changes again within the 6 h waits; once due, the mail has its state then, so a flap that settles back sends nothing. The mail lists the changed checks, then the whole status. The last mail per check is kept in memory and in `state.json` (`health.notified`), so a restart doesn't mail again, nor every tick when `state.json` can't be written (a full disk). A failed send is tried again after 30 min, not every tick, and each send gets at most 1 min of the job loop. Long details are wrapped in the mail, so no line comes near RFC 5322's 998. Health mails go out from `pinger.address` and count against `mail.max_per_hour`, but not as sends in `send_failures`.

The July 8 – August 7 outage would have shown up in two ways:
- the "no ping replies / no scan" checks, if the process was alive but mail was broken;
- every *other* go-echolot pinger's peer check within 6 h, if the whole host was down. The peer check is the part that doesn't depend on the broken host.

### 10.3 Config example

The config file is a small INI format, parsed by `internal/config` with the standard library only (no YAML library: dependencies are limited to the standard library and `golang.org/x`, §1):
- `[section]` headers; `[peer <name>]` sections repeat, one per peer;
- `key = value`, values unquoted. `#` starts a comment at the start of a line or of a value, or after a space or tab, so a value may contain `#` but not ` #`;
- durations in `time.ParseDuration` form (`2h`, `168h`), lists comma-separated;
- relative paths are relative to `paths.state_dir`;
- every key has a default except `pinger.sitename`, `pinger.address` and `pinger.operator_address`;
- unknown sections or keys are errors, so typos don't pass silently.

[`examples/config.ini`](../examples/config.ini) documents every key with its default. `go-echolot dumpconf` checks a config file and prints it with the defaults filled in.

```ini
[pinger]
sitename = Example yamn pinger
address = pinger@pinger.example.org     # local part + domain for tokens
recipient_delimiter = +
operator_address = remops@example.org

[paths]
state_dir = /var/lib/go-echolot
maildir = /var/lib/go-echolot/Maildir
results_dir = /var/www/pinger/yamn
private_results_dir = /var/lib/go-echolot/results.private

[yamn]
binary = /usr/local/bin/yamn
timeout = 30s

[mail]
method = sendmail                       # sendmail | smtp
sendmail = /usr/sbin/sendmail
smtp_relay = localhost
smtp_port = 25
usetls = true
require_tls = false
username =
password_file =
max_per_hour = 200
tor_socks =                             # Tor SOCKS host:port for .onion remailers; empty: skip them

[schedule]
tick = 5m
ping_interval = 2h
key_request_interval = 2h
conf_request_interval = 24h
help_request_interval = 168h
adminkey_request_interval = 168h
stats_interval = 5m
pubring_check_interval = 1h
pubring_debounce = 5m

[stats]
days = 12
weights = 0.5, 1.0, 1.0, 1.0, 1.0, 0.9, 0.8, 0.5, 0.3, 0.2, 0.2, 0.1
skew_abs = 15m
skew_percent = 0.8
sort_by_latency = false
random_garbage = 8192

[keys]
retention = 120h
rotation_window = 72h
quarantine = 24h
min_sightings = 2
require_proof = true                    # publish a key only after a ping to it came back (§9.2)

[discovery]
mode = manual                           # manual | echolot

[signing]
enabled = false
key_file = /var/lib/go-echolot/pinger.key
files = pubring.mix, type2.list, mlist2.txt

[health]
notify = remops@example.org

[peer mixmin]
mlist2 = https://www.mixmin.net/yamn/mlist2.txt
pubring =                               # empty: pubring.mix next to mlist2

[peer victor]
mlist2 = https://echolot.virebent.art/mlist2.txt

[compat]
meta_files = true
drop_pings_with_key = false
latency_from = delivery                 # delivery | processing
legacy_md5_tokens_until =               # set by import-echolot

[log]
level = info                            # debug | info | warn | error
file =                                  # empty = stderr/journald
```

Other sections refer to config keys as `section.key` (e.g. `keys.require_proof`, `compat.drop_pings_with_key`).

### 10.4 CLI

Echolot-compatible verbs (`E:pingd` POD, `E:Commands.pm`):
- `run` (replaces `start`; foreground; `--detach` is not provided because systemd handles that);
- `stop`, `process` (= SIGHUP);
- `add <addr> [--nick N]`, `delete`, `enable`, `disable`, `set showit|pingit|fetch=on|off <addr…>`;
- `setremailercaps <addr> '<caps>'`, `deleteremailercaps <addr>`;
- `getkeyconf [addr…]`, `sendpings [addr…]`, `sendchainpings a:b…`;
- `buildstats`, `buildkeys`, `buildthesaurus`, `buildfromlines`;
- `summary`, `dumpconf`.

New verbs:
- `status`, `keys [addr]`, `check`;
- `approve <addr> [keyid|nick|address]`, `reject …`;
- `suggestions`;
- `import-echolot`;
- `keygen`, `sign [--key FILE] [--valid DUR] FILE…`, `verify [--pub KEY|FILE] FILE…` (§9.5);
- `deliver`;
- `selftest`;
- `version`.

### 10.5 Logging

Structured `log/slog` with text output, to stderr (journald) or a file; levels debug/info/warn/error.
- Every reply is logged with remailer, kind, token age and decision.
- Every key decision is logged with keyid and reason.
- A daily summary line per remailer covers sent, returned, reliability and latency (Echolot's `summary`, `E:pingd:616`).
- Keys, tokens, the secret and mail bodies are never logged.

---

## 11. Testing

1. **Golden stats from the real Stats.pm. Practical, and done as a prototype.**
   - [`tools/golden/harness.pl`](../tools/golden/harness.pl):
     - stubs `Echolot::Log`, `Tools`, `Globals`, `Config` and the storage;
     - pins `time()`/`gmtime()` via `CORE::GLOBAL`;
     - loads the unmodified `Echolot/Stats.pm`;
     - runs `build_stats()` and writes `pub/mlist2.txt` and the private copy, plus `calc.json` (the per-address results of `calculate()`).
   - `gen.py` makes deterministic synthetic data: 6 remailers with 2 keys each, outstanding pings, very slow (`H`) latencies, a 0 % remailer, and middle vs exit caps.
   - It ran successfully on the local perl 5.40 (JSON::PP and core modules only; GnuPG::Interface isn't needed).
   - In go-echolot: `testdata/golden/<case>/{in.json, calc.json, mlist2.txt}` are committed. `go test` needs no perl. `make golden` regenerates the files when perl is present.
   - Edge cases to cover:
     - no done pings;
     - all pings outstanding;
     - even/odd medians;
     - latency exactly on bucket edges (1200 s, 3600 s, 172800 s);
     - reliability 0.99985 (`+` vs `9`);
     - `%5.1f` near .x5 (avoid exact ties);
     - nick of exactly 12 characters;
     - ties in reliability (sort by nick).
2. **Format goldens from live data:**
   - parse `pingers/*.mix` and write them back: the output must be byte-identical;
   - re-render `live-1021/mixmin.mlist2.txt` structure (sections, spacing) from parsed rows.
3. **Client compatibility:**
   - an integration test (with `YAMN_BIN`) runs `yamn -m --stdout` against our `pubring.mix`;
   - a tiny Go test harness, built from the yamn repo in CI, calls `ImportPubring`/`ImportStats` on our outputs. It checks that every key is imported and that every row matches.
4. **Parsers:**
   - table tests for the conf/key replies, including real `t_65.key`/`t_65.conf`;
   - CRLF, QP and dash-escaping;
   - forged keyids, wrong address, dates in the future or past, 2 keys in one reply, foreign summary lines.
   - Fuzz `ParseKey`/`ParseConf`/`token.Verify`/`pinger.Open`.
5. **End-to-end with a fake SMTP server and Maildir:**
   - an in-process SMTP sink (or `Mailer` fake) captures the outgoing requests and pings;
   - a fake remailer:
     - answers requests by writing yamn-formatted replies into the Maildir;
     - for pings, runs the *real* yamn remailer code path: a `yamn -M` instance with its own secring, the captured packet put in its Maildir, its exit output written to our Maildir via `mail.outfile`/pipe.

     That proves the full loop, as in the end-to-end setup used to test yamn.
   - A virtual clock (injected `now`) drives 13 simulated days in seconds.
   - Check:
     - rotation (old key expiring, new key appears → pubring within 5 min);
     - quarantine of an early change;
     - not-a-remailer;
     - bounce attribution;
     - crash and restart between `out` and send (journal recovery);
     - duplicate mail;
     - the lock held by a second instance.
6. **Side-by-side run.** Run go-echolot next to mixmin's pinger for ≥ 14 days, pinging the same remailers.
   - Compare hourly: key sets and the time each pingers picked up rotations; reliability (expect |Δ| ≤ 2 points except after rotations, where ours keeps the history); latency (expect within ±10 %).
   - Also run once with `compat.drop_pings_with_key: true` and `latency_from: processing`, which should track mixmin closely.
   - A small `cmd/mlistdiff` tool prints per-remailer deltas.

---

## 12. Phased plan, sizes, first PRs

### 12.1 Sizes (Go lines without tests; tests roughly 1:1)

| Component | Phase | Lines |
|---|---|---|
| config | 1 | 250 |
| store (state, journal, lock, atomic) | 1 | 450 |
| token | 1 | 120 |
| mailin (Maildir, dispatch, deliver) | 1 | 250 |
| mailout (sendmail, SMTP, compose) | 1 | 300 |
| replies (conf, key, thesaurus) | 1 | 300 |
| keys (validate, select, pin/quarantine) | 1 | 300 |
| output: pubring/type2/meta | 1 | 120 |
| sched | 1 | 200 |
| CLI (core verbs, spool) | 1 | 350 |
| health (local checks, status files) | 1 | 200 |
| **Phase 1 total** | | **≈2,850** |
| pinger (body, seal, YamnEncoder, receive) | 2 | 400 |
| stats (calculate, strings) + mlist2/mlist writers | 2 | 380 |
| import-echolot | 2 | 250 |
| **Phase 2 total (MVP)** | | **≈3,900 cumulative** |
| chain pings + broken chains | 3 | 300 |
| HTML pages (index, mlist2.html, thesaurus, fromlines) + templates | 3 | 350 |
| sign/verify (minisign), keygen | 4 | 220 |
| peer checks, notifications | 4 | 150 |
| yamn PR: signature verification | 4 (yamn) | 250 |
| yamn PR: multi-pinger cross-check | 4 (yamn) | 400 |

### 12.2 Phases and milestones

1. **Keys → pubring.**
   - Requests, Maildir intake, conf/key parsing with validation, pinning, quarantine.
   - `pubring.mix`/`type2.list` and `status`.
   - Pings don't exist yet, so keys can't be proven (§9.2). The phase 1 pubring is for comparison with mixmin only and isn't announced; it runs with `keys.require_proof: false`.
   - **Milestone:** for 7 days, the published pubring is a superset-correct match of mixmin's: same keyids per address, minus expired keys. New keys appear ≤ 2.5 h after rotation.
2. **Pings → mlist2.**
   - Encoder, ping send/receive, stats, `mlist2.txt`/`mlist.txt`, Echolot import.
   - Proof of possession on (`keys.require_proof: true`, the default from here on); the pubring may be announced.
   - **Milestone:** golden tests pass; the 14-day side-by-side stays within the bounds in §11-6; a yamn client using only our files builds chains.
3. **Chain pings, HTML.**
   - **Milestone:** the broken-chain list agrees with mixmin's for 14 days; the HTML index, mlist2.html and thesaurus are served.
4. **Signing and cross-check.**
   - minisign signatures and `pinger.pub`; peer staleness checks.
   - yamn PRs for `require_signatures` and `urls.pingers`/`key_quorum`.
   - **Milestone:** a yamn client configured with 3 pingers and quorum 2 survives one pinger serving a forged key.

### 12.3 First PR-sized steps

1. Repo skeleton: `cmd/go-echolot`, `internal/config` with defaults and validation, CI (`go vet`, `go test -race`), LICENSE (GPL-2.0+ is advisable, since formats and algorithms are ported from Echolot's GPL code).
2. `internal/store`: State JSON, atomic write, journal with recovery, flock. Tests include crash simulation.
3. `internal/token`: HKDF keys, mint/verify, legacy MD5. Fuzz test.
4. `internal/replies` + `internal/keys`: parsers and validation against `t_65.*` and the three live pubrings; selection and quarantine logic.
5. `internal/output` pubring writer: byte-identical round trip of `pingers/*.mix`.
6. `internal/mailin` + `internal/mailout` + `internal/sched` + `run`: phase 1 end to end with fakes.
7. `internal/stats` + golden harness and testdata (start of phase 2).
8. `internal/pinger` YamnEncoder + self-test.

---

## 13. Open questions (each with a recommended answer)

1. **License:** GPL-2.0-or-later, to match Echolot, whose algorithms and formats we port closely? *Recommended: yes.*
2. **Key request interval:** 1 h or 2 h? *Recommended: 2 h.* It cuts lag from ~32 h to ~2 h at 12 replies per remailer per day. 1 h buys little, since yamn rotates ≥ 0–48 h before expiry.
3. **History vs Echolot parity:** keep pings across key expiry by default (full 12-day history; numbers differ from mixmin/Victor), or default to Echolot parity? *Recommended: keep the history by default; document the `compat` switches for side-by-side runs.*
4. **Discovery:** manual list only? *Recommended: yes*, with suggestions shown in `status`.
5. **Quarantine policy:** 24 h plus ≥ 2 sightings for unexpected key changes, or always operator approval? *Recommended: 24 h + 2 sightings*, so single-operator pingers don't stall when the operator is away; notify always.
6. **Nick length:** enforce `[a-z0-9]{1,12}`? *Recommended: yes.* Longer nicks already break stats matching in yamn.
7. **Ping encryption:** secretbox (new format), or keep GPG symmetric for drop-in compatibility with in-flight Echolot pings? *Recommended: secretbox.* Drop in-flight legacy pings at import (≤ 24 h of samples).
8. **Ping identifiability:** `+ping=` in the token tells exits which mail is a ping. Should the token kind be opaque, e.g. `+t.<random>=…`, to make gaming harder? *Recommended: keep the Echolot shape for now.* The pinger's domain identifies pings anyway; revisit together with dummy-like cover traffic.
9. **`remailer-help`/`adminkey`:** request them at all? *Recommended: weekly*, for the thesaurus only.
10. **Signature format:** minisign-compatible, or a custom header format? *Recommended: minisign*, for existing tooling and a signed trusted comment.
11. **Where the pinger keys are anchored for clients:** yamn repo doc and default config? *Recommended: a `doc/pingers.md` in yamn plus commented-out defaults in the example config.* Not compiled-in.
12. **Stats merging in yamn:** median or freshest? *Recommended: conservative median* (§9.6). Freshest is simpler, but one bad pinger controls it.
13. **Dead remailers:** stop pinging in `dead`? *Recommended: yes* (Echolot keeps pinging until its keys expire).
14. **Middleman pings:** publish them as-is, measuring middle plus random exit as Echolot does, or route them through a known exit with `-l middle,exit`? *Recommended: as-is for parity.* ~~Add an optional diagnostic chain ping `(middle, our-best-exit)` in phase 3.~~ *Decided in phase 3: not needed; every (middle, exit) pair is chain-pinged weekly anyway, daily while it's bad.*
15. **Run on the same host as a remailer?** *Recommended: allowed, but use a separate user and state dir.* The yamn binary is shared; the config files are not.
16. **Who runs it first?** *Recommended: you, as the 4th pinger in parallel with mixmin, during phase 2.* Then offer the Echolot import to mixmin, Victor and Frell.
17. **Proof of possession:** publish a key only after a ping encrypted to it came back (§9.2)? *Recommended: yes, by default* (`keys.require_proof: true`), off only for phase 1 comparisons. It delays a rotated key by one ping round (≤ ~2 h) and is the only defense against a forger who can keep sending key replies.
18. **Counting pings to unpublished keys:** leave them out of the stats? *Recommended: yes*: clients can't use the key yet, so its pings say nothing about service they get.
19. **Config format:** the standard library has no YAML or TOML parser, and dependencies are limited to the standard library and `golang.org/x`. INI-style with our own ~150-line parser, or JSON (`encoding/json`, no parser to write)? *Recommended: INI-style* (§10.3): operators need comments, which JSON doesn't allow. *Decided 2026-10-22: INI-style; the parser is `internal/config`.*

---

## Addendum (2026-10-21): the original yamn Echolot patch was found

Zax (Steve Crook) posted it to alt.privacy.anon-server on 2019-06-02, Message-ID `<slrnqf7417.u39.admin@fleegle.mixmin.net>`, thread "Cloaked Yamn Pinger is broken". A verbatim copy is in [go-while/echolot](https://github.com/go-while/echolot/blob/research/usenet-pinger-history/research/usenet/found/Conf.pm.yamn.patch) (branch `research/usenet-pinger-history`, `research/usenet/found/Conf.pm.yamn.patch`); it is applied as commit 6001207 on that repo's `yamn` branch.

- **What it changes:** only `Echolot/Conf.pm` `parse_mix_key`. Both key-block regexes replace `\d+\r?\n(?:[a-zA-Z0-9+\/]*\r?\n)+` with `[0-9a-f]{64}\r?\n`, and the example key in a comment is updated. The patch is dated 2016-02-10, against the 2014-10-23 Conf.pm.
- **Checks:**
  - it applies cleanly to crooks/echolot `40676ca` (`patch --dry-run`);
  - the patched file passes `perl -c`;
  - the patched regex matches mixmin's live `thesaurus/65.key`: 1 match, versus 0 unpatched.
- **Zax's pinger client** (article `<slrnqf7mgl.u39.admin@fleegle.mixmin.net>`, same day), a pre-2022 gcfg `yamn.cfg`:
  ```
  [Mail]  SMTPRelay = fleegle.mixmin.net
          Pipe = "/usr/sbin/sendmail -f echolot-yamn@fleegle.mixmin.net -t"
  [Stats] UseExpired = true
  [Files] Pubring = "/home/echolot-yamn/yamn/pubring.mix"
  [Urls]  Fetch = false
  ```
  So Echolot's `Mix.pm` writes its one-key `pubring.mix` into `mixhome`, which is the yamn client's directory.
  - `Fetch = false` stops yamn from replacing that file.
  - `UseExpired = true` makes yamn encrypt to keys whose `until` date has passed. That's why Echolot pingers keep pinging expired keys (§2.1).
- **What this means for the design:**
  - The `YamnEncoder` (§4) should use the same three settings in its private `pinger.yml`: one-key pubring, `urls.fetch: false`, and `stats.use_expired` according to policy. The policy here is *false*, since we never ping or publish expired keys.
  - `-c 1` and `--nodummy` as planned.

---

## Addendum (2026-10-22): decisions and yamn-side status

- **No more Perl.** The patched Perl Echolot stays as it is (go-while/echolot, branch `yamn`). No new features go there, including Y-03 work. The open crooks/echolot PR #1 is left as it is.
- **Proof of possession** is part of the design (§1, §8.4, §9.2, questions 17–18).
- **Dependencies:** standard library and `golang.org/x/...` only, plus `github.com/dchest/blake2s` for keyids (reviewed exception, §1). The config is INI-style instead of YAML (§10.3, question 19); `civil.Date` is our own type (§4).
- **yamn side:** see §9.6 status and §9.7. Merged since the first draft:
  - #30, #52 (multi-pinger cross-check, stats quorum);
  - #64 (per-domain MX delivery: pings to exits with several recipients are no longer affected);
  - #65/#66 (`mail.tor_socks`: .onion recipients through Tor; a pinger can use it for .onion remailer addresses);
  - #67 (remailer self-check of published keys).
  - #72 (verifies go-echolot's signatures, §9.5), #73 (yamn refuses to run as root, except `-V`/`--version`; master `d5f9d63`).
- **The yamn binary** that the Encoder runs is a separate program, not a Go dependency of go-echolot.
- **Encoder note:** the yamn client go-echolot runs (`-m --stdout`) only needs a one-key pubring; the remailer self-check (#67) runs only in remailer mode, so the pinger's private yamn config isn't affected.

